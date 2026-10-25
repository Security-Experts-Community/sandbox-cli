from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from ptsandbox import Sandbox
from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxOptions

from sandbox_cli.console import console
from sandbox_cli.core.config import get_settings
from sandbox_cli.core.sandbox import get_key_by_name
from sandbox_cli.core.scan import SandboxArguments, ScanType
from sandbox_cli.services.scanner.prepare import PreparedScan, prepare_scan
from sandbox_cli.services.scanner.runner import ScanJob, ScanReporter, ScanTarget, plan_targets, run_scan_jobs
from sandbox_cli.services.scanner.uploads import apply_uploads
from sandbox_cli.services.scanner.utils import compute_wait_time

if TYPE_CHECKING:
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.requests import BasicScanRequest

__all__ = ["scan_internal"]


def _scan_options(request: BasicScanRequest, prepared: PreparedScan) -> SandboxBaseScanTaskRequest.Options:
    options = SandboxBaseScanTaskRequest.Options(
        analysis_depth=2,
        passwords_for_unpack=get_settings().passwords,
        sandbox=SandboxOptions(
            image_id=str(prepared.default_image),
            analysis_duration=request.analysis_duration,
            custom_command=request.custom_command,
        ),
    )
    debug = options.sandbox.debug_options
    debug["save_debug_files"] = True
    debug["extract_crashdumps"] = True
    apply_uploads(debug, prepared.uploads)
    return options


async def scan_internal(request: BasicScanRequest, reporter: ScanReporter) -> None:
    key = get_key_by_name(request.key_name)
    console.info(f"Using key: name={key.name} max_workers={key.max_workers}")

    async with Sandbox(key=key) as sandbox:
        prepared = await prepare_scan(
            sandbox,
            rules=request.rules,
            is_local=request.is_local,
            scan_images=request.images,
            hooks=request.hooks,
        )
        base_options = _scan_options(request, prepared)
        if request.custom_command:
            console.info(f"Using custom command: {request.custom_command}")

        wait_timeout = compute_wait_time(request.analysis_duration)
        download_options = replace(request.download_options, video=True, logs=True)

        def make_job(target: ScanTarget) -> ScanJob:
            options = base_options.model_copy(deep=True)
            options.sandbox.image_id = str(target.image)

            async def submit(sandbox: Sandbox) -> SandboxBaseTaskResponse:
                return await sandbox.create_scan(
                    target.file,
                    file_name=request.fake_name or target.file.name,
                    options=options,
                    rules=None,  # rules are passed via debug_options, not by the library
                    read_timeout=wait_timeout,
                    upload_timeout=request.upload_timeout,
                    async_result=True,
                )

            return ScanJob(
                name=target.file.name,
                image=str(target.image),
                out_dir=target.out_dir,
                idx=target.idx,
                submit=submit,
                wait_timeout=wait_timeout,
                download_options=download_options,
                arguments=SandboxArguments(
                    type=ScanType.SCAN, sandbox_key_name=key.name, sandbox_options=options.sandbox
                ),
            )

        jobs = [make_job(t) for t in plan_targets(request.files, prepared.images, request.out_dir)]
        await run_scan_jobs(sandbox, key, jobs, reporter, unpack=request.unpack, open_browser=request.open_browser)
