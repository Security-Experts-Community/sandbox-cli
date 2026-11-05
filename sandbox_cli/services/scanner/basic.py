from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxOptions

from sandbox_cli.console import console
from sandbox_cli.core.config import get_settings
from sandbox_cli.core.scan import SandboxArguments, ScanType
from sandbox_cli.services.scanner.backends import open_backends
from sandbox_cli.services.scanner.prepare import PreparedScan, prepare_scan
from sandbox_cli.services.scanner.runner import (
    ScanJob,
    ScanReporter,
    ScanTarget,
    Submission,
    plan_targets,
    run_scan_jobs,
)
from sandbox_cli.services.scanner.uploads import apply_uploads
from sandbox_cli.services.scanner.utils import compute_wait_time

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.backends import ScanBackend
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
    return options


async def scan_internal(request: BasicScanRequest, reporter: ScanReporter) -> None:
    async with open_backends(request.key_names) as backends:
        prepared = await prepare_scan(
            {backend.name: backend.sandbox for backend in backends},
            rules=request.rules,
            is_local=request.is_local,
            scan_images=request.images,
            hooks=request.hooks,
        )
        backends = [replace(backend, uploads=prepared.uploads[backend.name]) for backend in backends]
        base_options = _scan_options(request, prepared)
        if request.custom_command:
            console.info(f"Using custom command: {request.custom_command}")

        wait_timeout = compute_wait_time(request.analysis_duration)
        download_options = replace(request.download_options, video=True, logs=True)

        def make_job(target: ScanTarget) -> ScanJob:
            def bind(backend: ScanBackend) -> Submission:
                options = base_options.model_copy(deep=True)
                options.sandbox.image_id = str(target.image)
                apply_uploads(options.sandbox.debug_options, backend.uploads)

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

                return Submission(
                    arguments=SandboxArguments(
                        type=ScanType.SCAN, sandbox_key_name=backend.name, sandbox_options=options.sandbox
                    ),
                    submit=submit,
                )

            return ScanJob(
                name=target.file.name,
                image=str(target.image),
                out_dir=target.out_dir,
                idx=target.idx,
                bind=bind,
                wait_timeout=wait_timeout,
                download_options=download_options,
            )

        jobs = [make_job(t) for t in plan_targets(request.files, prepared.images, request.out_dir)]
        await run_scan_jobs(backends, jobs, reporter, unpack=request.unpack, open_browser=request.open_browser)
