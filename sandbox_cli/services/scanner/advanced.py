from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from ptsandbox import Sandbox
from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxOptions, SandboxOptionsAdvanced, VNCMode

from sandbox_cli.console import console
from sandbox_cli.core.config import get_settings
from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.core.sandbox import get_key_by_name
from sandbox_cli.core.scan import SandboxArguments, ScanType
from sandbox_cli.services.scanner.archives import is_archive
from sandbox_cli.services.scanner.prepare import PreparedScan, prepare_scan
from sandbox_cli.services.scanner.runner import ScanJob, ScanReporter, ScanTarget, plan_targets, run_scan_jobs
from sandbox_cli.services.scanner.uploads import apply_uploads
from sandbox_cli.services.scanner.utils import compute_wait_time

if TYPE_CHECKING:
    from pathlib import Path

    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.requests import AdvancedScanRequest

__all__ = ["archive_scan_options", "guest_filename", "scan_internal_advanced"]

SAFE_SUFFIXES = "_~"


def guest_filename(name: str, *, preserve: bool) -> str:
    """
    Name of the sample inside the VM.

    Strips a trailing ``_`` or ``~`` (a way to keep samples non-executable on disk)
    unless ``preserve`` is set.
    """
    return name if preserve else name.rstrip(SAFE_SUFFIXES)  # rstrip is used intentionally


def _sandbox_options(request: AdvancedScanRequest, prepared: PreparedScan) -> SandboxOptionsAdvanced:
    options = SandboxOptionsAdvanced(
        image_id=str(prepared.default_image),
        analysis_duration=request.analysis_duration,
        custom_command=request.custom_command,
        procdump_new_processes_on_finish=not request.no_procdumps_on_finish,
        bootkitmon=request.bootkitmon,
        analysis_duration_bootkitmon=request.bootkitmon_duration,
        mitm_enabled=not request.mitm_disabled,
        disable_clicker=request.disable_clicker,
        skip_sample_run=request.skip_sample_run,
        vnc_mode=request.vnc_mode,
    )

    debug = options.debug_options
    debug["save_debug_files"] = True
    debug["extract_crashdumps"] = True
    # lightweight memory dumps are the default
    debug["procdump_lightweight_mode"] = not request.disable_lightweight_dumps
    debug["allowed_outbound_connections"] = request.outbound_connections
    if request.file_type_as_ext is not None:
        debug["file_type_as_ext"] = request.file_type_as_ext
    apply_uploads(debug, prepared.uploads)
    return options


def archive_scan_options(options: SandboxOptionsAdvanced) -> SandboxBaseScanTaskRequest.Options:
    """
    Options of the full scan for an archive: unpack it with the config passwords and
    run every extracted file with the same VM settings.
    """
    return SandboxBaseScanTaskRequest.Options(
        analysis_depth=2,
        passwords_for_unpack=get_settings().passwords,
        sandbox=SandboxOptions(
            image_id=options.image_id,
            analysis_duration=options.analysis_duration,
            custom_command=options.custom_command,
            debug_options=options.debug_options.copy(),
            mitm_enabled=options.mitm_enabled,
            bootkitmon=options.bootkitmon,
            analysis_duration_bootkitmon=options.analysis_duration_bootkitmon,
            procdump_new_processes_on_finish=options.procdump_new_processes_on_finish,
        ),
    )


def _archive_flag_conflicts(request: AdvancedScanRequest) -> list[str]:
    flags = {
        "--disable-clicker": request.disable_clicker,
        "--extra-files": bool(request.extra_files),
        "--skip-sample-run": request.skip_sample_run,
        "--vnc-mode": request.vnc_mode != VNCMode.DISABLED,
    }
    return [flag for flag, used in flags.items() if used]


def _find_archives(request: AdvancedScanRequest) -> set[Path]:
    archives = {file for file in request.files if is_archive(file)}
    if not archives:
        return set()

    if not request.unpack_archives:
        for archive in sorted(archives):
            console.warning(f"{archive.name} is an archive: it runs as one file. Add --unpack-archives to unpack it")
        return set()

    if conflicts := _archive_flag_conflicts(request):
        names = ", ".join(sorted(archive.name for archive in archives))
        raise ScanError(
            f"{names}: {', '.join(conflicts)} don't work with --unpack-archives "
            "(archives run as a full scan, which has no such options)"
        )
    return archives


async def scan_internal_advanced(request: AdvancedScanRequest, reporter: ScanReporter) -> None:
    key = get_key_by_name(request.key_name)
    archives = _find_archives(request)
    console.info(f"Using key: name={key.name} max_workers={key.max_workers}")

    async with Sandbox(key=key) as sandbox:
        prepared = await prepare_scan(
            sandbox,
            rules_dir=request.rules_dir,
            is_local=request.is_local,
            scan_images=request.images,
            hooks=request.hooks,
        )
        base_options = _sandbox_options(request, prepared)
        if request.custom_command:
            console.info(f"Commandline: {request.custom_command}")
        if request.file_type_as_ext is not None:
            console.info("Using magic types from the sandbox")

        wait_timeout = compute_wait_time(request.analysis_duration, request.wait_timeout)
        download_options = replace(request.download_options, video=True, logs=True)

        def make_job(target: ScanTarget) -> ScanJob:
            options = base_options.model_copy(update={"image_id": str(target.image)}, deep=True)

            file_name = request.fake_name or guest_filename(target.file.name, preserve=request.preserve_filename)

            async def submit_archive(sandbox: Sandbox) -> SandboxBaseTaskResponse:
                return await sandbox.create_scan(
                    target.file,
                    file_name=file_name,
                    options=archive_scan_options(options),
                    rules=None,
                    priority=request.priority,
                    upload_timeout=request.upload_timeout,
                    async_result=True,
                )

            async def submit(sandbox: Sandbox) -> SandboxBaseTaskResponse:
                return await sandbox.create_advanced_scan(
                    target.file,
                    file_name=file_name,
                    extra_files=request.extra_files,
                    async_result=True,
                    priority=request.priority,
                    upload_timeout=request.upload_timeout,
                    sandbox=options,
                )

            return ScanJob(
                name=target.file.name,
                image=str(target.image),
                out_dir=target.out_dir,
                idx=target.idx,
                submit=submit_archive if target.file in archives else submit,
                wait_timeout=wait_timeout,
                download_options=download_options,
                arguments=SandboxArguments(type=ScanType.SCAN_NEW, sandbox_key_name=key.name, sandbox_options=options),
            )

        jobs = [make_job(t) for t in plan_targets(request.files, prepared.images, request.out_dir)]
        await run_scan_jobs(sandbox, key, jobs, reporter, unpack=request.unpack, open_browser=request.open_browser)
