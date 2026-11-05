"""
``scan-new``: the advanced scan of a file; plain archives may run as a full scan instead.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxOptions, SandboxOptionsAdvanced, VNCMode

from sandbox_cli.console import console
from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.core.scan import ScanType
from sandbox_cli.services.scanner.kinds.base import FileScan, full_scan_options
from sandbox_cli.services.scanner.pipeline.jobs import Submission
from sandbox_cli.services.scanner.requests import AdvancedScanRequest

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.pipeline.jobs import ScanTarget

__all__ = ["AdvancedScan", "archive_scan_options", "find_archives", "guest_filename", "is_archive", "sandbox_options"]

_SIGNATURES: tuple[tuple[int, bytes], ...] = (
    (0, b"7z\xbc\xaf\x27\x1c"),
    (0, b"Rar!\x1a\x07"),
    (0, b"\x1f\x8b"),  # gzip
    (0, b"BZh"),
    (0, b"\xfd7zXZ\x00"),
    (0, b"MSCF"),  # cab
    (257, b"ustar"),  # tar
)
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")

# zip containers that are documents or packages rather than archives
_ZIP_CONTAINER_MARKERS = frozenset({"[Content_Types].xml", "AndroidManifest.xml", "META-INF/MANIFEST.MF", "mimetype"})


def _is_plain_zip(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    return not _ZIP_CONTAINER_MARKERS.intersection(names)


def is_archive(path: Path) -> bool:
    """
    Whether ``path`` is an archive by its signature (zip, 7z, rar, gzip, bzip2, xz, cab, tar).

    Office documents, JARs and APKs are zip files too, but not archives here.
    """
    try:
        with open(path, "rb") as fd:
            head = fd.read(262)
    except OSError:
        return False

    if head.startswith(_ZIP_SIGNATURES):
        return _is_plain_zip(path)
    return any(head[offset : offset + len(magic)] == magic for offset, magic in _SIGNATURES)


SAFE_SUFFIXES = "_~"


def guest_filename(name: str, *, preserve: bool) -> str:
    """
    Name of the sample inside the VM.

    Strips a trailing ``_`` or ``~`` (a way to keep samples non-executable on disk)
    unless ``preserve`` is set.
    """
    return name if preserve else name.rstrip(SAFE_SUFFIXES)  # rstrip is used intentionally


def sandbox_options(request: AdvancedScanRequest) -> SandboxOptionsAdvanced:
    options = SandboxOptionsAdvanced(
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
    return options


def archive_scan_options(options: SandboxOptionsAdvanced) -> SandboxBaseScanTaskRequest.Options:
    """
    Options of the full scan for an archive: unpack it with the config passwords and
    run every extracted file with the same VM settings.
    """
    return full_scan_options(
        SandboxOptions(
            image_id=options.image_id,
            analysis_duration=options.analysis_duration,
            custom_command=options.custom_command,
            debug_options=options.debug_options.copy(),
            mitm_enabled=options.mitm_enabled,
            bootkitmon=options.bootkitmon,
            analysis_duration_bootkitmon=options.analysis_duration_bootkitmon,
            procdump_new_processes_on_finish=options.procdump_new_processes_on_finish,
        )
    )


def _archive_flag_conflicts(request: AdvancedScanRequest) -> list[str]:
    flags = {
        "--disable-clicker": request.disable_clicker,
        "--extra-files": bool(request.extra_files),
        "--skip-sample-run": request.skip_sample_run,
        "--vnc-mode": request.vnc_mode != VNCMode.DISABLED,
    }
    return [flag for flag, used in flags.items() if used]


def find_archives(request: AdvancedScanRequest) -> set[Path]:
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


class AdvancedScan(FileScan[AdvancedScanRequest, SandboxOptionsAdvanced]):
    def __init__(self, request: AdvancedScanRequest) -> None:
        super().__init__(request)
        self._archives: set[Path] = set()

    def check(self) -> None:
        self._archives = find_archives(self.request)

    def base_options(self) -> SandboxOptionsAdvanced:
        request = self.request
        if request.custom_command:
            console.info(f"Commandline: {request.custom_command}")
        if request.file_type_as_ext is not None:
            console.info("Using magic types from the sandbox")
        return sandbox_options(request)

    def submission(self, target: ScanTarget, options: SandboxOptionsAdvanced) -> Submission:
        request = self.request
        options = options.model_copy(update={"image_id": str(target.image)}, deep=True)
        file_name = request.fake_name or guest_filename(target.file.name, preserve=request.preserve_filename)

        if target.file in self._archives:
            full = archive_scan_options(options)

            async def submit_archive(sandbox: Sandbox) -> SandboxBaseTaskResponse:
                return await sandbox.create_scan(
                    target.file,
                    file_name=file_name,
                    options=full,
                    rules=None,
                    priority=request.priority,
                    upload_timeout=request.upload_timeout,
                    async_result=True,
                )

            return Submission(type=ScanType.SCAN, options=full.sandbox, submit=submit_archive)

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

        return Submission(type=ScanType.SCAN_NEW, options=options, submit=submit)
