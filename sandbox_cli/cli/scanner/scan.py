from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyclopts import Parameter

from sandbox_cli.cli._converters import files_path_resolver
from sandbox_cli.cli._params import (
    AnalysisDuration,
    ArtifactFlags,
    CustomCommand,
    DllHooksDir,
    FakeName,
    Images,
    IsLocal,
    JsonOutput,
    Key,
    OpenBrowser,
    OutDir,
    RulesDir,
    SyscallHooks,
    UnpackFlag,
    UploadTimeout,
    default_key,
)
from sandbox_cli.console import console
from sandbox_cli.core.config import DEFAULT_DURATION, DEFAULT_IMAGE
from sandbox_cli.core.reporting import make_scan_reporter
from sandbox_cli.services.scanner import scan_internal
from sandbox_cli.services.scanner.prepare import HookFiles
from sandbox_cli.services.scanner.requests import BasicScanRequest

__all__ = ["scan"]


async def scan(
    files: Annotated[list[Path], Parameter(help="Path to the files or folders to scan")],
    /,
    *,
    rules_dir: RulesDir = None,
    out_dir: OutDir = Path("./sandbox"),
    images: Images = None,
    key: Key = default_key(),
    is_local: IsLocal = False,
    unpack: UnpackFlag = False,
    upload_timeout: UploadTimeout = 300,
    fake_name: FakeName = None,
    analysis_duration: AnalysisDuration = DEFAULT_DURATION,
    syscall_hooks: SyscallHooks = None,
    dll_hooks_dir: DllHooksDir = None,
    custom_command: CustomCommand = None,
    artifacts: ArtifactFlags = ArtifactFlags(),
    open_browser: OpenBrowser = False,
    json_output: JsonOutput = False,
) -> None:
    """
    Send files to scan with the sandbox.

    .. deprecated::
        Use ``scan-new`` instead.

    Folders are scanned recursively. ``max-workers`` of the key limits parallel scans (usually 8).
    """

    console.warning('The "scan" command is deprecated. Use "scan-new" instead.')

    request = BasicScanRequest(
        key_name=key,
        out_dir=out_dir,
        rules_dir=rules_dir,
        is_local=is_local,
        unpack=unpack,
        open_browser=open_browser,
        download_options=artifacts.to_options(),
        files=files_path_resolver(files),
        images=images or {DEFAULT_IMAGE},
        hooks=HookFiles(syscall_hooks=syscall_hooks, dll_hooks_dir=dll_hooks_dir),
        analysis_duration=analysis_duration,
        custom_command=custom_command,
        fake_name=fake_name,
        upload_timeout=upload_timeout,
    )
    await scan_internal(request, make_scan_reporter(with_image=True, json_output=json_output))
