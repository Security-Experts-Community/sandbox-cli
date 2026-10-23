from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyclopts import Parameter, validators
from ptsandbox.models import VNCMode

from sandbox_cli.cli._converters import existing, files_path_resolver, ip_addresses_validator
from sandbox_cli.cli._params import (
    MIN_DURATION,
    SANDBOX_OPTIONS,
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
    WaitTimeout,
    default_key,
    sandbox_option,
    sandbox_switch,
)
from sandbox_cli.core.config import DEFAULT_DURATION, DEFAULT_IMAGE
from sandbox_cli.core.reporting import make_scan_reporter
from sandbox_cli.services.scanner.advanced import scan_internal_advanced
from sandbox_cli.services.scanner.prepare import HookFiles
from sandbox_cli.services.scanner.requests import AdvancedScanRequest

__all__ = ["scan_new"]


async def scan_new(
    files: Annotated[list[Path], Parameter(help="Path to the files or folders to scan")],
    /,
    *,
    rules_dir: RulesDir = None,
    out_dir: OutDir = Path("./sandbox"),
    images: Images = None,
    key: Key = default_key(),
    is_local: IsLocal = False,
    upload_timeout: UploadTimeout = 300,
    wait_timeout: WaitTimeout = None,
    fake_name: FakeName = None,
    analysis_duration: AnalysisDuration = DEFAULT_DURATION,
    syscall_hooks: SyscallHooks = None,
    dll_hooks_dir: DllHooksDir = None,
    unimon_hooks: Annotated[
        Path | None,
        sandbox_option(["--unimon-hooks", "-u"], "Path to file with unimon hooks", validator=existing("file")),
    ] = None,
    fileextractor_excludes: Annotated[
        Path | None,
        sandbox_option(
            ["--fileextractor-excludes", "-fe"],
            "Path to file with fileextractor excludes",
            validator=existing("file"),
        ),
    ] = None,
    procdump_excludes: Annotated[
        Path | None,
        sandbox_option(
            ["--procdump-excludes", "-pe"],
            "Path to file with procdump excludes (regular expressions of process paths, one per line)",
            validator=existing("file"),
        ),
    ] = None,
    custom_command: CustomCommand = None,
    unpack: UnpackFlag = False,
    priority: Annotated[
        int,
        Parameter(
            name=["--priority", "-pr"],
            help="Priority of the scan (1-4)",
            validator=validators.Number(gte=1, lte=4),
            group=SANDBOX_OPTIONS,
        ),
    ] = 3,
    no_procdumps_on_finish: Annotated[
        bool,
        sandbox_switch(["--no-procdumps-on-finish", "-P"], "Disable dumps for all created and not finished processes"),
    ] = False,
    disable_lightweight_dumps: Annotated[
        bool,
        sandbox_switch(
            ["--disable-lightweight-dumps", "-dl"], "Disable lightweight memory dumps (mostly for testing purposes)"
        ),
    ] = False,
    bootkitmon: Annotated[bool, sandbox_switch(["--bootkitmon", "-b"], "Enable bootkitmon")] = False,
    bootkitmon_duration: Annotated[
        int,
        Parameter(
            name=["--bootkitmon-duration", "-bd"],
            help="Bootkitmon duration in seconds",
            validator=validators.Number(gte=MIN_DURATION),
            group=SANDBOX_OPTIONS,
        ),
    ] = 60,
    mitm_disabled: Annotated[bool, sandbox_switch(["--mitm-disabled", "-M"], "Disable MITM")] = False,
    disable_clicker: Annotated[bool, sandbox_switch(["--disable-clicker", "-dc"], "Disable clicker")] = False,
    skip_sample_run: Annotated[bool, sandbox_switch(["--skip-sample-run", "-S"], "Skip sample run")] = False,
    vnc_mode: Annotated[VNCMode, sandbox_option(["--vnc-mode", "-V"], "VNC mode")] = VNCMode.DISABLED,
    extra_files: Annotated[
        list[Path] | None,
        sandbox_switch(["--extra-files", "-e"], "Extra files to upload", validator=existing("file")),
    ] = None,
    outbound_connections: Annotated[
        list[str] | None,
        sandbox_switch(
            ["--outbound-connections", "-oc"],
            "Whitelist of IP addresses to which connections from a VM are allowed (backconnect)",
            validator=ip_addresses_validator,
        ),
    ] = None,
    file_type_as_ext: Annotated[
        bool | None, sandbox_switch(["--file-type-as-ext", "-fte"], "Use a file type as an extension for a file")
    ] = None,
    unpack_archives: Annotated[
        bool,
        sandbox_switch(
            ["--unpack-archives", "-ua"],
            "Unpack archives in the sandbox with the passwords from the config and analyze every extracted file",
        ),
    ] = False,
    artifacts: ArtifactFlags = ArtifactFlags(),
    open_browser: OpenBrowser = False,
    json_output: JsonOutput = False,
    preserve_filename: Annotated[
        bool,
        Parameter(
            name=["--preserve-filename", "-pf"],
            help="Do not change filename for analysis.  \nWhen set to false (default behaviour): local/path/to/malware.exe[_~] -> sandbox/guest/os/malware.exe  \nWhen set to true name will remain unchanged.",
            negative="",
        ),
    ] = False,
) -> None:
    """
    Send files to scan with the sandbox (advanced scan).
    """

    request = AdvancedScanRequest(
        key_name=key,
        out_dir=out_dir,
        rules_dir=rules_dir,
        is_local=is_local,
        unpack=unpack,
        open_browser=open_browser,
        download_options=artifacts.to_options(),
        files=files_path_resolver(files),
        images=images or {DEFAULT_IMAGE},
        hooks=HookFiles(
            syscall_hooks=syscall_hooks,
            dll_hooks_dir=dll_hooks_dir,
            unimon_hooks=unimon_hooks,
            fileextractor_excludes=fileextractor_excludes,
            procdump_excludes=procdump_excludes,
        ),
        analysis_duration=analysis_duration,
        custom_command=custom_command,
        fake_name=fake_name,
        upload_timeout=upload_timeout,
        wait_timeout=wait_timeout,
        priority=priority,
        preserve_filename=preserve_filename,
        unpack_archives=unpack_archives,
        extra_files=extra_files or [],
        no_procdumps_on_finish=no_procdumps_on_finish,
        disable_lightweight_dumps=disable_lightweight_dumps,
        bootkitmon=bootkitmon,
        bootkitmon_duration=bootkitmon_duration,
        mitm_disabled=mitm_disabled,
        disable_clicker=disable_clicker,
        skip_sample_run=skip_sample_run,
        vnc_mode=vnc_mode,
        outbound_connections=outbound_connections or [],
        file_type_as_ext=file_type_as_ext,
    )
    await scan_internal_advanced(request, make_scan_reporter(with_image=True, json_output=json_output))
