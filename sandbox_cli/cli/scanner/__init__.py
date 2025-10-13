import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any

from cyclopts import App, Parameter, Token, validators
from ptsandbox.models import VNCMode

from sandbox_cli.console import console
from sandbox_cli.internal.config import Platform, VMImage, settings
from sandbox_cli.internal.helpers import validate_key
from sandbox_cli.utils.scanner import scan_internal
from sandbox_cli.utils.scanner.advanced import scan_internal_advanced
from sandbox_cli.utils.scanner.rescan import rescan_internal

DELIMETER = "\n"

scanner = App(
    name="scanner",
    help="Scan with the sandbox.",
    help_format="markdown",
)


def image_converter(_: Any, tokens: Sequence[Token]) -> set[VMImage | str]:
    images: set[VMImage | str] = set()
    for token in tokens:
        try:
            images.add(VMImage(token.value))
        except ValueError:
            # maybe it is custom image?
            images.add(token.value)

    return images


def rules_path_resolver(_: Any, tokens: Sequence[Token]) -> Path | None:
    path: Path | None = None
    for token in tokens:
        if token.value in {Platform.LINUX, Platform.WINDOWS}:
            if not settings.rules_path:
                console.error("You can't use aliases without specifying the path in the config")
                sys.exit(1)

            path = settings.rules_path / token.value
            break
        else:
            # if not found any platform, use specifed value as path
            path = Path(token.value)

    return path


@scanner.command(name="re-scan")
async def re_scan(
    traces: Annotated[
        list[Path],
        Parameter(
            help="Path to folder with **drakvuf-trace.log.zst and tcpdump.pcap** or **sandbox_logs.zip**",
        ),
    ],
    /,
    *,
    rules_dir: Annotated[
        Path | None,
        Parameter(
            name=["--rules", "-r"],
            help="The path to the folder with the rules or the default rules from the sandbox or platform alias (windows, linux)",
            converter=rules_path_resolver,
        ),
    ] = None,
    out_dir: Annotated[
        Path,
        Parameter(
            name=["--out", "-o"],
            help="The path where to save the results",
        ),
    ] = Path("./sandbox"),
    key: Annotated[
        str,
        Parameter(
            name=["--key", "-k"],
            help=f"The key to access the sandbox **{'**,**'.join(x.name.get_secret_value() for x in settings.sandbox_keys)}**",
            validator=validate_key,
            group="Sandbox Options",
        ),
    ] = settings.sandbox_keys[0].name.get_secret_value(),
    is_local: Annotated[
        bool,
        Parameter(
            name=["--local", "-l"],
            negative="",
            help="The rules will be compiled locally using Docker (unix only)",
        ),
    ] = False,
    unpack: Annotated[
        bool,
        Parameter(
            name=["--unpack", "-U"],
            help="Unpack downloaded files",
            negative="",
        ),
    ] = False,
    debug: Annotated[
        bool,
        Parameter(
            name=["--debug", "-d"],
            help="Download debug artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    open_browser: Annotated[
        bool,
        Parameter(
            name=["--open-browser", "-ob"],
            help="Open analysis link in the default browser",
            negative="",
        ),
    ] = False,
    timeout: Annotated[
        int,
        Parameter(
            name=["--timeout", "-t"],
            help="Response waiting time (increase this value if large traces are scanned)",
            validator=validators.Number(gt=0, lt=3600),
        ),
    ] = 300,
) -> None:
    """
    Send traces to re-scan.
    """

    out_dir.mkdir(exist_ok=True, parents=True)
    out_dir = out_dir.expanduser().resolve()

    # sanity check for traces
    is_ok = True
    for trace in traces:
        trace = trace.expanduser().resolve()
        if not trace.exists():
            console.log(f"{str(trace)} doesn't exists", style="bold red")
            is_ok = False

    if not is_ok:
        sys.exit(1)

    await rescan_internal(
        traces=traces,
        rules_dir=rules_dir,
        out_dir=out_dir,
        key_name=key,
        is_local=is_local,
        unpack=unpack,
        debug=debug,
        open_browser=open_browser,
        timeout=timeout,
    )


@scanner.command(name="scan")
async def scan(
    files: Annotated[
        list[Path],
        Parameter(
            help="Path to the files or folders to scan",
        ),
    ],
    /,
    *,
    rules_dir: Annotated[
        Path | None,
        Parameter(
            name=["--rules", "-r"],
            help="The path to the folder with the rules or the default rules from the sandbox or platform alias (windows, linux)",
            converter=rules_path_resolver,
        ),
    ] = None,
    out_dir: Annotated[
        Path,
        Parameter(
            name=["--out", "-o"],
            help="The path where to save the results",
        ),
    ] = Path("./sandbox"),
    images: Annotated[
        set[VMImage] | None,
        Parameter(
            name=["--image", "-i"],
            help=f"The name of the image to scan (*don't mix different platforms*) {DELIMETER}{DELIMETER.join(f'* {x}' for x in VMImage._value2member_map_.keys())}{DELIMETER * 2}",
            negative="",
            group="Sandbox Options",
            show_choices=False,
            converter=image_converter,
        ),
    ] = None,
    key: Annotated[
        str,
        Parameter(
            name=["--key", "-k"],
            help=f"The key to access the sandbox **{'**,**'.join(x.name.get_secret_value() for x in settings.sandbox_keys)}**",
            validator=validate_key,
            group="Sandbox Options",
        ),
    ] = settings.sandbox_keys[0].name.get_secret_value(),
    is_local: Annotated[
        bool,
        Parameter(
            name=["--local", "-l"],
            negative="",
            help="The rules will be compiled locally using Docker (unix only)",
        ),
    ] = False,
    unpack: Annotated[
        bool,
        Parameter(
            name=["--unpack", "-U"],
            help="Unpack downloaded files",
            negative="",
        ),
    ] = False,
    upload_timeout: Annotated[
        int,
        Parameter(
            name=["--upload-timeout", "-T"],
            help="Upload timeout in seconds (increase if upload big files)",
            validator=validators.Number(gt=0),
        ),
    ] = 300,
    fake_name: Annotated[
        str | None,
        Parameter(
            name=["--name", "-n"],
            help="Fake name for the sandbox (if specified more than one files will be applied to all files)",
            group="Sandbox Options",
        ),
    ] = None,
    analysis_duration: Annotated[
        int,
        Parameter(
            name=["--timeout", "-t"],
            help="Analysis duration in seconds",
            validator=validators.Number(gt=0, lt=3600),
            group="Sandbox Options",
        ),
    ] = settings.default_duration,
    syscall_hooks: Annotated[
        Path | None,
        Parameter(
            name=["--syscall-hooks", "-s"],
            help="Path to files with syscall hooks (file with syscall names splitted by newline)",
            group="Sandbox Options",
        ),
    ] = None,
    dll_hooks_dir: Annotated[
        Path | None,
        Parameter(
            name=["--dll-hooks-dir", "-dll"],
            help="Path to directory with dll hooks",
            group="Sandbox Options",
        ),
    ] = None,
    custom_command: Annotated[
        str | None,
        Parameter(
            name="--cmd",
            help="Command line for file execution `rundll32.exe {file},#1`",
            group="Sandbox Options",
        ),
    ] = None,
    all: Annotated[
        bool,
        Parameter(
            name=["--all", "-a"],
            help="Download all artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    debug: Annotated[
        bool,
        Parameter(
            name=["--debug", "-d"],
            help="Download debug artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    artifacts: Annotated[
        bool,
        Parameter(
            name=["--artifacts", "-A"],
            help="Download artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    download_files: Annotated[
        bool,
        Parameter(
            name=["--files", "-f"],
            help="Download files",
            negative="",
            group="Download options",
        ),
    ] = False,
    crashdumps: Annotated[
        bool,
        Parameter(
            name=["--crashdumps", "-c"],
            help="Download crashdumps (maybe be more 1GB)",
            negative="",
            group="Download options",
        ),
    ] = False,
    procdumps: Annotated[
        bool,
        Parameter(
            name=["--procdumps", "-p"],
            help="Download procdumps",
            negative="",
            group="Download options",
        ),
    ] = False,
    decompress: Annotated[
        bool,
        Parameter(
            name=["--decompress", "-D"],
            help="Decompress downloaded files",
            negative="",
        ),
    ] = False,
    open_browser: Annotated[
        bool,
        Parameter(
            name=["--open-browser", "-ob"],
            help="Open analysis link in the default browser",
            negative="",
        ),
    ] = False,
) -> None:
    """
    Send files to scan with the sandbox.

    If you want to scan a folder, you can specify the path to the folder

    Amount of simultaneous scans is limited by the sandbox settings (usually 8)
    """

    console.warning('Deprecated option, not particularly supported. Use "scan-new" instead')

    # some path preparations
    out_dir.mkdir(exist_ok=True, parents=True)
    out_dir = out_dir.expanduser().resolve()

    if images is None:
        images = {settings.default_image}

    # parse files options
    is_ok = True
    files_for_analysis: list[Path] = []
    for file in files:
        file = file.expanduser().resolve()

        if not file.exists():
            console.error(f"{str(file)} doesn't exists")
            is_ok = False

        if file.is_dir():
            files_for_analysis.extend(file.glob("**/*"))
            continue

        files_for_analysis.append(file)

    if not is_ok:
        sys.exit(1)

    if len(files_for_analysis) == 0:
        console.error("Nothing to scan")
        sys.exit(1)

    await scan_internal(
        files=files_for_analysis,
        scan_images=images,
        rules_dir=rules_dir,
        out_dir=out_dir,
        key_name=key,
        is_local=is_local,
        analysis_duration=analysis_duration,
        syscall_hooks=syscall_hooks,
        custom_command=custom_command,
        dll_hooks_dir=dll_hooks_dir,
        fake_name=fake_name,
        unpack=unpack,
        upload_timeout=upload_timeout,
        all=all,
        debug=debug,
        artifacts=artifacts,
        download_files=download_files,
        crashdumps=crashdumps,
        procdumps=procdumps,
        decompress=decompress,
        open_browser=open_browser,
    )


@scanner.command(name="scan-new")
async def scan_new(
    files: Annotated[
        list[Path],
        Parameter(
            help="Path to the files or folders to scan",
        ),
    ],
    /,
    *,
    rules_dir: Annotated[
        Path | None,
        Parameter(
            name=["--rules", "-r"],
            help="The path to the folder with the rules or the default rules from the sandbox or platform alias (windows, linux)",
            converter=rules_path_resolver,
        ),
    ] = None,
    out_dir: Annotated[
        Path,
        Parameter(
            name=["--out", "-o"],
            help="The path where to save the results",
        ),
    ] = Path("./sandbox"),
    images: Annotated[
        set[VMImage | str] | None,
        Parameter(
            name=["--image", "-i"],
            help=f"The name of the image to scan (*don't mix different platforms*) {DELIMETER}{DELIMETER.join(f'* {x}' for x in VMImage._value2member_map_.keys())}{DELIMETER * 2}",
            negative="",
            group="Sandbox Options",
            show_choices=False,
            converter=image_converter,
        ),
    ] = None,
    key: Annotated[
        str,
        Parameter(
            name=["--key", "-k"],
            help=f"The key to access the sandbox **{'**,**'.join(x.name.get_secret_value() for x in settings.sandbox_keys)}**",
            validator=validate_key,
            group="Sandbox Options",
        ),
    ] = settings.sandbox_keys[0].name.get_secret_value(),
    is_local: Annotated[
        bool,
        Parameter(
            name=["--local", "-l"],
            negative="",
            help="The rules will be compiled locally using Docker (unix only)",
        ),
    ] = False,
    upload_timeout: Annotated[
        int,
        Parameter(
            name=["--upload-timeout", "-T"],
            help="Upload timeout in seconds (increase if upload big files)",
            validator=validators.Number(gt=0),
        ),
    ] = 300,
    wait_timeout: Annotated[
        int | None,
        Parameter(
            name=["--wait-timeout", "-W"],
            help="Task waiting time in seconds (useful for heavy samples)",
            validator=validators.Number(gt=0),
        ),
    ] = None,
    fake_name: Annotated[
        str | None,
        Parameter(
            name=["--name", "-n"],
            help="Fake name for the sandbox (if specified more than one file will be applied to all files)",
            group="Sandbox Options",
        ),
    ] = None,
    analysis_duration: Annotated[
        int,
        Parameter(
            name=["--timeout", "-t"],
            help="Analysis duration in seconds",
            validator=validators.Number(gt=0, lt=3600),
            group="Sandbox Options",
        ),
    ] = settings.default_duration,
    syscall_hooks: Annotated[
        Path | None,
        Parameter(
            name=["--syscall-hooks", "-s"],
            help="Path to files with syscall hooks (file with syscall names splitted by newline)",
            group="Sandbox Options",
        ),
    ] = None,
    dll_hooks_dir: Annotated[
        Path | None,
        Parameter(
            name=["--dll-hooks-dir", "-dll"],
            help="Path to directory with dll hooks",
            group="Sandbox Options",
        ),
    ] = None,
    custom_command: Annotated[
        str | None,
        Parameter(
            name="--cmd",
            help="Command line for file execution _rundll32.exe {file},#1_",
            group="Sandbox Options",
        ),
    ] = None,
    unpack: Annotated[
        bool,
        Parameter(
            name=["--unpack", "-U"],
            help="Unpack downloaded files",
            negative="",
        ),
    ] = False,
    priority: Annotated[
        int,
        Parameter(
            name=["--priority", "-pr"],
            help="Priority of the scan (1-4)",
            validator=validators.Number(gte=1, lte=4),
            group="Sandbox Options",
        ),
    ] = 3,
    no_procdumps_on_finish: Annotated[
        bool,
        Parameter(
            name=["--no-procdumps-on-finish", "-P"],
            help="Disable dumps for all created and not finished processes",
            group="Sandbox Options",
            negative="",
        ),
    ] = False,
    bootkitmon: Annotated[
        bool,
        Parameter(
            name=["--bootkitmon", "-b"],
            help="Enable bootkitmon",
            group="Sandbox Options",
            negative="",
        ),
    ] = False,
    bootkitmon_duration: Annotated[
        int,
        Parameter(
            name=["--bootkitmon-duration", "-bd"],
            help="Bootkitmon duration in seconds",
            validator=validators.Number(gt=0),
            group="Sandbox Options",
            negative="",
        ),
    ] = 60,
    mitm_disabled: Annotated[
        bool,
        Parameter(
            name=["--mitm-disabled", "-M"],
            help="Disable MITM",
            group="Sandbox Options",
            negative="",
        ),
    ] = False,
    disable_clicker: Annotated[
        bool,
        Parameter(
            name=["--disable-clicker", "-dc"],
            help="Disable clicker",
            group="Sandbox Options",
            negative="",
        ),
    ] = False,
    skip_sample_run: Annotated[
        bool,
        Parameter(
            name=["--skip-sample-run", "-S"],
            help="Skip sample run",
            group="Sandbox Options",
            negative="",
        ),
    ] = False,
    vnc_mode: Annotated[
        VNCMode,
        Parameter(
            name=["--vnc-mode", "-V"],
            help="VNC mode",
            group="Sandbox Options",
        ),
    ] = VNCMode.DISABLED,
    extra_files: Annotated[
        list[Path] | None,
        Parameter(
            name=["--extra-files", "-e"],
            help="Extra files to upload",
            group="Sandbox Options",
            negative="",
        ),
    ] = None,
    outbound_connections: Annotated[
        list[str] | None,
        Parameter(
            name=["--outbound-connections", "-oc"],
            help="Whitelist of IP addresses to which connections from a VM are allowed (backconnect)",
            group="Sandbox Options",
            negative="",
        ),
    ] = None,
    all: Annotated[
        bool,
        Parameter(
            name=["--all", "-a"],
            help="Download all artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    debug: Annotated[
        bool,
        Parameter(
            name=["--debug", "-d"],
            help="Download debug artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    artifacts: Annotated[
        bool,
        Parameter(
            name=["--artifacts", "-A"],
            help="Download artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    download_files: Annotated[
        bool,
        Parameter(
            name=["--files", "-f"],
            help="Download files",
            negative="",
            group="Download options",
        ),
    ] = False,
    crashdumps: Annotated[
        bool,
        Parameter(
            name=["--crashdumps", "-c"],
            help="Download crashdumps (maybe be more 1GB)",
            negative="",
            group="Download options",
        ),
    ] = False,
    procdumps: Annotated[
        bool,
        Parameter(
            name=["--procdumps", "-p"],
            help="Download procdumps",
            negative="",
            group="Download options",
        ),
    ] = False,
    decompress: Annotated[
        bool,
        Parameter(
            name=["--decompress", "-D"],
            help="Decompress downloaded files",
            negative="",
        ),
    ] = False,
    open_browser: Annotated[
        bool,
        Parameter(
            name=["--open-browser", "-ob"],
            help="Open analysis link in the default browser",
            negative="",
        ),
    ] = False,
) -> None:
    """
    Send files to scan with the sandbox (advanced scan).
    """

    # some path preparations
    out_dir.mkdir(exist_ok=True, parents=True)
    out_dir = out_dir.expanduser().resolve()

    if images is None:
        images = {settings.default_image}

    if extra_files is None:
        extra_files = []

    # parse files options
    is_ok = True
    files_for_analysis: list[Path] = []
    for file in files:
        file = file.expanduser().resolve()

        if not file.exists():
            console.error(f"{str(file)} doesn't exists")
            is_ok = False

        if file.is_dir():
            files_for_analysis.extend(file.glob("**/*"))
            continue

        files_for_analysis.append(file)

    if not is_ok:
        sys.exit(1)

    if len(files_for_analysis) == 0:
        console.error("Nothing to scan")
        sys.exit(1)

    await scan_internal_advanced(
        files=files_for_analysis,
        scan_images=images,
        rules_dir=rules_dir,
        out_dir=out_dir,
        key_name=key,
        is_local=is_local,
        analysis_duration=analysis_duration,
        syscall_hooks=syscall_hooks,
        custom_command=custom_command,
        dll_hooks_dir=dll_hooks_dir,
        fake_name=fake_name,
        unpack=unpack,
        priority=priority,
        no_procdumps_on_finish=no_procdumps_on_finish,
        bootkitmon=bootkitmon,
        bootkitmon_duration=bootkitmon_duration,
        mitm_disabled=mitm_disabled,
        disable_clicker=disable_clicker,
        skip_sample_run=skip_sample_run,
        vnc_mode=vnc_mode,
        extra_files=extra_files,
        upload_timeout=upload_timeout,
        wait_timeout=wait_timeout,
        all=all,
        debug=debug,
        artifacts=artifacts,
        download_files=download_files,
        crashdumps=crashdumps,
        procdumps=procdumps,
        decompress=decompress,
        open_browser=open_browser,
        outbound_connections=outbound_connections,
    )
