from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

from cyclopts import Parameter, validators
from ptsandbox.models import VNCMode

from sandbox_cli.cli._converters import (
    files_path_resolver,
    image_converter,
    out_dir_converter,
    out_dir_validator,
    rules_path_resolver,
)
from sandbox_cli.core.config import VMImage, images_help, key_help, settings
from sandbox_cli.core.sandbox import validate_key
from sandbox_cli.services.downloader import DownloadOptions
from sandbox_cli.services.scanner.advanced import scan_internal_advanced

__all__ = ["scan_new"]


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
            converter=out_dir_converter,
            validator=out_dir_validator,
        ),
    ] = Path("./sandbox"),
    images: Annotated[
        set[VMImage | str] | None,
        Parameter(
            name=["--image", "-i"],
            help=f"The name of the image to scan (*don't mix different platforms*)\n{images_help()}\n\n",
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
            help=key_help(),
            validator=validate_key,
            group="Sandbox Options",
        ),
    ] = settings.default_key_name,
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
            help="Path to file with syscall hooks (file with syscall names split by newline)",
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
    unimon_hooks: Annotated[
        Path | None,
        Parameter(
            name=["--unimon-hooks", "-u"],
            help="Path to file with unimon hooks",
            group="Sandbox Options",
        ),
    ] = None,
    fileextractor_excludes: Annotated[
        Path | None,
        Parameter(
            name=["--fileextractor-excludes", "-fe"],
            help="Path to file with fileextractor excludes",
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
    disable_lightweight_dumps: Annotated[
        bool,
        Parameter(
            name=["--disable-lightweight-dumps", "-dl"],
            help="Disable lightweight memory dumps (mostly for testing purposes)",
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
    file_type_as_ext: Annotated[
        bool | None,
        Parameter(
            name=["--file-type-as-ext", "-fte"],
            help="Use a file type as an extension for a file",
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
            help="Download crashdumps (may be more than 1GB)",
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
    amsi: Annotated[
        bool,
        Parameter(
            name=["--amsi", "-am"],
            help="Download amsi-dumps",
            negative="",
            group="Download options",
        ),
    ] = False,
    dex: Annotated[
        bool,
        Parameter(
            name=["--dex", "-dx"],
            help="Download dex-dumps",
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

    if images is None:
        images = {settings.default_image}

    if extra_files is None:
        extra_files = []

    files_for_analysis = files_path_resolver(files)

    if not files_for_analysis:
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
        unimon_hooks=unimon_hooks,
        custom_command=custom_command,
        dll_hooks_dir=dll_hooks_dir,
        fileextractor_excludes=fileextractor_excludes,
        fake_name=fake_name,
        unpack=unpack,
        priority=priority,
        no_procdumps_on_finish=no_procdumps_on_finish,
        disable_lightweight_dumps=disable_lightweight_dumps,
        bootkitmon=bootkitmon,
        bootkitmon_duration=bootkitmon_duration,
        mitm_disabled=mitm_disabled,
        disable_clicker=disable_clicker,
        skip_sample_run=skip_sample_run,
        vnc_mode=vnc_mode,
        extra_files=extra_files,
        upload_timeout=upload_timeout,
        wait_timeout=wait_timeout,
        download_options=DownloadOptions(
            all=all,
            debug=debug,
            artifacts=artifacts,
            files=download_files,
            crashdumps=crashdumps,
            procdumps=procdumps,
            decompress=decompress,
            amsi=amsi,
            dex=dex,
        ),
        open_browser=open_browser,
        preserve_filename=preserve_filename,
        outbound_connections=outbound_connections,
        file_type_as_ext=file_type_as_ext,
    )
