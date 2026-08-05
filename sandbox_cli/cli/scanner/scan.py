from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

from cyclopts import Parameter, validators

from sandbox_cli.cli._converters import (
    files_path_resolver,
    image_converter,
    out_dir_converter,
    out_dir_validator,
    rules_path_resolver,
)
from sandbox_cli.console import console
from sandbox_cli.core.config import VMImage, images_help, key_help, settings
from sandbox_cli.core.sandbox import validate_key
from sandbox_cli.services.downloader import DownloadOptions
from sandbox_cli.services.scanner import scan_internal

__all__ = ["scan"]


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
            help="Path to files with syscall hooks (file with syscall names split by newline)",
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
) -> None:
    """
    Send files to scan with the sandbox.

    .. deprecated::
        Use ``scan-new`` instead. This command is not particularly supported.

    If you want to scan a folder, you can specify the path to the folder

    Amount of simultaneous scans is limited by the sandbox settings (usually 8)
    """

    console.warning('The "scan" command is deprecated. Use "scan-new" instead.')

    if images is None:
        images = {settings.default_image}

    files_for_analysis = files_path_resolver(files)

    if not files_for_analysis:
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
    )
