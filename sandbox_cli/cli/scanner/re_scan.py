from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyclopts import Parameter, validators

from sandbox_cli.cli._converters import (
    out_dir_converter,
    out_dir_validator,
    rules_path_resolver,
    trace_converter,
    trace_validator,
)
from sandbox_cli.core.config import key_help, settings
from sandbox_cli.core.sandbox import validate_key
from sandbox_cli.services.downloader import DownloadOptions
from sandbox_cli.services.scanner.rescan import rescan_internal

__all__ = ["re_scan"]


async def re_scan(
    traces: Annotated[
        list[Path],
        Parameter(
            help="Path to folder with **drakvuf-trace.log.zst and tcpdump.pcap** or **sandbox_logs.zip**",
            converter=trace_converter,
            validator=trace_validator,
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

    await rescan_internal(
        traces=traces,
        rules_dir=rules_dir,
        out_dir=out_dir,
        key_name=key,
        is_local=is_local,
        unpack=unpack,
        download_options=DownloadOptions(debug=debug),
        open_browser=open_browser,
        timeout=timeout,
    )
