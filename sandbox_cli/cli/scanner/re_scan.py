from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyclopts import Parameter

from sandbox_cli.cli._converters import trace_converter, trace_validator
from sandbox_cli.cli._params import (
    ArtifactFlags,
    IsLocal,
    JsonOutput,
    Key,
    OpenBrowser,
    OutDir,
    RulesDir,
    UnpackFlag,
    WaitTimeout,
    default_key,
)
from sandbox_cli.core.reporting import make_scan_reporter
from sandbox_cli.services.scanner.requests import RescanRequest
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
    rules_dir: RulesDir = None,
    out_dir: OutDir = Path("./sandbox"),
    key: Key = default_key(),
    is_local: IsLocal = False,
    unpack: UnpackFlag = False,
    wait_timeout: WaitTimeout = None,
    artifacts: ArtifactFlags = ArtifactFlags(),
    open_browser: OpenBrowser = False,
    json_output: JsonOutput = False,
) -> None:
    """
    Send traces to re-scan.
    """

    request = RescanRequest(
        key_name=key,
        out_dir=out_dir,
        rules_dir=rules_dir,
        is_local=is_local,
        unpack=unpack,
        open_browser=open_browser,
        download_options=artifacts.to_options(),
        traces=traces,
        wait_timeout=wait_timeout,
    )
    await rescan_internal(request, make_scan_reporter(with_image=False, json_output=json_output))
