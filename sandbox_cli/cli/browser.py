from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyclopts import Parameter

from sandbox_cli.core.browser import open_link
from sandbox_cli.core.config import REPORT_NAME
from sandbox_cli.core.exceptions import SandboxCliError
from sandbox_cli.core.sandbox import (
    format_link,
    get_sandbox_config,
)
from sandbox_cli.core.scan import SCAN_CONFIG_NAME, load_report, load_scan_arguments

__all__ = ["open_browser"]


def open_browser(
    path: Annotated[
        Path,
        Parameter(
            help="Folder with sandbox report (report.json and scan_config.json)",
        ),
    ] = Path(),
) -> None:
    """
    Open sandbox link in the default browser.
    """

    report_file = path / REPORT_NAME
    if not report_file.exists():
        raise SandboxCliError(f"Can't find {REPORT_NAME}: {path}")

    scan_config_file = next((p for p in (path / SCAN_CONFIG_NAME, path.parent / SCAN_CONFIG_NAME) if p.exists()), None)
    if scan_config_file is None:
        raise SandboxCliError(f"Can't find {SCAN_CONFIG_NAME}: {path}")

    report = load_report(report_file)
    scan_config = load_scan_arguments(scan_config_file)

    link = format_link(report, get_sandbox_config(scan_config.sandbox_key_name).host)

    open_link(link)
