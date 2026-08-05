from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyclopts import Parameter

from sandbox_cli.console import console
from sandbox_cli.core.browser import open_link
from sandbox_cli.core.sandbox import (
    format_link,
    get_key_by_name,
)
from sandbox_cli.core.scan import load_report, load_scan_arguments

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

    report_file = path / "report.json"
    if not report_file.exists():
        console.error(f"Can't find report.json: {path}")
        return

    scan_config_file = path / "scan_config.json"
    if not scan_config_file.exists():
        console.error(f"Can't find scan_config.json: {path}")
        return

    report = load_report(report_file)
    scan_config = load_scan_arguments(scan_config_file)

    key = get_key_by_name(scan_config.sandbox_key_name)
    link = format_link(report, key=key)

    open_link(link)
