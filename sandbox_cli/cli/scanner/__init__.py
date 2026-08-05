from __future__ import annotations

from cyclopts import App

from sandbox_cli.cli.scanner.re_scan import re_scan
from sandbox_cli.cli.scanner.scan import scan
from sandbox_cli.cli.scanner.scan_new import scan_new

__all__ = ["scanner"]

scanner = App(
    name="scanner",
    help="Scan with the sandbox.",
    help_format="markdown",
)

scanner.command(name="re-scan")(re_scan)
scanner.command(name="scan")(scan)
scanner.command(name="scan-new")(scan_new)
