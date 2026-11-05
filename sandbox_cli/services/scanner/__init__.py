"""
Scanning files and traces in the sandbox.

``engine.execute_scan`` runs a ``ScanKind`` (``kinds/``): the kind says what to
prepare and which jobs to run, ``prepare`` uploads what the jobs need and
``pipeline`` spreads the jobs over the sandboxes and downloads the results.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sandbox_cli.services.scanner.engine import execute_scan
from sandbox_cli.services.scanner.kinds.advanced import AdvancedScan
from sandbox_cli.services.scanner.kinds.basic import BasicScan
from sandbox_cli.services.scanner.kinds.rescan import Rescan

if TYPE_CHECKING:
    from sandbox_cli.services.scanner.pipeline.runner import ScanReporter
    from sandbox_cli.services.scanner.requests import AdvancedScanRequest, BasicScanRequest, RescanRequest

__all__ = ["rescan", "scan", "scan_new"]


async def scan(request: BasicScanRequest, reporter: ScanReporter) -> None:
    await execute_scan(BasicScan(request), reporter)


async def scan_new(request: AdvancedScanRequest, reporter: ScanReporter) -> None:
    await execute_scan(AdvancedScan(request), reporter)


async def rescan(request: RescanRequest, reporter: ScanReporter) -> None:
    await execute_scan(Rescan(request), reporter)
