"""
The steps every scan command shares.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from sandbox_cli.services.scanner.pipeline.backends import open_backends
from sandbox_cli.services.scanner.pipeline.runner import run_scan_jobs
from sandbox_cli.services.scanner.prepare import prepare_scan

if TYPE_CHECKING:
    from sandbox_cli.services.scanner.kinds.base import ScanKind
    from sandbox_cli.services.scanner.pipeline.runner import ScanReporter

__all__ = ["execute_scan"]


async def execute_scan(kind: ScanKind[Any], reporter: ScanReporter) -> None:
    """
    Check the input, open the sandboxes, prepare them and run the jobs of ``kind``.
    """
    request = kind.request
    await asyncio.to_thread(kind.check)

    async with open_backends(request.key_names) as backends:
        prepared = await prepare_scan(
            backends, rules=request.rules, is_local=request.is_local, scan_images=kind.scan_images, hooks=kind.hooks
        )
        jobs = await asyncio.to_thread(kind.jobs, prepared)
        await run_scan_jobs(prepared.backends, jobs, reporter, unpack=request.unpack, open_browser=request.open_browser)
