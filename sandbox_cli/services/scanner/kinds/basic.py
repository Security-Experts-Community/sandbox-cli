"""
``scan``: the full scan of a file (deprecated in favour of ``scan-new``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxOptions

from sandbox_cli.console import console
from sandbox_cli.core.scan import ScanType
from sandbox_cli.services.scanner.kinds.base import FileScan, full_scan_options
from sandbox_cli.services.scanner.pipeline.jobs import Submission
from sandbox_cli.services.scanner.requests import BasicScanRequest

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.pipeline.jobs import ScanTarget

__all__ = ["BasicScan"]


class BasicScan(FileScan[BasicScanRequest, SandboxBaseScanTaskRequest.Options]):
    def base_options(self) -> SandboxBaseScanTaskRequest.Options:
        request = self.request
        options = full_scan_options(
            SandboxOptions(analysis_duration=request.analysis_duration, custom_command=request.custom_command)
        )
        options.sandbox.debug_options["extract_crashdumps"] = True
        if request.custom_command:
            console.info(f"Using custom command: {request.custom_command}")
        return options

    def submission(self, target: ScanTarget, options: SandboxBaseScanTaskRequest.Options) -> Submission:
        request = self.request
        wait_timeout = self.wait_timeout
        options = options.model_copy(deep=True)
        options.sandbox.image_id = str(target.image)

        async def submit(sandbox: Sandbox) -> SandboxBaseTaskResponse:
            return await sandbox.create_scan(
                target.file,
                file_name=request.fake_name or target.file.name,
                options=options,
                rules=None,  # rules are passed via debug_options, not by the library
                read_timeout=wait_timeout,
                upload_timeout=request.upload_timeout,
                async_result=True,
            )

        return Submission(type=ScanType.SCAN, options=options.sandbox, submit=submit)
