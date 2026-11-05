"""
``scan``: the full scan of a file (deprecated in favour of ``scan-new``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxOptions

from sandbox_cli.console import console
from sandbox_cli.core.config import get_settings
from sandbox_cli.core.scan import SandboxArguments, ScanType
from sandbox_cli.services.scanner.kinds.base import FileScan
from sandbox_cli.services.scanner.pipeline.jobs import Submission
from sandbox_cli.services.scanner.prepare import apply_uploads
from sandbox_cli.services.scanner.requests import BasicScanRequest

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.pipeline.backends import ScanBackend
    from sandbox_cli.services.scanner.pipeline.jobs import ScanTarget
    from sandbox_cli.services.scanner.prepare import PreparedScan

__all__ = ["BasicScan"]

_Options = SandboxBaseScanTaskRequest.Options


class BasicScan(FileScan[BasicScanRequest, _Options]):
    def base_options(self, prepared: PreparedScan) -> _Options:
        request = self.request
        options = _Options(
            analysis_depth=2,
            passwords_for_unpack=get_settings().passwords,
            sandbox=SandboxOptions(
                image_id=str(prepared.default_image),
                analysis_duration=request.analysis_duration,
                custom_command=request.custom_command,
            ),
        )
        debug = options.sandbox.debug_options
        debug["save_debug_files"] = True
        debug["extract_crashdumps"] = True
        if request.custom_command:
            console.info(f"Using custom command: {request.custom_command}")
        return options

    def submission(self, target: ScanTarget, options: _Options, backend: ScanBackend) -> Submission:
        request = self.request
        wait_timeout = self.wait_timeout()
        options = options.model_copy(deep=True)
        options.sandbox.image_id = str(target.image)
        apply_uploads(options.sandbox.debug_options, backend.uploads)

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

        return Submission(
            arguments=SandboxArguments(
                type=ScanType.SCAN, sandbox_key_name=backend.name, sandbox_options=options.sandbox
            ),
            submit=submit,
        )
