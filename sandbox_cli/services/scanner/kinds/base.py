"""
``ScanKind``: what differs between the scan commands.

``engine.execute_scan`` runs the shared steps (sandboxes, preparation, pipeline) and
asks the kind only for local checks, what to prepare and which jobs to run.
``FileScan`` adds the files x images layout of ``scan`` and ``scan-new``: a kind
built on it only says how to build the sandbox options and submit one file.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import replace
from functools import cached_property, partial
from typing import TYPE_CHECKING, Generic, TypeVar

from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxOptions

from sandbox_cli.core.config import get_settings
from sandbox_cli.services.scanner.pipeline.jobs import ScanJob, ScanTarget, Submission, plan_targets
from sandbox_cli.services.scanner.requests import BasicScanRequest, HookFiles, ScanRequest

if TYPE_CHECKING:
    from sandbox_cli.core.config import VMImage
    from sandbox_cli.services.scanner.prepare import PreparedScan

__all__ = ["FileScan", "ScanKind", "compute_wait_time", "full_scan_options"]

RequestT = TypeVar("RequestT", bound=ScanRequest)
FileRequestT = TypeVar("FileRequestT", bound=BasicScanRequest)
OptionsT = TypeVar("OptionsT")

_WAIT_TIME_FACTOR = 4
_WAIT_TIME_SHORT_BONUS = 300
_WAIT_TIME_LONG_BONUS = 120
_WAIT_TIME_SHORT_THRESHOLD = 80


def compute_wait_time(analysis_duration: int) -> int:
    """
    The default report wait timeout of a VM scan from its analysis duration.
    """
    bonus = _WAIT_TIME_SHORT_BONUS if analysis_duration < _WAIT_TIME_SHORT_THRESHOLD else _WAIT_TIME_LONG_BONUS
    return analysis_duration * _WAIT_TIME_FACTOR + bonus


def full_scan_options(sandbox: SandboxOptions | None = None) -> SandboxBaseScanTaskRequest.Options:
    """
    Options of a full scan: unpack archives with the config passwords and keep the debug files.
    """
    options = SandboxBaseScanTaskRequest.Options(
        analysis_depth=2,
        passwords_for_unpack=get_settings().passwords,
        sandbox=sandbox or SandboxOptions(),
    )
    options.sandbox.debug_options["save_debug_files"] = True
    return options


class ScanKind(ABC, Generic[RequestT]):
    """
    One scan command.
    """

    def __init__(self, request: RequestT) -> None:
        self.request = request

    def check(self) -> None:
        """
        Validate the local input before connecting to any sandbox.
        """

    @property
    def scan_images(self) -> set[VMImage | str] | None:
        """
        Images to resolve on the sandboxes; ``None`` when the scan doesn't run a VM.
        """
        return None

    @property
    def hooks(self) -> HookFiles | None:
        return None

    @abstractmethod
    def default_wait_timeout(self) -> int:
        """
        How long to wait for a task report unless the request sets it.
        """

    @cached_property
    def wait_timeout(self) -> int:
        if self.request.wait_timeout is not None:
            return self.request.wait_timeout
        return self.default_wait_timeout()

    @abstractmethod
    def jobs(self, prepared: PreparedScan) -> list[ScanJob]:
        """
        The jobs to run; called once the sandboxes are prepared.
        """


class FileScan(ScanKind[FileRequestT], Generic[FileRequestT, OptionsT]):
    """
    A scan of every file on every image; ``OptionsT`` is the type of its sandbox options.
    """

    @property
    def scan_images(self) -> set[VMImage | str] | None:
        return self.request.images

    @property
    def hooks(self) -> HookFiles | None:
        return self.request.hooks

    def default_wait_timeout(self) -> int:
        return compute_wait_time(self.request.analysis_duration)

    @abstractmethod
    def base_options(self) -> OptionsT:
        """
        Sandbox options shared by all jobs.
        """

    @abstractmethod
    def submission(self, target: ScanTarget, options: OptionsT) -> Submission:
        """
        The task for ``target``; works on a copy of ``options``.
        """

    def jobs(self, prepared: PreparedScan) -> list[ScanJob]:
        options = self.base_options()
        download_options = replace(self.request.download_options, video=True, logs=True)
        return [
            ScanJob(
                name=target.file.name,
                image=str(target.image),
                out_dir=target.out_dir,
                idx=target.idx,
                submission=partial(self.submission, target, options),
                wait_timeout=self.wait_timeout,
                download_options=download_options,
            )
            for target in plan_targets(self.request.files, prepared.images, self.request.out_dir)
        ]
