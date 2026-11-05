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
from functools import partial
from typing import TYPE_CHECKING, Generic, TypeVar

from sandbox_cli.services.scanner.pipeline.jobs import ScanJob, ScanTarget, Submission, plan_targets
from sandbox_cli.services.scanner.requests import BasicScanRequest, HookFiles, ScanRequest

if TYPE_CHECKING:
    from sandbox_cli.core.config import VMImage
    from sandbox_cli.services.scanner.pipeline.backends import ScanBackend
    from sandbox_cli.services.scanner.prepare import PreparedScan

__all__ = ["FileScan", "ScanKind", "compute_wait_time"]

RequestT = TypeVar("RequestT", bound=ScanRequest)
FileRequestT = TypeVar("FileRequestT", bound=BasicScanRequest)
OptionsT = TypeVar("OptionsT")

_WAIT_TIME_FACTOR = 4
_WAIT_TIME_SHORT_BONUS = 300
_WAIT_TIME_LONG_BONUS = 120
_WAIT_TIME_SHORT_THRESHOLD = 80


def compute_wait_time(analysis_duration: int, wait_timeout: int | None = None) -> int:
    """
    Compute the sandbox wait timeout from the analysis duration.

    If ``wait_timeout`` is set it overrides the computed value.
    """
    if wait_timeout is not None:
        return wait_timeout
    bonus = _WAIT_TIME_SHORT_BONUS if analysis_duration < _WAIT_TIME_SHORT_THRESHOLD else _WAIT_TIME_LONG_BONUS
    return analysis_duration * _WAIT_TIME_FACTOR + bonus


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

    def wait_timeout(self) -> int:
        return compute_wait_time(self.request.analysis_duration)

    @abstractmethod
    def base_options(self, prepared: PreparedScan) -> OptionsT:
        """
        Sandbox options shared by all jobs.
        """

    @abstractmethod
    def submission(self, target: ScanTarget, options: OptionsT, backend: ScanBackend) -> Submission:
        """
        The task for ``target`` on ``backend``; ``options`` must not be modified.
        """

    def jobs(self, prepared: PreparedScan) -> list[ScanJob]:
        options = self.base_options(prepared)
        wait_timeout = self.wait_timeout()
        download_options = replace(self.request.download_options, video=True, logs=True)
        return [
            ScanJob(
                name=target.file.name,
                image=str(target.image),
                out_dir=target.out_dir,
                idx=target.idx,
                bind=partial(self.submission, target, options),
                wait_timeout=wait_timeout,
                download_options=download_options,
            )
            for target in plan_targets(self.request.files, prepared.images, self.request.out_dir)
        ]
