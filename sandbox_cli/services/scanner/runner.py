"""
The scan pipeline shared by ``scan``, ``scan-new`` and ``re-scan``.

Every scan goes through the same stages: submit → wait for the report →
save ``report.json`` → download results → unpack (with ``--unpack``).
Commands differ only in how they submit a task: they build ``ScanJob`` objects
and pass them to ``run_scan_jobs``. Progress and messages go to a ``ScanReporter``.

Jobs are spread over one or more sandboxes (``ScanBackend``): every sandbox has
``max_workers`` slots and a free slot pulls the next job from a shared queue, so a
faster sandbox takes more jobs. A sandbox that can't be reached is dropped and
its job goes back to the queue for the others.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
from collections import Counter, deque
from collections.abc import Awaitable, Callable, Iterable, Sequence
from concurrent.futures import Executor, ProcessPoolExecutor
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import aiohttp
from ptsandbox.exceptions import SandboxException, SandboxUploadException, SandboxWaitTimeoutException

from sandbox_cli.core.browser import open_link
from sandbox_cli.core.config import VMImage
from sandbox_cli.core.exceptions import SandboxCliError
from sandbox_cli.core.sandbox import format_link
from sandbox_cli.core.scan import SandboxArguments, save_report, save_scan_arguments
from sandbox_cli.services.downloader import DEFAULT_CONCURRENCY, DownloadOptions, DownloadTracker, download
from sandbox_cli.services.unpack import unpack_results

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.backends import ScanBackend

__all__ = [
    "JobQueue",
    "ScanFailure",
    "ScanJob",
    "ScanReporter",
    "ScanTarget",
    "Submission",
    "describe_error",
    "is_unreachable",
    "plan_targets",
    "run_scan_jobs",
    "unique_names",
    "worker_slots",
]


class ScanFailure(SandboxCliError):
    """
    A single scan failed; the other scans keep running.
    """


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """
    One cell of the files x images matrix.
    """

    file: Path
    image: VMImage | str
    out_dir: Path
    idx: str


@dataclass(frozen=True, slots=True)
class Submission:
    """
    A job bound to a sandbox: what to save in ``scan_config.json`` and how to create the task.
    """

    arguments: SandboxArguments
    submit: Callable[[Sandbox], Awaitable[SandboxBaseTaskResponse]]


@dataclass(slots=True)
class ScanJob:
    """
    Everything needed to run and report one sandbox task.
    """

    name: str
    """File or trace name shown in the output."""
    out_dir: Path
    idx: str
    bind: Callable[[ScanBackend], Submission]
    """Build the task for the sandbox the job was given to."""
    wait_timeout: int
    download_options: DownloadOptions
    image: str | None = None
    key_name: str | None = None
    """Set once the job is given to a sandbox."""
    task_id: str | None = None
    """Set once the sandbox accepts the task."""
    link: str | None = None


def unique_names(
    paths: list[Path],
    name: Callable[[Path], str] = lambda p: p.stem,
    fallback: Callable[[Path], str] = lambda p: p.name,
) -> list[str]:
    """
    A distinct folder name per path: ``name(path)``, ``fallback(path)`` when that
    clashes, then ``_1``, ``_2`` suffixes (``a.exe`` + ``a.dll``, ``x86/a.dll`` + ``x64/a.dll``).
    """
    counts = Counter(name(path) for path in paths)
    used: set[str] = set()
    result: list[str] = []
    for path in paths:
        base = name(path) if counts[name(path)] == 1 else fallback(path)
        candidate, n = base, 1
        while candidate in used:
            candidate, n = f"{base}_{n}", n + 1
        used.add(candidate)
        result.append(candidate)
    return result


def plan_targets(files: list[Path], images: Iterable[VMImage | str], out_dir: Path) -> list[ScanTarget]:
    """
    Lay out the files x images matrix and create the output directories.

    A single file goes to ``out/<image>``, several files to ``out/<file>/<image>``
    (see ``unique_names``).
    """
    images = sorted(images, key=str)
    total = len(files) * len(images)
    dir_names = unique_names(files)
    targets: list[ScanTarget] = []
    for i, image in enumerate(images):
        for j, file in enumerate(files):
            target_dir = out_dir / str(image) if len(files) == 1 else out_dir / dir_names[j] / str(image)
            target_dir.mkdir(parents=True, exist_ok=True)
            targets.append(ScanTarget(file, image, target_dir, f"{i * len(files) + j + 1}/{total}"))
    return targets


def describe_error(error: BaseException) -> str:
    """
    Turn an exception raised while running a job into a short reason.
    """
    match error:
        case SandboxUploadException():
            return f"an error occurred when uploading a file to the server • {error}"
        case SandboxWaitTimeoutException():
            return "got timeout while waiting"
        case aiohttp.SocketTimeoutError():
            return "got timeout while downloading results"
        case aiohttp.ClientResponseError() | SandboxException() | SandboxCliError():
            return str(error)
        case aiohttp.ClientError():
            return f"connection error • {error}"
        case _:
            return f"unexpected error • {type(error).__name__}: {error}"


def is_unreachable(error: BaseException) -> bool:
    """
    Whether ``error`` (or what caused it) means the sandbox host can't be connected to.
    """
    if isinstance(error, aiohttp.ClientConnectorError):
        return True
    if isinstance(error, BaseExceptionGroup):
        return any(is_unreachable(e) for e in error.exceptions)
    return error.__cause__ is not None and is_unreachable(error.__cause__)


def worker_slots(backends: Sequence[ScanBackend]) -> list[ScanBackend]:
    """
    One entry per worker slot, interleaved across sandboxes so a few jobs spread over all of them.
    """
    most = max(backend.key.max_workers for backend in backends)
    return [backend for i in range(most) for backend in backends if i < backend.key.max_workers]


class JobQueue:
    """
    Jobs waiting for a free slot on any sandbox.

    A slot leaves when the queue is empty and no job is being submitted: a failed
    submission may still put its job back.
    """

    def __init__(self, jobs: Iterable[ScanJob], backends: Iterable[ScanBackend]) -> None:
        self._pending = deque(jobs)
        self._alive = {backend.name for backend in backends}
        self._submitting = 0
        self._changed = asyncio.Condition()

    def _can_leave(self, backend: ScanBackend) -> bool:
        return backend.name not in self._alive or (not self._pending and not self._submitting)

    async def take(self, backend: ScanBackend) -> ScanJob | None:
        """
        The next job for a free slot of ``backend``; ``None`` when the slot should stop.
        """
        async with self._changed:
            await self._changed.wait_for(lambda: self._can_leave(backend) or bool(self._pending))
            if backend.name not in self._alive or not self._pending:
                return None
            self._submitting += 1
            return self._pending.popleft()

    async def submitted(self, requeue: ScanJob | None = None) -> None:
        """
        A submission taken with ``take`` ended; ``requeue`` goes back to the front of the queue.
        """
        async with self._changed:
            self._submitting -= 1
            if requeue is not None:
                self._pending.appendleft(requeue)
            self._changed.notify_all()

    def retire(self, backend: ScanBackend) -> bool:
        """
        Stop giving jobs to ``backend``; ``False`` (and nothing changes) when it is the last one.
        """
        if self._alive - {backend.name}:
            self._alive.discard(backend.name)
            return True
        return False


class ScanReporter(Protocol):
    """
    UI hooks for the scan pipeline (implemented by the CLI).
    """

    def session(self, total: int) -> AbstractContextManager[None]:
        """
        Wrap the whole run; ``total`` is the number of jobs.
        """
        ...

    def job_started(self, job: ScanJob) -> None: ...

    def job_requeued(self, job: ScanJob, reason: str) -> None:
        """
        The job didn't reach its sandbox and goes back to the queue; ``job_started`` follows again.
        """
        ...

    def job_submitted(self, job: ScanJob, link: str) -> None: ...

    def job_downloading(self, job: ScanJob) -> None: ...

    def job_done(self, job: ScanJob) -> None: ...

    def job_failed(self, job: ScanJob, reason: str) -> None: ...

    def job_finished(self, job: ScanJob) -> None:
        """
        Called last for every job, whatever the outcome.
        """
        ...

    def download_tracker(self, job: ScanJob) -> DownloadTracker | None: ...


async def run_scan_jobs(
    backends: Sequence[ScanBackend],
    jobs: list[ScanJob],
    reporter: ScanReporter,
    *,
    unpack: bool,
    open_browser: bool,
) -> None:
    """
    Run ``jobs`` on ``backends``, at most ``key.max_workers`` tasks in each sandbox at a time.

    Raises ``ScanFailure`` after all jobs finished if any of them failed.
    """
    if not backends:
        raise ValueError("no sandboxes to scan on")

    queue = JobQueue(jobs, backends)
    download_sem = asyncio.Semaphore(DEFAULT_CONCURRENCY)
    failed: list[ScanJob] = []

    def fail(job: ScanJob, error: BaseException) -> None:
        failed.append(job)
        reporter.job_failed(job, describe_error(error))
        reporter.job_finished(job)

    async def submit(job: ScanJob, backend: ScanBackend) -> SandboxBaseTaskResponse | None:
        """
        Create the task; ``None`` when the job went back to the queue.
        """
        requeue = False
        try:
            submission = job.bind(backend)
            job.key_name = backend.name
            save_scan_arguments(job.out_dir, submission.arguments)
            reporter.job_started(job)
            return await submission.submit(backend.sandbox)
        except Exception as e:
            if not (is_unreachable(e) and queue.retire(backend)):
                raise
            requeue = True
            reporter.job_requeued(job, f"{backend.name} is unreachable, using the other keys • {describe_error(e)}")
            return None
        finally:
            await queue.submitted(job if requeue else None)

    async def finish(
        job: ScanJob, backend: ScanBackend, result: SandboxBaseTaskResponse, unpack_pool: Executor | None
    ) -> None:
        try:
            save_report(job.out_dir, result)
            if not (long_report := result.get_long_report()):
                raise ScanFailure("full report not available")

            reporter.job_downloading(job)
            await download(
                long_report,
                backend.sandbox,
                job.out_dir,
                job.download_options,
                tracker=reporter.download_tracker(job),
                full_report=result,
                semaphore=download_sem,
            )
            if unpack_pool is not None:
                await asyncio.get_running_loop().run_in_executor(unpack_pool, unpack_results, job.out_dir)
        except Exception as e:
            fail(job, e)
            return
        reporter.job_done(job)
        reporter.job_finished(job)

    async def worker(backend: ScanBackend, tg: asyncio.TaskGroup, unpack_pool: Executor | None) -> None:
        while (job := await queue.take(backend)) is not None:
            try:
                if (task := await submit(job, backend)) is None:
                    continue
                if short_report := task.get_short_report():
                    job.task_id = str(short_report.scan_id)
                job.link = format_link(task, backend.key.host)
                reporter.job_submitted(job, job.link)
                if open_browser:
                    open_link(job.link)

                if not (result := await backend.sandbox.wait_for_report(task, job.wait_timeout)):
                    raise ScanFailure("scan failed")
            except Exception as e:
                fail(job, e)
                continue
            tg.create_task(finish(job, backend, result, unpack_pool))

    pool_size = min(len(jobs), os.cpu_count() or 1)
    pool_cm = (
        ProcessPoolExecutor(max_workers=pool_size, mp_context=multiprocessing.get_context("spawn"))
        if unpack and jobs
        else nullcontext(None)
    )
    with pool_cm as unpack_pool, reporter.session(total=len(jobs)):
        async with asyncio.TaskGroup() as tg:
            for backend in worker_slots(backends):
                tg.create_task(worker(backend, tg, unpack_pool))

    if failed:
        raise ScanFailure(f"Failed {len(failed)} of {len(jobs)} tasks")
