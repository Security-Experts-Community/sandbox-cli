"""
The scan pipeline shared by ``scan``, ``scan-new`` and ``re-scan``.

Every scan goes through the same stages: submit → wait for the report →
save ``report.json`` → download results → unpack (with ``--unpack``).
Commands differ only in how they submit a task: they build ``ScanJob`` objects
and pass them to ``run_scan_jobs``. Progress and messages go to a ``ScanReporter``.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
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
    from ptsandbox import Sandbox, SandboxKey
    from ptsandbox.models import SandboxBaseTaskResponse

__all__ = [
    "ScanFailure",
    "ScanJob",
    "ScanReporter",
    "ScanTarget",
    "describe_error",
    "plan_targets",
    "run_scan_jobs",
    "unique_names",
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


@dataclass(slots=True)
class ScanJob:
    """
    Everything needed to run and report one sandbox task.
    """

    name: str
    """File or trace name shown in the output."""
    out_dir: Path
    idx: str
    submit: Callable[[Sandbox], Awaitable[SandboxBaseTaskResponse]]
    wait_timeout: int
    download_options: DownloadOptions
    arguments: SandboxArguments
    image: str | None = None
    task_id: str | None = None
    """Set once the sandbox accepts the task."""
    link: str | None = None


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


async def run_scan_jobs(
    sandbox: Sandbox,
    key: SandboxKey,
    jobs: list[ScanJob],
    reporter: ScanReporter,
    *,
    unpack: bool,
    open_browser: bool,
) -> None:
    """
    Run ``jobs`` concurrently, at most ``key.max_workers`` tasks in the sandbox at a time.

    Raises ``ScanFailure`` after all jobs finished if any of them failed.
    """
    sandbox_sem = asyncio.Semaphore(key.max_workers)
    download_sem = asyncio.Semaphore(DEFAULT_CONCURRENCY)

    async def run(job: ScanJob, unpack_pool: Executor | None) -> None:
        save_scan_arguments(job.out_dir, job.arguments)
        try:
            async with sandbox_sem:
                reporter.job_started(job)
                task = await job.submit(sandbox)
                if short_report := task.get_short_report():
                    job.task_id = str(short_report.scan_id)
                job.link = format_link(task, key.host)
                reporter.job_submitted(job, job.link)
                if open_browser:
                    open_link(job.link)

                if not (result := await sandbox.wait_for_report(task, job.wait_timeout)):
                    raise ScanFailure("scan failed")

            save_report(job.out_dir, result)
            if not (long_report := result.get_long_report()):
                raise ScanFailure("full report not available")

            reporter.job_downloading(job)
            await download(
                long_report,
                sandbox,
                job.out_dir,
                job.download_options,
                tracker=reporter.download_tracker(job),
                full_report=result,
                semaphore=download_sem,
            )
            if unpack_pool is not None:
                await asyncio.get_running_loop().run_in_executor(unpack_pool, unpack_results, job.out_dir)
            reporter.job_done(job)
        except Exception as e:
            failed.append(job)
            reporter.job_failed(job, describe_error(e))
        finally:
            reporter.job_finished(job)

    pool_size = min(len(jobs), os.cpu_count() or 1)
    pool_cm = (
        ProcessPoolExecutor(max_workers=pool_size, mp_context=multiprocessing.get_context("spawn"))
        if unpack and jobs
        else nullcontext(None)
    )
    failed: list[ScanJob] = []
    with pool_cm as unpack_pool, reporter.session(total=len(jobs)):
        await asyncio.gather(*(run(job, unpack_pool) for job in jobs))

    if failed:
        raise ScanFailure(f"Failed {len(failed)} of {len(jobs)} tasks")
