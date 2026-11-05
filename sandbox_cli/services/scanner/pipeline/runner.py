"""
The scan pipeline shared by ``scan``, ``scan-new`` and ``re-scan``.

Every job goes through the same stages: submit → wait for the report →
save ``report.json`` → download results → unpack (with ``--unpack``).
Jobs are spread over the sandboxes by ``JobQueue``; progress and messages go to a ``ScanReporter``.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor
from contextlib import AbstractContextManager, nullcontext
from typing import TYPE_CHECKING, Protocol

from sandbox_cli.core.browser import open_link
from sandbox_cli.core.errors import describe_error, is_unreachable
from sandbox_cli.core.exceptions import ScanFailure
from sandbox_cli.core.sandbox import format_link
from sandbox_cli.core.scan import SandboxArguments, save_report, save_scan_arguments
from sandbox_cli.services.downloader import DEFAULT_CONCURRENCY, DownloadTracker, download
from sandbox_cli.services.scanner.pipeline.scheduler import JobQueue, worker_slots
from sandbox_cli.services.unpack import unpack_results

if TYPE_CHECKING:
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.pipeline.backends import ScanBackend
    from sandbox_cli.services.scanner.pipeline.jobs import ScanJob

__all__ = ["ScanReporter", "run_scan_jobs"]


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
        try:
            submission = job.submission()
            backend.apply_uploads(submission.options.debug_options)
            job.key_name = backend.name
            arguments = SandboxArguments(
                type=submission.type, sandbox_key_name=backend.name, sandbox_options=submission.options
            )
            await asyncio.to_thread(save_scan_arguments, job.out_dir, arguments)
            reporter.job_started(job)
            return await submission.submit(backend.sandbox)
        except Exception as e:
            if not (is_unreachable(e) and queue.retire(backend)):
                raise
            reporter.job_requeued(job, f"{backend.name} is unreachable, using the other keys • {describe_error(e)}")
            queue.put_nowait(job)
            return None

    async def finish(job: ScanJob, backend: ScanBackend, result: SandboxBaseTaskResponse) -> None:
        try:
            await asyncio.to_thread(save_report, job.out_dir, result)
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

    async def occupy_slot(job: ScanJob, backend: ScanBackend) -> None:
        """
        Submit ``job`` and wait for its report, then hand the download over and free the slot.
        """
        try:
            if (task := await submit(job, backend)) is None:
                return
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
            return
        tg.create_task(finish(job, backend, result))

    async def worker(backend: ScanBackend) -> None:
        while True:
            job = await queue.get()
            try:
                if not queue.is_alive(backend):
                    queue.put_nowait(job)
                    return
                await occupy_slot(job, backend)
            finally:
                queue.task_done()

    pool_size = min(len(jobs), os.cpu_count() or 1)
    pool_cm = (
        ProcessPoolExecutor(max_workers=pool_size, mp_context=multiprocessing.get_context("spawn"))
        if unpack and jobs
        else nullcontext(None)
    )
    with pool_cm as unpack_pool, reporter.session(total=len(jobs)):
        async with asyncio.TaskGroup() as tg:
            workers = [tg.create_task(worker(backend)) for backend in worker_slots(backends)]
            await queue.join()
            for task in workers:
                task.cancel()

    if failed:
        raise ScanFailure(f"Failed {len(failed)} of {len(jobs)} tasks")
