"""
Rich implementations of the progress hooks used by the services.
"""

from __future__ import annotations

import time
from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from typing import TYPE_CHECKING, Any

from rich.markup import escape

from sandbox_cli.console import console
from sandbox_cli.core.progress import SandboxProgress, make_scan_progress

if TYPE_CHECKING:
    from uuid import UUID

    from rich.progress import TaskID

    from sandbox_cli.services.downloader import DownloadTracker
    from sandbox_cli.services.scanner.runner import ScanJob, ScanReporter

__all__ = [
    "JsonScanReporter",
    "ProgressDownloadTracker",
    "ProgressScanReporter",
    "format_elapsed",
    "make_scan_reporter",
    "shorten_name",
]

_SEP = " • "


def format_elapsed(seconds: float) -> str:
    """
    Format a duration as ``H:MM:SS``.
    """
    total = int(seconds)
    return f"[yellow]{total // 3600}:{total % 3600 // 60:02d}:{total % 60:02d}[/]"


def shorten_name(name: str, max_len: int = 24) -> str:
    """
    Truncate long filenames (e.g. SHA256 hashes) to a readable length, preserving the extension.
    """
    if len(name) <= max_len:
        return name
    stem, dot, suffix = name.rpartition(".")
    if dot and len(suffix) <= 4:
        keep = max_len - len(suffix) - 2
        return f"{stem[:keep]}….{suffix}"
    return f"{name[: max_len - 1]}…"


class ProgressDownloadTracker:
    """
    One transient progress row per downloaded file.
    """

    def __init__(self, progress: SandboxProgress, **fields: Any) -> None:
        self._progress = progress
        self._fields = fields

    def file_started(self, scan_id: UUID, name: str) -> TaskID:
        if self._fields:
            return self._progress.add_task(f"Download [green]{escape(name)}[/]", **self._fields)
        return self._progress.add_task(rf"\[[green1]{scan_id}[/]] {escape(name)}")

    def file_finished(self, token: object) -> None:
        self._progress.remove_task(token)  # type: ignore[arg-type]


class _JobRow:
    __slots__ = ("link", "started", "task_id")

    def __init__(self) -> None:
        self.task_id: TaskID | None = None
        self.link: str | None = None
        self.started = time.monotonic()


class ProgressScanReporter:
    """
    Live progress table for scan jobs plus one ``[DONE]``/``[ERROR]`` line per job.
    """

    def __init__(self, *, with_image: bool) -> None:
        self._with_image = with_image
        self._progress = make_scan_progress(with_image=with_image)
        self._rows: dict[int, _JobRow] = {}

    @contextmanager
    def session(self, total: int) -> Generator[None, None, None]:
        with console.terminal_progress.activity(total=total), self._progress:
            yield

    def _row(self, job: ScanJob) -> _JobRow:
        return self._rows.setdefault(id(job), _JobRow())

    def _fields(self, job: ScanJob) -> dict[str, Any]:
        row = self._row(job)
        fields: dict[str, Any] = {
            "idx": f"[turquoise2 bold]{job.idx}[/]",
            "url": f"[medium_purple]{row.link}[/]" if row.link else "...",
        }
        if self._with_image:
            fields["image"] = escape(f"[{job.image}]")
        return fields

    def _summary(self, job: ScanJob, *parts: str) -> str:
        row = self._row(job)
        items: list[str] = []
        if job.image is not None:
            items.append(escape(f"[{job.image}]"))
        items.append(f"[yellow]{escape(shorten_name(job.name))}[/]")
        if row.link:
            items.append(f"[medium_purple]{row.link}[/]")
        items.extend(parts)
        items.append(format_elapsed(time.monotonic() - row.started))
        return _SEP.join(items)

    def job_started(self, job: ScanJob) -> None:
        row = self._row(job)
        row.started = time.monotonic()
        row.task_id = self._progress.add_task("Creating task", **self._fields(job))

    def job_submitted(self, job: ScanJob, link: str) -> None:
        row = self._row(job)
        row.link = link
        if row.task_id is not None:
            self._progress.update(
                row.task_id,
                description=f"Waiting [yellow]{escape(shorten_name(job.name))}[/]",
                **self._fields(job),
            )

    def job_downloading(self, job: ScanJob) -> None:
        row = self._row(job)
        if row.task_id is not None:
            self._progress.update(row.task_id, description="Downloading results...")

    def job_done(self, job: ScanJob) -> None:
        console.done(self._summary(job))

    def job_failed(self, job: ScanJob, reason: str) -> None:
        console.error(self._summary(job, escape(reason)))

    def job_finished(self, job: ScanJob) -> None:
        row = self._rows.pop(id(job), None)
        if row is not None and row.task_id is not None:
            self._progress.remove_task(row.task_id)
        console.terminal_progress.advance()

    def download_tracker(self, job: ScanJob) -> DownloadTracker:
        return ProgressDownloadTracker(self._progress, **self._fields(job))


class JsonScanReporter:
    """
    Wrap another reporter and print one JSON line per finished job.

    Fields: ``status`` (``done``/``failed``), ``name``, ``image``, ``task_id``,
    ``link``, ``out_dir``, ``elapsed`` (seconds) and ``reason`` for failures.
    """

    def __init__(self, inner: ScanReporter) -> None:
        self._inner = inner
        self._started: dict[int, float] = {}

    def session(self, total: int) -> AbstractContextManager[None]:
        return self._inner.session(total)

    def job_started(self, job: ScanJob) -> None:
        self._started[id(job)] = time.monotonic()
        self._inner.job_started(job)

    def job_submitted(self, job: ScanJob, link: str) -> None:
        self._inner.job_submitted(job, link)

    def job_downloading(self, job: ScanJob) -> None:
        self._inner.job_downloading(job)

    def job_done(self, job: ScanJob) -> None:
        self._inner.job_done(job)
        self._emit(job, "done")

    def job_failed(self, job: ScanJob, reason: str) -> None:
        self._inner.job_failed(job, reason)
        self._emit(job, "failed", reason=reason)

    def job_finished(self, job: ScanJob) -> None:
        self._started.pop(id(job), None)
        self._inner.job_finished(job)

    def download_tracker(self, job: ScanJob) -> DownloadTracker | None:
        return self._inner.download_tracker(job)

    def _emit(self, job: ScanJob, status: str, **extra: str) -> None:
        started = self._started.get(id(job))
        console.emit_json(
            {
                "status": status,
                "name": job.name,
                "image": job.image,
                "task_id": job.task_id,
                "link": job.link,
                "out_dir": str(job.out_dir),
                "elapsed": round(time.monotonic() - started, 1) if started is not None else None,
                **extra,
            }
        )


def make_scan_reporter(*, with_image: bool, json_output: bool) -> ScanReporter:
    """
    The progress reporter, wrapped in ``JsonScanReporter`` with ``--json``.

    ``main`` switches messages to stderr for ``--json`` before any command runs.
    """
    reporter: ScanReporter = ProgressScanReporter(with_image=with_image)
    return JsonScanReporter(reporter) if json_output else reporter
