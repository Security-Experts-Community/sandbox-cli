from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = [
    "compute_wait_time",
    "get_elapsed_time",
    "shorten_name",
]

if TYPE_CHECKING:
    from rich.progress import Task

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


def get_elapsed_time(task: Task) -> str:
    """
    Format a Progress task's elapsed time as ``H:MM:SS``.
    """
    total = int(task.elapsed or 0)
    hours = total // 3600
    minutes = (total % 3600) // 60
    seconds = total % 60
    return f"[yellow]{hours}:{minutes:02d}:{seconds:02d}[/]"


def shorten_name(name: str, max_len: int = 24) -> str:
    """
    Truncate long filenames (e.g. SHA256 hashes) to a readable length, preserving the extension.
    """
    if len(name) <= max_len:
        return name
    stem, dot, suffix = name.rpartition(".")
    if dot and len(suffix) <= 4:
        keep = max_len - len(suffix) - 2
        return f"{stem[:keep]}…{suffix}"
    return f"{name[: max_len - 1]}…"
