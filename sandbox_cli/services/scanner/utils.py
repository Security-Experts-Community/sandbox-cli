from __future__ import annotations

__all__ = ["compute_wait_time"]

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
