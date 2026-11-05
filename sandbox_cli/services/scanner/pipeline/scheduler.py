"""
Spreading jobs over sandboxes.

Every sandbox has ``max_workers`` slots and a free slot pulls the next job from a
shared queue, so a faster sandbox takes more jobs. A sandbox that can't be reached
is retired and its job goes back to the queue for the others.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

import aiohttp

if TYPE_CHECKING:
    from sandbox_cli.services.scanner.pipeline.backends import ScanBackend
    from sandbox_cli.services.scanner.pipeline.jobs import ScanJob

__all__ = ["JobQueue", "is_unreachable", "worker_slots"]


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
