"""
Spreading jobs over sandboxes.

Every sandbox has ``max_workers`` slots and a free slot pulls the next job from a
shared queue, so a faster sandbox takes more jobs. A sandbox that can't be reached
is retired and its job goes back to the queue for the others.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sandbox_cli.services.scanner.pipeline.backends import ScanBackend
    from sandbox_cli.services.scanner.pipeline.jobs import ScanJob

__all__ = ["JobQueue", "worker_slots"]


def worker_slots(backends: Sequence[ScanBackend]) -> list[ScanBackend]:
    """
    One entry per worker slot, interleaved across sandboxes so a few jobs spread over all of them.
    """
    most = max(backend.key.max_workers for backend in backends)
    return [backend for i in range(most) for backend in backends if i < backend.key.max_workers]


class JobQueue(asyncio.Queue["ScanJob"]):
    """
    Jobs waiting for a free slot on any sandbox.

    Every ``get`` is matched by ``task_done`` once the slot is done with the job, so
    ``join`` returns when no job is waiting or running in a slot.
    """

    def __init__(self, jobs: Iterable[ScanJob], backends: Iterable[ScanBackend]) -> None:
        super().__init__()
        for job in jobs:
            self.put_nowait(job)
        self._alive = {backend.name for backend in backends}

    def is_alive(self, backend: ScanBackend) -> bool:
        return backend.name in self._alive

    def retire(self, backend: ScanBackend) -> bool:
        """
        Stop giving jobs to ``backend``; ``False`` (and nothing changes) when it is the last one.
        """
        if self._alive - {backend.name}:
            self._alive.discard(backend.name)
            return True
        return False
