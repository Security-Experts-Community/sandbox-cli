from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import Self

__all__ = ["GroupedWriter"]

_FLUSH_THRESHOLD = 32 * 1024 * 1024


class GroupedWriter:
    """
    Split lines into one file per key with bounded memory.

    Lines are buffered per key and appended to ``<base>/<key>`` whenever the
    buffer grows past a threshold.
    """

    def __init__(self, base: Path, *, threshold: int = _FLUSH_THRESHOLD) -> None:
        self._base = base
        self._threshold = threshold
        self._buffers: dict[str, list[bytes]] = {}
        self._buffered = 0
        self._created: set[str] = set()

    def add(self, name: str, line: bytes) -> None:
        self._buffers.setdefault(name, []).append(line)
        self._buffered += len(line)
        if self._buffered >= self._threshold:
            self.flush()

    def flush(self) -> None:
        for name, lines in self._buffers.items():
            mode = "ab" if name in self._created else "wb"
            with open(self._base / name, mode) as fd:
                fd.writelines(lines)
            self._created.add(name)
        self._buffers.clear()
        self._buffered = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        if exc_type is None:
            self.flush()
