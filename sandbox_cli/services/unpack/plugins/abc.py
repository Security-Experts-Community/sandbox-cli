from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any

import orjson


class BasePlugin(ABC):
    """
    Base class for all plugins

    It is necessary to designate a single entry point
    """

    def __init__(self, trace: Path) -> None:
        self.trace = trace

    @abstractmethod
    def run(self) -> None:
        """
        Invoke plugin
        """
        ...

    @staticmethod
    def group_lines(
        file: Path,
        key_fn: Callable[[dict[str, Any]], str | None],
    ) -> dict[str, list[bytes]]:
        """
        Read a JSON-lines file and group raw lines by ``key_fn``.

        Lines where ``key_fn`` returns ``None`` are skipped.
        """

        groups: dict[str, list[bytes]] = {}
        if not file.exists():
            return groups

        with open(file, "rb") as fd:
            for line in fd:
                key = key_fn(orjson.loads(line))
                if key is not None:
                    groups.setdefault(key, []).append(line)
        return groups

    @staticmethod
    def write_groups(base_path: Path, groups: dict[str, list[bytes]], suffix: str = ".log") -> None:
        """
        Batch-write each group to ``base_path / f"{key}{suffix}"``.
        """

        for key, lines in groups.items():
            with open(base_path / f"{key}{suffix}", "wb") as fd:
                fd.writelines(lines)
