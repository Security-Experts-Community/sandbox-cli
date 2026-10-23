from __future__ import annotations

from pathlib import Path

import orjson

from sandbox_cli.services.unpack.plugins.abc import GroupedWriter

__all__ = ["split_normalized"]


def split_normalized(base: Path) -> None:
    """
    One ``<plugin>.log`` per drakvuf plugin that produced normalized events.
    """
    source = base / "events-normalized.log"
    if not source.exists():
        return

    with open(source, "rb") as fd, GroupedWriter(base) as writer:
        for line in fd:
            if plugin := orjson.loads(line).get("plugin"):
                writer.add(f"{plugin}.log", line)
