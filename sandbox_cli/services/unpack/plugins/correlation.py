from __future__ import annotations

from pathlib import Path

import orjson

from sandbox_cli.services.unpack.plugins.abc import GroupedWriter

__all__ = ["split_correlated"]

_MALWARE = "malware"
_PER_DETECT = {"suspicious": ".suspicious.log", "silent": ".silent.log"}


def split_correlated(base: Path) -> None:
    """
    ``malware.log`` with all malicious detections and one file per suspicious/silent detection.
    """
    source = base / "events-correlated.log"
    if not source.exists():
        return

    with open(source, "rb") as fd, GroupedWriter(base) as writer:
        for line in fd:
            event = orjson.loads(line)
            detect_type = event.get("detect.type")
            if not detect_type:
                continue
            if detect_type == _MALWARE:
                writer.add("malware.log", line)
            elif suffix := _PER_DETECT.get(detect_type):
                writer.add(f"{event['detect.name']}{suffix}", line)
