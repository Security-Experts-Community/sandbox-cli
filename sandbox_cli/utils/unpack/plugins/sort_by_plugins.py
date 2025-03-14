from collections import defaultdict
from pathlib import Path

import orjson

from sandbox_cli.console import console
from sandbox_cli.utils.unpack.plugins.abc import BasePlugin


class SortByPlugins(BasePlugin):
    def run(self) -> None:
        base_path = self.trace / "normalized"
        file = Path(base_path / "events-normalized.log")
        if not file.exists():
            console.warning(f"{file} not exist")
            return

        with open(file, errors="ignore") as fd:
            raw_trace = fd.readlines()

        plugins: defaultdict[str, list[str]] = defaultdict(list)
        for line in raw_trace:
            data: dict[str, str] = orjson.loads(line)
            if data.get("plugin"):
                plugins[data["plugin"]].append(line)

        for plugin, lines in plugins.items():
            with open(f"{file}.{plugin}", "w", encoding="utf-8") as fd:
                for line in lines:
                    fd.write(line)
