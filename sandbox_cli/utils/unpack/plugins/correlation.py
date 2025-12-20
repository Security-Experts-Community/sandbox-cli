from collections import defaultdict
from pathlib import Path

import orjson

from sandbox_cli.models.detections import DetectionType
from sandbox_cli.utils.unpack.plugins.abc import BasePlugin


class CorrelatedRules(BasePlugin):
    def run(self) -> None:
        base_path = self.trace / "correlated"
        file = Path(base_path / "events-correlated.log")
        if not file.exists():
            return

        with open(file, errors="ignore", encoding="utf-8") as fd:
            raw_trace = fd.readlines()

        suspicious: defaultdict[str, list[str]] = defaultdict(list)
        silent: defaultdict[str, list[str]] = defaultdict(list)
        malware: list[str] = []

        for line in raw_trace:
            data: dict[str, str] = orjson.loads(line)
            if data.get("detect.type"):
                match data["detect.type"]:
                    case DetectionType.malware:
                        malware.append(line)
                    case DetectionType.suspicious:
                        suspicious[data["detect.name"]].append(line)
                    case DetectionType.silent:
                        silent[data["detect.name"]].append(line)
                    case _:
                        pass

        if len(malware) > 0:
            with open(base_path / "malware.log", "w", encoding="utf-8") as fd:
                for line in malware:
                    fd.write(line)

        for key, lines in silent.items():
            with open(base_path / f"{key}.silent.log", "w", encoding="utf-8") as fd:
                for line in lines:
                    fd.write(line)

        for key, lines in suspicious.items():
            with open(base_path / f"{key}.suspicious.log", "w", encoding="utf-8") as fd:
                for line in lines:
                    fd.write(line)
