import orjson
from ptsandbox.utils import DetectionType

from sandbox_cli.services.unpack.plugins.abc import BasePlugin


class CorrelatedRules(BasePlugin):
    def run(self) -> None:
        base_path = self.trace / "correlated"
        file = base_path / "events-correlated.log"

        malware: list[bytes] = []
        suspicious: dict[str, list[bytes]] = {}
        silent: dict[str, list[bytes]] = {}

        if file.exists():
            with open(file, "rb") as fd:
                for line in fd:
                    data = orjson.loads(line)
                    if not data.get("detect.type"):
                        continue
                    match data["detect.type"]:
                        case DetectionType.MALWARE:
                            malware.append(line)
                        case DetectionType.SUSPICIOUS:
                            suspicious.setdefault(data["detect.name"], []).append(line)
                        case DetectionType.SILENT:
                            silent.setdefault(data["detect.name"], []).append(line)

        if malware:
            with open(base_path / "malware.log", "wb") as fd:
                fd.writelines(malware)

        self.write_groups(base_path, silent, suffix=".silent.log")
        self.write_groups(base_path, suspicious, suffix=".suspicious.log")
