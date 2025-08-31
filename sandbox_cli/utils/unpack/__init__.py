import shutil
from gzip import GzipFile
from pathlib import Path
from zipfile import ZipFile

import zstandard

from sandbox_cli.console import console
from sandbox_cli.utils.unpack.plugins.abc import BasePlugin
from sandbox_cli.utils.unpack.plugins.correlation import CorrelatedRules
from sandbox_cli.utils.unpack.plugins.sort_by_plugins import SortByPlugins


class Unpack:
    def __init__(self, trace: Path) -> None:
        if not trace.exists():
            console.error(f"{trace} not exist")
            return

        # unpack zip file
        if trace.is_file() and trace.suffix.endswith("zip"):
            self.trace = Path(trace.with_suffix(""))
            self.trace.mkdir(exist_ok=True)

            with ZipFile(trace, mode="r") as zip:
                zip.extractall(path=self.trace)
        elif trace.is_dir():
            self.trace = trace
        else:
            console.error(f"Unsupported file: {trace}")
            return

        self.plugins: list[BasePlugin] = [CorrelatedRules(self.trace), SortByPlugins(self.trace)]
        self.logs = {
            "drakvuf-trace": Path(""),  # dynamic detect what extension is using
            "correlated": Path(self.trace / "events-correlated.log.gz"),
            "normalized": Path(self.trace / "events-normalized.log.gz"),
            "network": Path(self.trace / "tcpdump.pcap"),
        }
        self.raw = Path(self.trace / "raw")

    def _extract_logs(self) -> None:
        def _extract(file: Path) -> None:
            if file.exists() and file.suffix.endswith("zst"):
                dctx = zstandard.ZstdDecompressor()
                with open(file, mode="rb") as zst, open(file.with_suffix(""), "wb") as out:
                    dctx.copy_stream(zst, out)

            if file.exists() and file.suffix.endswith("gz"):
                with GzipFile(file, mode="rb") as gzip, open(file.with_suffix(""), "wb") as out:
                    out.write(gzip.read())

        for log in self.logs.values():
            _extract(log)

    def _create_dirs(self) -> None:
        def _create(dir: Path) -> None:
            if dir.exists() and dir.is_dir():
                shutil.rmtree(dir)
            dir.mkdir(exist_ok=True)

        for dir in self.logs:
            _create(Path(self.trace / dir))

    def _move_files(self) -> None:
        self.raw.mkdir(exist_ok=True)
        for log in self.logs.values():
            if log.exists() and log.is_file():
                shutil.copy(log, self.raw)

        for dir, file in self.logs.items():
            if not file.exists() or file.is_dir():
                continue

            if file.suffix.endswith("gz") or file.suffix.endswith("zst"):
                shutil.move(file.with_suffix(""), self.trace / dir)
            else:
                shutil.move(file, self.trace / dir)

    def run(self) -> None:
        if Path(self.trace / "drakvuf-trace.log.gz").exists():
            self.logs["drakvuf-trace"] = Path(self.trace / "drakvuf-trace.log.gz")
        elif Path(self.trace / "drakvuf-trace.log.zst").exists():
            self.logs["drakvuf-trace"] = Path(self.trace / "drakvuf-trace.log.zst")

        self._extract_logs()
        self._create_dirs()
        self._move_files()

        # run plugins
        for plugin in self.plugins:
            plugin.run()

        # remove files
        for log in self.logs.values():
            # drakvuf trace not found
            if log == Path(""):
                continue

            if not log.exists():
                continue

            log.unlink(missing_ok=True)
