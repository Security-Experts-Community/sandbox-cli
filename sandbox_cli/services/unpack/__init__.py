import shutil
from gzip import GzipFile
from pathlib import Path
from zipfile import ZipFile

import zstandard

from sandbox_cli.core.exceptions import UnpackError
from sandbox_cli.services.unpack.plugins.abc import BasePlugin
from sandbox_cli.services.unpack.plugins.correlation import CorrelatedRules
from sandbox_cli.services.unpack.plugins.sort_by_plugins import SortByPlugins

# Chunk size for streaming gzip decompression (64 KiB).
_GZ_CHUNK_SIZE = 64 * 1024


class Unpack:
    def __init__(self, trace: Path) -> None:
        if not trace.exists():
            raise UnpackError(f"{trace} does not exist")

        # unpack zip file
        if trace.is_file() and trace.suffix.endswith("zip"):
            self.trace = Path(trace.with_suffix(""))
            self.trace.mkdir(exist_ok=True)

            with ZipFile(trace, mode="r") as zf:
                zf.extractall(path=self.trace)
        elif trace.is_dir():
            self.trace = trace
        else:
            raise UnpackError(f"Unsupported file: {trace}")

        self.plugins: list[BasePlugin] = [CorrelatedRules(self.trace), SortByPlugins(self.trace)]
        self.logs: dict[str, Path | None] = {
            "drakvuf-trace": None,  # dynamic detect what extension is using
            "correlated": Path(self.trace / "events-correlated.log.gz"),
            "normalized": Path(self.trace / "events-normalized.log.gz"),
            "network": Path(self.trace / "tcpdump.pcap"),
        }
        self.raw = Path(self.trace / "raw")

    def _extract_log(self, file: Path) -> None:
        if file.exists() and file.suffix.endswith("zst"):
            dctx = zstandard.ZstdDecompressor()
            with open(file, mode="rb") as zst, open(file.with_suffix(""), "wb") as out:
                dctx.copy_stream(zst, out)

        if file.exists() and file.suffix.endswith("gz"):
            with GzipFile(file, mode="rb") as gzip, open(file.with_suffix(""), "wb") as out:
                # Chunked copy to avoid loading the entire decompressed
                # content into memory at once.
                while chunk := gzip.read(_GZ_CHUNK_SIZE):
                    out.write(chunk)

    def _extract_logs(self) -> None:
        for log in self.logs.values():
            if log is not None:
                self._extract_log(log)

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
            if log is not None and log.exists() and log.is_file():
                shutil.copy(log, self.raw)

        for dir, file in self.logs.items():
            if file is None or not file.exists() or file.is_dir():
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

        # Run plugins sequentially — they are CPU-bound (JSON parsing) and
        # the GIL prevents real parallelism with threads.  Each plugin
        # operates on an independent file so there is no contention.
        for plugin in self.plugins:
            plugin.run()

        # remove files
        for log in self.logs.values():
            # drakvuf trace not found
            if log is None:
                continue

            if not log.exists():
                continue

            log.unlink(missing_ok=True)

    @staticmethod
    def run_unpack(trace: Path) -> None:
        """
        Construct and run in one call — suitable for ``asyncio.to_thread``.

        Example::

            await asyncio.to_thread(Unpack.run_unpack, out_dir)
        """
        Unpack(trace).run()
