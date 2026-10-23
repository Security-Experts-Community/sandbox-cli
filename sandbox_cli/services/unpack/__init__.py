"""
Convert downloaded sandbox logs into an analysis-friendly layout.

::

    <dir>/drakvuf-trace/drakvuf-trace.log
    <dir>/correlated/events-correlated.log (+ per-detection files)
    <dir>/normalized/events-normalized.log (+ per-plugin files)
    <dir>/network/tcpdump.pcap
    <dir>/raw/<original compressed files>

The originals move to ``raw/``, so a second run on an unpacked directory
rebuilds the same result.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from gzip import GzipFile
from pathlib import Path
from zipfile import ZipFile

import zstandard

from sandbox_cli.core.exceptions import UnpackError
from sandbox_cli.services.unpack.plugins.correlation import split_correlated
from sandbox_cli.services.unpack.plugins.sort_by_plugins import split_normalized

__all__ = ["has_logs", "unpack_results", "unpack_trace"]

RAW_DIR = "raw"

_SOURCES: dict[str, tuple[str, ...]] = {
    "drakvuf-trace": ("drakvuf-trace.log.gz", "drakvuf-trace.log.zst"),
    "correlated": ("events-correlated.log.gz",),
    "normalized": ("events-normalized.log.gz",),
    "network": ("tcpdump.pcap",),
}

_PLUGINS: tuple[tuple[str, Callable[[Path], None]], ...] = (
    ("correlated", split_correlated),
    ("normalized", split_normalized),
)

_CHUNK_SIZE = 1024 * 1024


def _decompress(src: Path, dst: Path) -> None:
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        if src.suffix == ".zst":
            zstandard.ZstdDecompressor().copy_stream(fin, fout, read_size=_CHUNK_SIZE, write_size=_CHUNK_SIZE)
        else:
            with GzipFile(fileobj=fin, mode="rb") as gz:
                shutil.copyfileobj(gz, fout, _CHUNK_SIZE)


def _find_source(root: Path, names: tuple[str, ...]) -> Path | None:
    for base in (root, root / RAW_DIR):
        for name in names:
            if (path := base / name).is_file():
                return path
    return None


def _resolve_root(trace: Path) -> Path:
    if not trace.exists():
        raise UnpackError(f"{trace} does not exist")
    if trace.is_dir():
        return trace
    if trace.suffix == ".zip":
        root = trace.with_suffix("")
        root.mkdir(exist_ok=True)
        with ZipFile(trace) as zf:
            zf.extractall(root)
        return root
    raise UnpackError(f"Unsupported file: {trace}")


def has_logs(directory: Path) -> bool:
    """
    Whether ``directory`` holds sandbox logs (fresh or already unpacked).
    """
    return any(_find_source(directory, names) for names in _SOURCES.values())


def unpack_trace(trace: Path) -> Path:
    """
    Unpack a result directory or ``sandbox_logs.zip``; return the directory.

    CPU-bound: call it in a worker thread or process from async code.
    """
    root = _resolve_root(trace)
    sources = {directory: _find_source(root, names) for directory, names in _SOURCES.items()}
    raw = root / RAW_DIR
    raw.mkdir(exist_ok=True)

    for directory, src in sources.items():
        out_dir = root / directory
        shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir()
        if src is None:
            continue

        if src.suffix in {".gz", ".zst"}:
            _decompress(src, out_dir / src.stem)
            if src.parent != raw:
                src.replace(raw / src.name)
        else:
            shutil.copy2(src, out_dir / src.name)
            if src.parent != raw:
                src.replace(raw / src.name)

    for directory, plugin in _PLUGINS:
        plugin(root / directory)

    return root


def unpack_results(directory: Path) -> list[Path]:
    """
    Unpack every result folder under ``directory`` (``<image>/``, ``<image>/<file>/``, ...).

    Returns the unpacked folders.
    """
    if not directory.is_dir():
        return []
    if has_logs(directory):
        return [unpack_trace(directory)]
    return [unpacked for entry in sorted(directory.iterdir()) if entry.is_dir() for unpacked in unpack_results(entry)]
