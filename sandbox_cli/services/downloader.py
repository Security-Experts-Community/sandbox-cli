from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Coroutine
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import aiofiles
import aiohttp
import zstandard
from ptsandbox.models import (
    ArtifactType,
    LogType,
)
from rich.markup import escape

from sandbox_cli.console import console
from sandbox_cli.core.scan import save_report

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse
    from rich.progress import Progress, TaskID

__all__ = ["DEFAULT_CONCURRENCY", "DEFAULT_READ_TIMEOUT", "DownloadOptions", "download"]

# Default limits — can be overridden per-call via CLI flags.
DEFAULT_CONCURRENCY = 16
DEFAULT_READ_TIMEOUT = 300


@dataclass(frozen=True, slots=True)
class DownloadOptions:
    """
    What artifact categories to fetch from a completed scan.

    Grouped into a single value object so callers don't have to thread
    a dozen booleans through every function signature.
    """

    all: bool = False
    artifacts: bool = False
    crashdumps: bool = False
    debug: bool = False
    decompress: bool = False
    files: bool = False
    logs: bool = False
    procdumps: bool = False
    video: bool = False
    amsi: bool = False
    dex: bool = False


# At first glance, it's counter-intuitive, but ArtifactType can contain not only predefined fields in it, but also newly added.
# This usually happens when a new feature is released in the sandbox.
_KNOWN_ARTIFACT_TYPES = {
    ArtifactType.AMSI,
    ArtifactType.ARCHIVE,
    ArtifactType.COMPRESSED,
    ArtifactType.DEX_DUMP,
    ArtifactType.EMAIL,
    ArtifactType.FILE,
    ArtifactType.PROCESS_DUMP,
    ArtifactType.URL,
}

# Log types downloaded by default (with --logs or --all).
_DEFAULT_LOG_TYPES = {
    LogType.EVENT_CORRELATED,
    LogType.EVENT_NORMALIZED,
    LogType.EVENT_RAW,
    LogType.NETWORK,
}
_CRASHDUMP_FILES = {"crashdump.bin", "crashdump.metadata"}
_DEBUG_LOG_TYPES = {LogType.DEBUG, LogType.GRAPH}


def _unique_path(path: Path, claimed: set[Path]) -> Path:
    """
    Return a non-existing path next to ``path``, avoiding both on-disk
    files and paths already claimed by concurrent downloads in ``claimed``.
    """
    if not path.exists() and path not in claimed:
        return path
    stem, suffix = path.stem, path.suffix
    for n in range(1, 10_000):
        candidate = path.with_name(f"{stem}_{n}{suffix}")
        if not candidate.exists() and candidate not in claimed:
            return candidate
    # Extremely unlikely: fall back to a random suffix.
    return path.with_name(f"{stem}_{uuid4().hex[:8]}{suffix}")


async def _stream_to_file(
    sandbox: Sandbox,
    file_uri: str,
    path: Path,
    decompress: bool,
    read_timeout: int,
) -> None:
    """
    Stream ``file_uri`` from the sandbox directly to ``path``.

    Uses ``download_artifact_stream`` so the payload is never fully held in
    memory. When ``decompress`` is set, zstd chunks are decompressed on the
    fly through ``decompressobj`` and written asynchronously.
    """
    # Guard against ``path`` being a directory — can happen when the
    # artifact name was empty or resolved to an existing directory.
    if path.is_dir():
        console.warning(f"Skipping directory path: {path}")
        return

    path.parent.mkdir(exist_ok=True, parents=True)

    stream: AsyncIterator[bytes] = sandbox.api.download_artifact_stream(
        file_uri=file_uri,
        read_timeout=read_timeout,
    )

    if not decompress:
        async with aiofiles.open(path, "wb") as fd:
            async for chunk in stream:
                await fd.write(chunk)
        return

    # Streaming zstd decompression: feed raw chunks into the decompressor
    # and write decoded bytes to disk asynchronously via aiofiles.
    dctx = zstandard.ZstdDecompressor()
    dobj = dctx.decompressobj()
    try:
        async with aiofiles.open(path, "wb") as fd:
            async for chunk in stream:
                decoded = dobj.decompress(chunk)
                if decoded:
                    await fd.write(decoded)
            # Flush any remaining buffered data.
            tail = dobj.flush()
            if tail:
                await fd.write(tail)
    except zstandard.ZstdError as e:
        console.warning(f"Can't decompress [yellow]{path.name}[/]. {e}")


async def _save_artifact(
    scan_id: UUID,
    sandbox: Sandbox,
    out_dir: Path,
    name: str,
    file_uri: str,
    semaphore: asyncio.Semaphore,
    claimed: set[Path],
    read_timeout: int,
    overwrite: bool = False,
    decompress: bool = False,
    progress: Progress | None = None,
    idx: str | None = None,
    image: str | None = None,
    link: str | None = None,
) -> None:
    if not file_uri:
        return

    # sanitize name — an empty name would make ``out_dir / ""`` resolve to
    # ``out_dir`` itself (a directory), causing IsADirectoryError on open.
    name = name.strip().replace(" ", "_")
    if not name:
        return

    path = out_dir / name
    if not overwrite:
        path = _unique_path(path, claimed)
    claimed.add(path)

    task_id: TaskID | None = None

    async with semaphore:
        if progress:
            if idx and image and link:
                task_id = progress.add_task(
                    description=f"Download [green]{escape(path.name)}[/]",
                    idx=idx,
                    image=image,
                    url=link,
                )
            else:
                task_id = progress.add_task(rf"\[[green1]{scan_id}[/]] {escape(path.name)}")

        def _drop_task() -> None:
            if task_id is not None and progress is not None:
                progress.stop_task(task_id)
                progress.update(task_id=task_id, visible=False)

        try:
            await _stream_to_file(sandbox, file_uri, path, decompress, read_timeout)
        except aiohttp.ClientResponseError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                console.warning(f"File {path.name} not found in storage: {file_uri=} {scan_id=}")
                _drop_task()
                return
            _drop_task()
            raise
        except aiohttp.SocketTimeoutError:
            _drop_task()
            raise

        _drop_task()


def _resolve_output_dir(out_dir: Path, sandbox_result: Any) -> Path:
    """
    Determine the output directory for a sandbox result.

    If the result has an image_id that differs from the last path component
    of ``out_dir``, a subdirectory is created for that image.
    """
    details = sandbox_result.details
    if details and details.sandbox and details.sandbox.image:
        image_id = details.sandbox.image.image_id
        if image_id and out_dir.parts[-1] != image_id:
            return Path(out_dir / image_id)
    return out_dir


def _save_report_json(
    output: Path,
    full_report: SandboxBaseTaskResponse | None,
    saved_dirs: set[Path],
) -> None:
    """
    Save ``report.json`` in ``output`` if not already saved there.
    """
    if full_report is not None and output not in saved_dirs:
        output.mkdir(parents=True, exist_ok=True)
        save_report(output, full_report)
        saved_dirs.add(output)


def _collect_log_downloads(
    log_entries: list[Any],
    output: Path,
    options: DownloadOptions,
) -> list[tuple[Path, str, str, bool, bool]]:
    """
    Build the list of (out_dir, name, file_uri, decompress, overwrite) for log artifacts.
    """
    result: list[tuple[Path, str, str, bool, bool]] = []

    for log in log_entries:
        if (options.all or options.logs) and log.type in _DEFAULT_LOG_TYPES:
            result.append((output, log.file_name, log.file_uri, False, True))

        if (options.all or options.video) and log.type == LogType.SCREENSHOT:
            result.append((output, log.file_name, log.file_uri, False, True))

        if (options.all or options.crashdumps) and log.file_name in _CRASHDUMP_FILES:
            result.append((output / "crashdumps", log.file_name, log.file_uri, False, False))

        if (options.all or options.debug) and log.type in _DEBUG_LOG_TYPES:
            result.append((output / "debug", log.file_name, log.file_uri, False, False))

    return result


def _collect_artifact_downloads(
    sandbox_artifacts: list[Any],
    output: Path,
    options: DownloadOptions,
) -> list[tuple[Path, str, str, bool, bool]]:
    """
    Build the list of (out_dir, name, file_uri, decompress, overwrite) for sandbox artifacts.
    """
    result: list[tuple[Path, str, str, bool, bool]] = []

    for artifact in sandbox_artifacts:
        if not artifact.file_info:
            continue

        fi = artifact.file_info
        atype = artifact.type

        if atype == ArtifactType.FILE and (options.files or options.artifacts or options.all):
            result.append((output / "artifacts", fi.file_path.removeprefix("/"), fi.file_uri, False, False))

        if atype == ArtifactType.PROCESS_DUMP and (options.procdumps or options.artifacts or options.all):
            result.append(
                (
                    output / "process_dump",
                    fi.details.process_dump.process_name.removeprefix("/"),
                    fi.file_uri,
                    options.decompress,
                    False,
                )
            )

        if atype == ArtifactType.AMSI and (options.amsi or options.all):
            result.append((output / "amsi", f"{fi.sha256}.bin", fi.file_uri, False, False))

        if atype == ArtifactType.DEX_DUMP and (options.dex or options.all):
            result.append((output / "dex", f"{fi.sha256}.bin", fi.file_uri, False, False))

        if options.all and atype not in _KNOWN_ARTIFACT_TYPES:
            result.append((output / "other", fi.sha256, fi.file_uri, False, False))

    return result


async def download(
    report: SandboxBaseTaskResponse.LongReport,
    sandbox: Sandbox,
    out_dir: Path,
    options: DownloadOptions,
    *,
    progress: Progress | None = None,
    idx: str | None = None,
    image: str | None = None,
    link: str | None = None,
    full_report: SandboxBaseTaskResponse | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
) -> None:
    tasks: list[Coroutine[Any, Any, None]] = []
    saved_report_dirs: set[Path] = set()
    claimed: set[Path] = set()
    semaphore = asyncio.Semaphore(value=concurrency)

    def add_task(out_dir: Path, name: str, file_uri: str, decompress: bool = False, overwrite: bool = False) -> None:
        tasks.append(
            _save_artifact(
                scan_id=report.scan_id,
                sandbox=sandbox,
                out_dir=out_dir,
                name=name,
                file_uri=file_uri,
                semaphore=semaphore,
                claimed=claimed,
                read_timeout=read_timeout,
                progress=progress,
                idx=idx,
                image=image,
                link=link,
                decompress=decompress,
                overwrite=overwrite,
            )
        )

    for artifact in report.artifacts:
        for sandbox_result in artifact.get_sandbox_results():
            if sandbox_result is None or sandbox_result.details is None or sandbox_result.details.sandbox is None:
                continue

            output = _resolve_output_dir(out_dir, sandbox_result)
            _save_report_json(output, full_report, saved_report_dirs)

            sb = sandbox_result.details.sandbox

            # Logs
            for out, name, uri, decomp, ow in _collect_log_downloads(sb.logs, output, options):
                add_task(out, name, uri, decompress=decomp, overwrite=ow)

            # Artifacts
            if options.artifacts or options.files or options.procdumps or options.all:
                if not sb.artifacts:
                    continue
                for out, name, uri, decomp, ow in _collect_artifact_downloads(sb.artifacts, output, options):
                    add_task(out, name, uri, decompress=decomp, overwrite=ow)

    if not tasks:
        console.info(f"Nothing to download from {report.scan_id}")

    await asyncio.gather(*tasks)
