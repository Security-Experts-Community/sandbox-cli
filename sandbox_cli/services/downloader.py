from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import AsyncIterator, Coroutine, Iterable, Iterator
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol
from uuid import UUID, uuid4

import aiofiles
import aiohttp
import zstandard
from ptsandbox.models import (
    ArtifactType,
    EngineSubsystem,
    LogType,
)

from sandbox_cli.console import console
from sandbox_cli.core.scan import save_report

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

__all__ = [
    "DEFAULT_CONCURRENCY",
    "DEFAULT_READ_TIMEOUT",
    "DownloadItem",
    "DownloadOptions",
    "DownloadTracker",
    "download",
]

# Default limits — can be overridden per-call via CLI flags.
DEFAULT_CONCURRENCY = 16
DEFAULT_READ_TIMEOUT = 300


@dataclass(frozen=True, slots=True)
class DownloadOptions:
    """
    Artifact categories to fetch from a completed scan.
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
    sample: bool = False


class DownloadItem(NamedTuple):
    """
    A single file to fetch from the sandbox storage.
    """

    out_dir: Path
    name: str
    file_uri: str
    decompress: bool = False
    overwrite: bool = False


class DownloadTracker(Protocol):
    """
    Receives per-file download events (e.g. to show a progress row per file).
    """

    def file_started(self, scan_id: UUID, name: str) -> object:
        """
        Called when a file starts downloading; the return value is passed to ``file_finished``.
        """
        ...

    def file_finished(self, token: object) -> None: ...


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
    Stream ``file_uri`` from the sandbox to ``path`` without buffering the payload.

    With ``decompress``, zstd chunks are decompressed as they arrive.
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
    item: DownloadItem,
    *,
    semaphore: asyncio.Semaphore,
    claimed: set[Path],
    read_timeout: int,
    tracker: DownloadTracker | None,
) -> None:
    if not item.file_uri:
        return

    # sanitize name — an empty name would make ``out_dir / ""`` resolve to
    # ``out_dir`` itself (a directory), causing IsADirectoryError on open.
    name = item.name.strip().replace(" ", "_")
    if not name:
        return

    path = item.out_dir / name
    if not item.overwrite:
        path = _unique_path(path, claimed)
    claimed.add(path)

    async with semaphore:
        token = tracker.file_started(scan_id, path.name) if tracker else None
        try:
            await _stream_to_file(sandbox, item.file_uri, path, item.decompress, read_timeout)
        except aiohttp.ClientResponseError as e:
            if e.status != HTTPStatus.NOT_FOUND:
                raise
            console.warning(f"File {path.name} not found in storage: file_uri={item.file_uri!r} {scan_id=}")
        finally:
            if tracker:
                tracker.file_finished(token)


def _resolve_output_dir(out_dir: Path, sandbox_result: Any) -> Path:
    """
    Output directory for a sandbox result.

    A result whose image id differs from the last component of ``out_dir`` gets its own subdirectory.
    """
    details = sandbox_result.details
    if details and details.sandbox and details.sandbox.image:
        image_id = details.sandbox.image.image_id
        if image_id and out_dir.parts[-1] != image_id:
            return Path(out_dir / image_id)
    return out_dir


def _sandbox_runs(artifacts: Iterable[Any] | None) -> Iterator[tuple[Any, Any]]:
    """
    ``(artifact, sandbox result)`` for every behavioral run, nested artifacts included.
    """
    for artifact in artifacts or ():
        for result in artifact.engine_results or ():
            if result.engine_subsystem == EngineSubsystem.SANDBOX and result.details and result.details.sandbox:
                yield artifact, result
        yield from _sandbox_runs(artifact.artifacts)


def _image_of(sandbox_result: Any) -> str | None:
    image = sandbox_result.details.sandbox.image
    return image.image_id if image else None


def _plan_run_dirs(out_dir: Path, runs: list[tuple[Any, Any]]) -> Iterator[tuple[Path, Any]]:
    """
    Output directory for each run.

    A run gets ``<image>/``; when an image has several runs (files extracted from an
    archive), each one gets ``<image>/<file name>/``.
    """
    runs_per_image = Counter(_image_of(result) for _, result in runs)
    used: set[Path] = set()
    for artifact, result in runs:
        output = _resolve_output_dir(out_dir, result)
        if runs_per_image[_image_of(result)] > 1:
            fi = artifact.file_info
            name = (Path(fi.file_path).name if fi and fi.file_path else "") or (fi.sha256 if fi else "") or "file"
            base = output / name.replace(" ", "_")
            output, n = base, 1
            while output in used:
                output, n = base.with_name(f"{base.name}_{n}"), n + 1
            used.add(output)
        yield output, result


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
    log_entries: Iterable[Any],
    output: Path,
    options: DownloadOptions,
) -> list[DownloadItem]:
    """
    Select the log files of a sandbox result that ``options`` asks for.
    """
    result: list[DownloadItem] = []

    for log in log_entries:
        if (options.all or options.logs) and log.type in _DEFAULT_LOG_TYPES:
            result.append(DownloadItem(output, log.file_name, log.file_uri, overwrite=True))

        if (options.all or options.video) and log.type == LogType.SCREENSHOT:
            result.append(DownloadItem(output, log.file_name, log.file_uri, overwrite=True))

        if (options.all or options.crashdumps) and log.file_name in _CRASHDUMP_FILES:
            result.append(DownloadItem(output / "crashdumps", log.file_name, log.file_uri))

        if (options.all or options.debug) and log.type in _DEBUG_LOG_TYPES:
            result.append(DownloadItem(output / "debug", log.file_name, log.file_uri))

    return result


def _collect_artifact_downloads(
    sandbox_artifacts: Iterable[Any],
    output: Path,
    options: DownloadOptions,
) -> list[DownloadItem]:
    """
    Select the artifacts (dropped files, dumps, ...) that ``options`` asks for.
    """
    result: list[DownloadItem] = []

    for artifact in sandbox_artifacts:
        if not artifact.file_info:
            continue

        fi = artifact.file_info
        atype = artifact.type

        if atype == ArtifactType.FILE and (options.files or options.artifacts or options.all):
            result.append(DownloadItem(output / "artifacts", fi.file_path.removeprefix("/"), fi.file_uri))

        if atype == ArtifactType.PROCESS_DUMP and (options.procdumps or options.artifacts or options.all):
            result.append(
                DownloadItem(
                    output / "process_dump",
                    fi.details.process_dump.process_name.removeprefix("/"),
                    fi.file_uri,
                    decompress=options.decompress,
                )
            )

        if atype == ArtifactType.AMSI and (options.amsi or options.all):
            result.append(DownloadItem(output / "amsi", f"{fi.sha256}.bin", fi.file_uri))

        if atype == ArtifactType.DEX_DUMP and (options.dex or options.all):
            result.append(DownloadItem(output / "dex", f"{fi.sha256}.bin", fi.file_uri))

        if options.all and atype not in _KNOWN_ARTIFACT_TYPES:
            result.append(DownloadItem(output / "other", fi.sha256, fi.file_uri))

    return result


async def download(
    report: SandboxBaseTaskResponse.LongReport,
    sandbox: Sandbox,
    out_dir: Path,
    options: DownloadOptions,
    *,
    tracker: DownloadTracker | None = None,
    full_report: SandboxBaseTaskResponse | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
    semaphore: asyncio.Semaphore | None = None,
) -> None:
    """
    Download everything ``options`` selects from a finished task into ``out_dir``.

    ``semaphore`` limits concurrent downloads; pass a shared one to bound
    downloads across several tasks running in parallel.
    """
    items: list[DownloadItem] = []
    saved_report_dirs: set[Path] = set()

    if options.sample:
        for artifact in report.artifacts:
            fi = artifact.file_info
            if fi is None or not fi.file_uri:
                continue
            name = Path(fi.file_path).name or fi.sha256
            items.append(DownloadItem(out_dir, f"{name}.bin", fi.file_uri))

    for output, sandbox_result in _plan_run_dirs(out_dir, list(_sandbox_runs(report.artifacts))):
        _save_report_json(output, full_report, saved_report_dirs)

        sb = sandbox_result.details.sandbox
        items.extend(_collect_log_downloads(sb.logs, output, options))
        if sb.artifacts:
            items.extend(_collect_artifact_downloads(sb.artifacts, output, options))

    if not items:
        console.info(f"Nothing to download from {report.scan_id}")
        return

    semaphore = semaphore or asyncio.Semaphore(value=concurrency)
    claimed: set[Path] = set()
    tasks: list[Coroutine[Any, Any, None]] = [
        _save_artifact(
            report.scan_id,
            sandbox,
            item,
            semaphore=semaphore,
            claimed=claimed,
            read_timeout=read_timeout,
            tracker=tracker,
        )
        for item in items
    ]
    await asyncio.gather(*tasks)
