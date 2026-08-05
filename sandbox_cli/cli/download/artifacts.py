from __future__ import annotations

import asyncio
import os
from contextlib import AsyncExitStack
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Annotated
from urllib.parse import urlparse
from uuid import UUID

import aiohttp
import aiohttp.client_exceptions
from cyclopts import Parameter, validators
from ptsandbox import Sandbox

from sandbox_cli.console import console
from sandbox_cli.core.config import key_help, settings
from sandbox_cli.core.progress import make_progress
from sandbox_cli.core.sandbox import (
    get_key_by_name,
    get_sandbox_key_by_host,
    validate_key,
)
from sandbox_cli.services.downloader import DownloadOptions, download
from sandbox_cli.services.unpack import Unpack

if TYPE_CHECKING:
    from ptsandbox.models import SandboxBaseTaskResponse

__all__ = ["download_command"]


def _unpack_dir(out_dir: Path) -> None:
    """
    Unpack downloaded logs, handling multi-image task directories.
    """
    if not out_dir.exists():
        return
    if (out_dir / "events-correlated.log.gz").exists():
        Unpack.run_unpack(out_dir)
        return
    for entry in os.scandir(out_dir):
        if entry.is_dir():
            Unpack.run_unpack(Path(entry.path))


def _parse_task_url(task: str) -> tuple[str, UUID] | None:
    """
    Extract ``(host, uuid)`` from a sandbox task URL.

    Accepts ``/tasks/<uuid>`` and ``/<uuid>`` path shapes.
    Returns ``None`` when ``task`` is not a parseable task URL.
    """
    url = urlparse(task)
    if not (url.scheme and url.hostname and url.path):
        return None

    segments = [s for s in url.path.split("/") if s]
    if not segments:
        return None

    uuid_segment = segments[1] if segments[0] == "tasks" else segments[0]
    try:
        return url.hostname, UUID(uuid_segment)
    except ValueError:
        return None


def get_key_and_task(key: str, task: str) -> tuple[Sandbox, UUID] | None:
    """
    Resolve a task ID or URL into a ``(Sandbox, UUID)`` pair.

    The returned ``Sandbox`` is not yet entered as a context manager —
    the caller is responsible for managing its lifecycle (e.g. via
    ``async with`` or ``AsyncExitStack``).
    """

    # Bare UUID — use the provided key.
    try:
        uuid = UUID(task)
    except ValueError:
        pass
    else:
        return Sandbox(get_key_by_name(key)), uuid

    # URL — resolve sandbox by host.
    if (parsed := _parse_task_url(task)) is not None:
        host, uuid = parsed
        try:
            return Sandbox(get_sandbox_key_by_host(host)), uuid
        except KeyError:
            console.error(f"Unknown sandbox host: {host}")
            return None

    console.error(f"Invalid task id: {task}")
    return None


async def download_command(
    tasks_id: Annotated[
        list[str] | None,
        Parameter(
            help="Links to tasks or task ids",
            negative="",
        ),
    ] = None,
    /,
    *,
    key: Annotated[
        str,
        Parameter(
            name=["--key", "-k"],
            help=key_help(),
            validator=validate_key,
            group="Sandbox",
        ),
    ] = settings.default_key_name,
    out_dir: Annotated[
        Path,
        Parameter(
            name=["--out", "-o"],
            help="Output directory",
        ),
    ] = Path("./downloads"),
    decompress: Annotated[
        bool,
        Parameter(
            name=["--decompress", "-D"],
            help="Decompress downloaded files",
            negative="",
        ),
    ] = False,
    unpack: Annotated[
        bool,
        Parameter(
            name=["--unpack", "-U"],
            help="Unpack downloaded files",
            negative="",
        ),
    ] = False,
    all: Annotated[
        bool,
        Parameter(
            name=["--all", "-a"],
            help="Download all artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    debug: Annotated[
        bool,
        Parameter(
            name=["--debug", "-d"],
            help="Download debug artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    artifacts: Annotated[
        bool,
        Parameter(
            name=["--artifacts", "-A"],
            help="Download artifacts",
            negative="",
            group="Download options",
        ),
    ] = False,
    files: Annotated[
        bool,
        Parameter(
            name=["--files", "-f"],
            help="Download files",
            negative="",
            group="Download options",
        ),
    ] = False,
    crashdumps: Annotated[
        bool,
        Parameter(
            name=["--crashdumps", "-C"],
            help="Download crashdumps (may be more than 1GB)",
            negative="",
            group="Download options",
        ),
    ] = False,
    procdumps: Annotated[
        bool,
        Parameter(
            name=["--procdumps", "-p"],
            help="Download procdumps",
            negative="",
            group="Download options",
        ),
    ] = False,
    video: Annotated[
        bool,
        Parameter(
            name=["--video", "-v"],
            help="Download video",
            negative="",
            group="Download options",
        ),
    ] = False,
    logs: Annotated[
        bool,
        Parameter(
            name=["--logs", "-l"],
            help="Download logs",
            negative="",
            group="Download options",
        ),
    ] = False,
    amsi: Annotated[
        bool,
        Parameter(
            name=["--amsi", "-am"],
            help="Download amsi-dumps",
            negative="",
            group="Download options",
        ),
    ] = False,
    dex: Annotated[
        bool,
        Parameter(
            name=["--dex", "-dx"],
            help="Download dex-dumps",
            negative="",
            group="Download options",
        ),
    ] = False,
    query: Annotated[
        str | None,
        Parameter(
            name=["--query", "-q"],
            help="Query for searching tasks (leave empty for last tasks)",
            group="Search",
        ),
    ] = None,
    count: Annotated[
        int,
        Parameter(
            name=["--count", "-c"],
            help="How many tasks find and download",
            group="Search",
        ),
    ] = 20,
    concurrency: Annotated[
        int,
        Parameter(
            name=["--concurrency", "-j"],
            help="Maximum number of concurrent downloads",
            validator=validators.Number(gt=0),
            group="Performance",
        ),
    ] = 16,
    read_timeout: Annotated[
        int,
        Parameter(
            name=["--read-timeout"],
            help="Read timeout in seconds for each download",
            validator=validators.Number(gt=0),
            group="Performance",
        ),
    ] = 300,
) -> None:
    """
    Download any artifact from the sandbox.
    """

    if tasks_id is None:
        tasks_id = []

    download_options = DownloadOptions(
        all=all,
        debug=debug,
        artifacts=artifacts,
        files=files,
        crashdumps=crashdumps,
        procdumps=procdumps,
        video=video,
        amsi=amsi,
        dex=dex,
        logs=logs,
        decompress=decompress,
    )

    progress = make_progress()

    async def worker(
        report: SandboxBaseTaskResponse.LongReport,
        sandbox: Sandbox,
        out_dir: Path,
        full_report: SandboxBaseTaskResponse,
    ) -> None:
        await download(
            report=report,
            sandbox=sandbox,
            out_dir=out_dir,
            options=download_options,
            progress=progress,
            full_report=full_report,
            concurrency=concurrency,
            read_timeout=read_timeout,
        )

        if unpack:
            await asyncio.to_thread(_unpack_dir, out_dir)

    download_tasks: list[asyncio.Task[None]] = []

    async def fetch_report(sandbox: Sandbox, task_id: str | UUID) -> None:
        """
        Fetch report for ``task_id`` and schedule download immediately.
        """

        progress_task_id = progress.add_task(description=rf"\[[green1]{task_id}[/]] fetching info", start=True)

        try:
            result = await sandbox.get_report(task_id=task_id)
        except aiohttp.client_exceptions.ClientResponseError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                console.warning(f"Got 404 error for {task_id}")
            progress.remove_task(task_id=progress_task_id)
            return

        if (report := result.get_long_report()) is None:
            console.warning(f"Not found information for {task_id}")
            progress.remove_task(task_id=progress_task_id)
            return

        progress.remove_task(task_id=progress_task_id)
        download_tasks.append(
            asyncio.create_task(
                worker(
                    report=report,
                    sandbox=sandbox,
                    out_dir=out_dir / str(task_id),
                    full_report=result,
                )
            )
        )

    # All Sandbox instances are managed via AsyncExitStack so their sessions
    # are closed automatically when the block exits — even on errors.
    async with AsyncExitStack() as stack:
        with progress:
            if query is not None:
                sandbox = await stack.enter_async_context(Sandbox(get_key_by_name(key_name=key)))

                limit = min(40, count)
                viewed, next_cursor = 0, ""

                while viewed <= count:
                    response = await sandbox.get_tasks(query=query, limit=limit, next_cursor=next_cursor)
                    await asyncio.gather(*(fetch_report(sandbox, task.id) for task in response.tasks))

                    viewed += limit
                    next_cursor = response.next_cursor

            # Resolve task IDs to (Sandbox, UUID) pairs, enter each Sandbox
            # context into the stack, then fetch reports concurrently.
            if tasks_id:
                resolved: list[tuple[Sandbox, UUID]] = []
                for task_str in tasks_id:
                    pair = get_key_and_task(key, task_str)
                    if pair is not None:
                        sb, task_id = pair
                        await stack.enter_async_context(sb)
                        resolved.append((sb, task_id))

                await asyncio.gather(*(fetch_report(sb, task_id) for sb, task_id in resolved))

            # Wait for all downloads to finish (some may already be complete
            # by now — they started as soon as their report was fetched).
            await asyncio.gather(*download_tasks)
