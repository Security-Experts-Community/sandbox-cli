from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Annotated
from urllib.parse import urlparse
from uuid import UUID

import aiohttp
from cyclopts import Parameter, validators
from ptsandbox import Sandbox

from sandbox_cli.cli._params import (
    DOWNLOAD_OPTIONS,
    ArtifactFlags,
    JsonOutput,
    Key,
    OutDir,
    UnpackFlag,
    default_key,
    switch,
)
from sandbox_cli.console import console
from sandbox_cli.core.exceptions import DownloadError, SandboxCliError
from sandbox_cli.core.progress import SandboxProgress, make_progress
from sandbox_cli.core.reporting import ProgressDownloadTracker
from sandbox_cli.core.sandbox import (
    format_link,
    get_key_by_name,
    get_sandbox_key_by_host,
)
from sandbox_cli.services.downloader import DEFAULT_CONCURRENCY, DEFAULT_READ_TIMEOUT, download
from sandbox_cli.services.scanner.runner import describe_error
from sandbox_cli.services.unpack import unpack_results

if TYPE_CHECKING:
    from ptsandbox import SandboxKey
    from ptsandbox.models import SandboxBaseTaskResponse

__all__ = ["download_command"]

_TASKS_PAGE_SIZE = 40


def _parse_task_url(task: str) -> tuple[str, UUID] | None:
    """
    Extract ``(host, uuid)`` from a sandbox task URL.

    Accepts ``/tasks/<uuid>`` and ``/<uuid>`` path shapes, with or without ``https://``.
    Returns ``None`` when ``task`` is not a parseable task URL.
    """
    url = urlparse(task if "://" in task else f"https://{task}")
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


def resolve_task(key: str, task: str) -> tuple[SandboxKey, UUID]:
    """
    Resolve a task ID or URL into the sandbox key it belongs to and its UUID.

    A bare UUID uses ``key``; a URL selects the sandbox by host.
    """
    try:
        uuid = UUID(task)
    except ValueError:
        pass
    else:
        return get_key_by_name(key), uuid

    if (parsed := _parse_task_url(task)) is None:
        raise DownloadError(f"Invalid task id: {task}")

    host, uuid = parsed
    return get_sandbox_key_by_host(host), uuid


def _resolve_tasks(key: str, tasks: list[str]) -> list[tuple[SandboxKey, UUID]]:
    """
    Resolve every task id or link; raise ``DownloadError`` listing all invalid ones.
    """
    resolved: list[tuple[SandboxKey, UUID]] = []
    problems: list[str] = []
    for task in tasks:
        try:
            resolved.append(resolve_task(key, task))
        except SandboxCliError as e:
            problems.append(str(e))
    if problems:
        raise DownloadError("; ".join(problems))
    return resolved


async def _search_tasks(sandbox: Sandbox, query: str, count: int) -> list[str]:
    """
    Ids of up to ``count`` tasks matching ``query``, newest first.
    """
    task_ids: list[str] = []
    next_cursor = ""
    while len(task_ids) < count:
        limit = min(_TASKS_PAGE_SIZE, count - len(task_ids))
        response = await sandbox.get_tasks(query=query, limit=limit, next_cursor=next_cursor)
        page = response.tasks[:limit]
        task_ids.extend(str(task.id) for task in page)
        next_cursor = response.next_cursor
        if not page or not next_cursor:
            break
    return task_ids


async def _fetch_report(
    sandbox: Sandbox, task_id: str | UUID, progress: SandboxProgress
) -> tuple[SandboxBaseTaskResponse, SandboxBaseTaskResponse.LongReport] | None:
    progress_task = progress.add_task(rf"\[[green1]{task_id}[/]] fetching info")
    try:
        result = await sandbox.get_report(task_id=task_id)
    except aiohttp.ClientResponseError as e:
        if e.status != HTTPStatus.NOT_FOUND:
            raise
        console.warning(f"Task {task_id} not found")
        return None
    finally:
        progress.remove_task(progress_task)

    if (report := result.get_long_report()) is None:
        console.warning(f"Not found information for {task_id}")
        return None
    return result, report


async def download_command(
    tasks_id: Annotated[list[str] | None, Parameter(help="Links to tasks or task ids", negative="")] = None,
    /,
    *,
    key: Key = default_key(),
    out_dir: OutDir = Path("./downloads"),
    unpack: UnpackFlag = False,
    json_output: JsonOutput = False,
    artifacts: ArtifactFlags = ArtifactFlags(),
    video: Annotated[bool, switch(["--video", "-v"], "Download video", DOWNLOAD_OPTIONS)] = False,
    logs: Annotated[bool, switch(["--logs", "-L"], "Download logs", DOWNLOAD_OPTIONS)] = False,
    sample: Annotated[
        bool, switch(["--sample", "-sa"], "Download the original sample submitted for analysis", DOWNLOAD_OPTIONS)
    ] = False,
    query: Annotated[
        str | None,
        Parameter(
            name=["--query", "-q"], help="Query for searching tasks (leave empty for last tasks)", group="Search"
        ),
    ] = None,
    count: Annotated[
        int,
        Parameter(
            name=["--count", "-c"],
            help="How many tasks find and download",
            validator=validators.Number(gt=0),
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
    ] = DEFAULT_CONCURRENCY,
    read_timeout: Annotated[
        int,
        Parameter(
            name="--read-timeout",
            help="Read timeout in seconds for each download",
            validator=validators.Number(gt=0),
            group="Performance",
        ),
    ] = DEFAULT_READ_TIMEOUT,
) -> None:
    """
    Download any artifact from the sandbox.
    """

    resolved = _resolve_tasks(key, tasks_id or [])
    options = artifacts.to_options(video=video, logs=logs, sample=sample)
    progress = make_progress()
    tracker = ProgressDownloadTracker(progress)
    semaphore = asyncio.Semaphore(concurrency)

    async def process(sandbox: Sandbox, task_id: str | UUID) -> bool:
        try:
            if (fetched := await _fetch_report(sandbox, task_id, progress)) is None:
                console.emit_json({"status": "skipped", "task_id": str(task_id), "reason": "no report"})
                return True
            result, report = fetched
            task_dir = out_dir / str(task_id)
            await download(
                report,
                sandbox,
                task_dir,
                options,
                tracker=tracker,
                full_report=result,
                read_timeout=read_timeout,
                semaphore=semaphore,
            )
            if unpack:
                await asyncio.to_thread(unpack_results, task_dir)
        except Exception as e:
            reason = describe_error(e)
            console.error(rf"\[[green1]{task_id}[/]] • {reason}")
            console.emit_json({"status": "failed", "task_id": str(task_id), "reason": reason})
            return False
        console.done(rf"\[[green1]{task_id}[/]] • {task_dir}")
        console.emit_json(
            {
                "status": "done",
                "task_id": str(task_id),
                "link": format_link(result, sandbox.api.key.host),
                "out_dir": str(task_dir),
            }
        )
        return True

    async with AsyncExitStack() as stack:
        sandboxes: dict[str, Sandbox] = {}

        async def session(sandbox_key: SandboxKey) -> Sandbox:
            if (sandbox := sandboxes.get(sandbox_key.name)) is None:
                sandbox = sandboxes[sandbox_key.name] = await stack.enter_async_context(Sandbox(sandbox_key))
            return sandbox

        with progress:
            targets: list[tuple[Sandbox, str | UUID]] = []
            if query is not None:
                sandbox = await session(get_key_by_name(key))
                targets.extend((sandbox, task_id) for task_id in await _search_tasks(sandbox, query, count))

            for sandbox_key, task_id in resolved:
                targets.append((await session(sandbox_key), task_id))

            with console.terminal_progress.activity(total=len(targets)):

                async def tracked(sandbox: Sandbox, task_id: str | UUID) -> bool:
                    try:
                        return await process(sandbox, task_id)
                    finally:
                        console.terminal_progress.advance()

                results = await asyncio.gather(*(tracked(sb, task_id) for sb, task_id in targets))

    if failed := results.count(False):
        raise DownloadError(f"Failed to download {failed} of {len(targets)} tasks")
