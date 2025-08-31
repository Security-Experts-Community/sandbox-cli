import asyncio
import os
import sys
from collections.abc import Coroutine
from http import HTTPStatus
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse
from uuid import UUID

import aiofiles
import aiohttp
import aiohttp.client_exceptions
from cyclopts import Parameter
from ptsandbox import Sandbox
from ptsandbox.models import Artifact, SandboxBaseTaskResponse
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from sandbox_cli.console import console
from sandbox_cli.internal.config import settings
from sandbox_cli.internal.helpers import (
    get_key_by_name,
    get_sandbox_key_by_host,
    validate_key,
)
from sandbox_cli.utils.downloader import download
from sandbox_cli.utils.unpack import Unpack


def get_key_and_task(key: str, task: str) -> tuple[Sandbox, UUID] | tuple[None, None]:
    try:
        uuid = UUID(task)
        sandbox_key = get_key_by_name(key)
        return Sandbox(sandbox_key), uuid
    except ValueError:
        url = urlparse(task)
        if not (url.scheme and url.path and "/tasks" in url.path):
            console.warning(f"Invalid task_id: {task}")
            return None, None

        try:
            uuid = UUID(url.path.split("/")[2])
            sandbox_key = get_sandbox_key_by_host(url.hostname or "")
            return Sandbox(sandbox_key), uuid
        except ValueError:
            console.error(f"Invalid task id: {task}")
            return None, None


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
            help=f"The key to access the sandbox **{'**,**'.join(x.name.get_secret_value() for x in settings.sandbox_keys)}**",
            validator=validate_key,
            group="Sandbox",
        ),
    ] = settings.sandbox_keys[0].name.get_secret_value(),
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
            help="Download crashdumps (maybe be more 1GB)",
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
    query: Annotated[
        str | None,
        Parameter(
            name=["--query", "-q"],
            help="Query for searching tasks (leave empty for last tasks)",
            group="Search",
        )
    ] = None,
    count: Annotated[
        int,
        Parameter(
            name=["--count", "-c"],
            help="How many tasks find and download",
            group="Search",
        )
    ] = 20,
) -> None:
    """
    Download any artifact from the sandbox.
    """

    if tasks_id is None:
        tasks_id = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )

    async def worker(
        report: SandboxBaseTaskResponse.LongReport,
        sandbox: Sandbox,
        out_dir: Path,
        all: bool = False,
        artifacts: bool = False,
        crashdumps: bool = False,
        debug: bool = False,
        decompress: bool = False,
        files: bool = False,
        logs: bool = False,
        procdumps: bool = False,
        video: bool = False,
        progress: Progress | None = None,
    ) -> None:
        await download(
            report=report,
            sandbox=sandbox,
            out_dir=out_dir,
            all=all,
            debug=debug,
            artifacts=artifacts,
            files=files,
            crashdumps=crashdumps,
            procdumps=procdumps,
            video=video,
            logs=logs,
            decompress=decompress,
            progress=progress,
        )

        if unpack and out_dir.exists():
            # multiple images can be downloaded from the task
            if not (out_dir / "events-correlated.log.gz").exists():
                subfolders = [f.path for f in os.scandir(out_dir) if f.is_dir()]
                for folder in subfolders:
                    Unpack(Path(folder)).run()
            else:
                Unpack(out_dir).run()

    async def create_task(sandbox: Sandbox, task_id: str) -> None:
        progress_task_id = progress.add_task(description=rf"\[[green1]{task_id}[/]] fetching info", start=True)

        def finalize_progress() -> None:
            progress.remove_task(task_id=progress_task_id)

        try:
            result = await sandbox.get_report(task_id=task_id)
        except aiohttp.client_exceptions.ClientResponseError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                console.warning(f"Got 404 error for {task_id}")
            finalize_progress()
            return

        if (report := result.get_long_report()) is None:
            console.warning(f"Not found information for {task_id}")
            finalize_progress()
            return

        finalize_progress()

        tasks.append(
            worker(
                report=report,
                sandbox=sandbox,
                out_dir=out_dir / str(task_id),
                all=all,
                debug=debug,
                artifacts=artifacts,
                files=files,
                crashdumps=crashdumps,
                procdumps=procdumps,
                video=video,
                logs=logs,
                decompress=decompress,
                progress=progress,
            )
        )

    tasks: list[Coroutine[Any, Any, Artifact.EngineResult | None]] = []

    if query is not None:
        sandbox = Sandbox(get_key_by_name(key_name=key))

        limit = 40 if count > 40 else count
        viewed, next_cursor = 0, ""

        with progress:
            while viewed <= count:
                response = await sandbox.get_tasks(query=query, limit=limit, next_cursor=next_cursor)
                await asyncio.gather(*(create_task(sandbox, task.id) for task in response.tasks))

                viewed += limit
                next_cursor = response.next_cursor

        # clear last line
        sys.stdout.write("\033[F\033[K")

    for task in tasks_id:
        sandbox, task_id = get_key_and_task(key, task)
        if not sandbox or not task_id:
            continue

        await create_task(sandbox, task_id)

    with progress:
        await asyncio.gather(*tasks)

    # clear last line
    sys.stdout.write("\033[F\033[K")

def download_email(
    emails: Annotated[
        list[Path],
        Parameter(
            help="The path to the email files",
        ),
    ],
    /,
    *,
    out_dir: Annotated[
        Path,
        Parameter(
            name=["--out", "-o"],
            help="Output directory",
        ),
    ] = Path("./downloads"),
    key: Annotated[
        str,
        Parameter(
            name=["--key", "-k"],
            help=f"The key to access the sandbox **{'**,**'.join(x.name.get_secret_value() for x in settings.sandbox_keys)}**",
            validator=validate_key,
            group="Sandbox",
        ),
    ] = settings.sandbox_keys[0].name.get_secret_value(),
) -> None:
    """
    Upload an email and get its headers.
    """

    # some path prepartions
    out_dir.mkdir(exist_ok=True, parents=True)
    out_dir = out_dir.expanduser().resolve()

    async def _func(out_dir: Path) -> None:
        sandbox = Sandbox(get_key_by_name(key))

        async def _internal(email: Path, out_dir: Path) -> None:
            async with aiofiles.open(out_dir / f"{email}.headers", "wb") as fd:
                async for chunk in sandbox.get_email_headers(email):
                    await fd.write(chunk)

        # small validation
        files: list[Path] = []
        for email in emails:
            if not email.exists():
                console.warning(f"{email} doesn't exists")
                continue
            files.append(email)

        await asyncio.gather(*(_internal(email, out_dir) for email in files))

    asyncio.run(_func(out_dir))
