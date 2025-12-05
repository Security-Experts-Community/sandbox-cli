import asyncio
from collections.abc import Coroutine
from io import BytesIO
from pathlib import Path
from typing import Any
from uuid import UUID

import aiofiles
import aiohttp
import zstandard
from ptsandbox import Sandbox
from ptsandbox.models import (
    ArtifactType,
    LogType,
    SandboxBaseTaskResponse,
    SandboxFileNotFoundException,
)
from rich.markup import escape
from rich.progress import Progress, TaskID

from sandbox_cli.console import console

semaphore = asyncio.Semaphore(value=16)

# At first glance, it's counter-intuitive, but ArtifactType can contain not only predefined fields in it, but also newly added.
# This usually happens when a new feature is released in the sandbox.
_KNOWN_ARTIFACT_TYPES = {
    ArtifactType.ARCHIVE,
    ArtifactType.COMPRESSED,
    ArtifactType.EMAIL,
    ArtifactType.FILE,
    ArtifactType.PROCESS_DUMP,
    ArtifactType.URL,
}


async def _save_artifact(
    scan_id: UUID,
    sandbox: Sandbox,
    out_dir: Path,
    path: Path,
    file_uri: str,
    overwrite: bool = False,
    decompress: bool = False,
    progress: Progress | None = None,
    idx: str | None = None,
    image: str | None = None,
    link: str | None = None,
) -> None:
    _, uri = file_uri.split(":")
    if not uri:
        return

    # sanitize path
    path = out_dir / Path(str(path).replace(" ", "_"))
    if not overwrite:
        n = 1
        while path.exists():
            if not path.with_name(path.name + f"_{n}").exists():
                path = path.with_name(path.name + f"_{n}")
                break
            n += 1

    path.parent.mkdir(exist_ok=True, parents=True)
    path.touch()
    task_id: TaskID = None  # type: ignore

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
        try:
            # a 5-minute timeout for downloading large files
            downloaded_data = await sandbox.get_file(uri, read_timeout=300)
        except SandboxFileNotFoundException:
            console.warning(f"File {path.name} not found in storage: {uri=} {scan_id=}")
            if progress:
                progress.stop_task(task_id)
                progress.update(task_id=task_id, visible=False)
            return
        except aiohttp.SocketTimeoutError as e:
            if progress:
                progress.stop_task(task_id)
                progress.update(task_id=task_id, visible=False)

            raise e

        if decompress:
            try:
                dctx = zstandard.ZstdDecompressor()
                with open(path, "wb") as output:
                    input_fd = BytesIO(downloaded_data)
                    dctx.copy_stream(input_fd, output)
            except zstandard.ZstdError as e:
                console.warning(f"Can't decompress [yellow]{path.name}[/]. {e}")
        else:
            async with aiofiles.open(path, "wb") as fd:
                await fd.write(downloaded_data)

        if progress:
            progress.stop_task(task_id)
            progress.update(task_id=task_id, visible=False)


async def download(
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
    idx: str | None = None,
    image: str | None = None,
    link: str | None = None,
) -> None:
    tasks: list[Coroutine[Any, Any, None]] = []

    def add_task(out_dir: Path, path: Path, file_uri: str, decompress: bool = False, overwrite: bool = False) -> None:
        tasks.append(
            _save_artifact(
                scan_id=report.scan_id,
                sandbox=sandbox,
                out_dir=out_dir,
                path=path,
                file_uri=file_uri,
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
            if sandbox_result is None:
                continue

            if sandbox_result.details is None:
                continue

            if sandbox_result.details.sandbox is None:
                continue

            if (
                sandbox_result.details.sandbox.image
                and (image_id := sandbox_result.details.sandbox.image.image_id)
                and out_dir.parts[-1] != image_id
            ):
                output = out_dir / image_id
            else:
                output = out_dir

            for log in sandbox_result.details.sandbox.logs:
                # download default logs by default
                if (all or logs) and log.type in {
                    LogType.EVENT_CORRELATED,
                    LogType.EVENT_NORMALIZED,
                    LogType.EVENT_RAW,
                    LogType.NETWORK,
                }:
                    add_task(output, log.file_name, log.file_uri, overwrite=True)

                if (all or video) and log.type == LogType.SCREENSHOT:
                    add_task(output, log.file_name, log.file_uri, overwrite=True)

                if (all or crashdumps) and log.file_name in {"crashdump.bin", "crashdump.metadata"}:
                    add_task(output / "crashdumps", log.file_name, log.file_uri)

                if (all or debug) and log.type in {LogType.DEBUG, LogType.GRAPH}:
                    add_task(output / "debug", log.file_name, log.file_uri)

            if artifacts or files or procdumps or all:
                if not sandbox_result.details:
                    continue

                if not sandbox_result.details.sandbox:
                    continue

                if not sandbox_result.details.sandbox.artifacts:
                    continue

                for artifact in sandbox_result.details.sandbox.artifacts:
                    if not artifact.file_info:
                        continue

                    if artifact.type == ArtifactType.FILE and (files or artifacts or all):
                        add_task(
                            output / "artifacts",
                            artifact.file_info.file_path.removeprefix("/"),
                            artifact.file_info.file_uri,
                        )
                    if artifact.type == ArtifactType.PROCESS_DUMP and (procdumps or artifacts or all):
                        add_task(
                            output / "process_dump",
                            artifact.file_info.details.process_dump.process_name.removeprefix("/"),  # type: ignore
                            artifact.file_info.file_uri,
                            decompress=decompress,
                        )

                    if all and artifact.type not in _KNOWN_ARTIFACT_TYPES:
                        add_task(
                            output / "other",
                            artifact.file_info.sha256,
                            artifact.file_info.file_uri,
                        )

    if not tasks:
        console.info(f"Nothing to download from {report.scan_id}")

    await asyncio.gather(*tasks)
