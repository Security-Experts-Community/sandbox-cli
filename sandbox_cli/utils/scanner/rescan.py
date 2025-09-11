import asyncio
import sys
from collections.abc import Coroutine
from io import BytesIO
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile

import aiohttp
import aiohttp.client_exceptions
from ptsandbox import Sandbox
from ptsandbox.models import (
    SandboxBaseScanTaskRequest,
    SandboxKey,
    SandboxUploadException,
    SandboxWaitTimeoutException,
)
from rich.progress import Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn

from sandbox_cli.console import console
from sandbox_cli.internal.config import settings
from sandbox_cli.internal.helpers import (
    format_link,
    get_key_by_name,
    open_link,
    save_scan_arguments,
)
from sandbox_cli.models.sandbox_arguments import SandboxArguments, ScanType
from sandbox_cli.utils.compiler import compile_rules_internal
from sandbox_cli.utils.downloader import download
from sandbox_cli.utils.unpack import Unpack


async def _get_compiled_rules(progress: Progress, rules_dir: Path | None, is_local: bool) -> bytes | None:
    if not rules_dir:
        progress.disable = False
        progress.start()
        return None

    inner_progress = Progress(
        TextColumn(console.INFO),
        SpinnerColumn(),
        TextColumn(text_format="{task.description}"),
        "•",
        TimeElapsedColumn(),
        console=console,
    )
    task_id: TaskID

    text = (
        "Compiling rules locally"
        if is_local
        else f"Compiling rules on the remote • [medium_purple]{settings.sandbox[0].host}[/]"
    )
    task_id = inner_progress.add_task(text)

    with inner_progress:
        result = await compile_rules_internal(rules_dir=rules_dir, is_local=is_local)
        inner_progress.stop_task(task_id=task_id)

    inner_progress.stop()

    progress.disable = False
    progress.start()

    return result


async def _prepare_rescan_options(
    progress: Progress,
    rules_dir: Path | None,
    sandbox_key: SandboxKey,
    is_local: bool,
) -> tuple[Sandbox, SandboxBaseScanTaskRequest.Options]:
    sandbox = Sandbox(sandbox_key)

    sandbox_options = SandboxBaseScanTaskRequest.Options(analysis_depth=2, passwords_for_unpack=settings.passwords)

    # process custom options
    compiled_rules = await _get_compiled_rules(rules_dir=rules_dir, is_local=is_local, progress=progress)

    if compiled_rules:
        try:
            rules_uri = (await sandbox.api.upload_file(compiled_rules)).data.file_uri
            sandbox_options.sandbox.debug_options["rules_url"] = rules_uri
        except aiohttp.client_exceptions.ClientResponseError:
            console.error(f"Can't upload compiled rules {rules_dir} to sandbox")

    return (sandbox, sandbox_options)


async def rescan_internal(
    *,  # no not keyword args
    traces: list[Path],
    rules_dir: Path | None,
    out_dir: Path,
    key_name: str,
    is_local: bool,
    unpack: bool,
    debug: bool,
    open_browser: bool,
    timeout: int,
) -> None:
    key = get_key_by_name(key_name)
    sandbox_sem = asyncio.Semaphore(value=key.max_workers)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.fields[idx]}"),
        "•",
        TextColumn("{task.description}"),
        "•",
        TextColumn("{task.fields[url]}"),
        "•",
        TimeElapsedColumn(),
        console=console,
        disable=True,
        transient=True,
    )

    async def process_trace(
        drakvuf_trace: Path | BytesIO,
        tcpdump_pcap: Path | BytesIO,
        trace: Path,
        out_dir: Path,
        idx: str,
    ) -> None:
        idx = f"[turquoise2 bold]{idx}[/]"

        async with sandbox_sem:
            task_id = progress.add_task(description="Creating task", idx=idx, url="...")

            try:
                rescan_result = await sandbox.create_rescan(
                    drakvuf_trace,
                    tcpdump_pcap,
                    options=sandbox_options,
                    rules=None,
                    read_timeout=timeout,
                )
            except SandboxUploadException as e:
                console.error(f"[yellow]{trace}[/] • an error occurred when uploading a file to the server • {e}")
                progress.remove_task(task_id)
                return
            except aiohttp.client_exceptions.ClientResponseError as e:
                console.error(f"[yellow]{trace}[/] • {e}")
                progress.remove_task(task_id)
                return

            formatted_link = f"[medium_purple]{format_link(rescan_result, key=key)}[/]"
            final_output = f"[yellow]{trace.name}[/] • {formatted_link}"

            if open_browser:
                open_link(format_link(rescan_result, key=key))

            progress.update(
                task_id=task_id,
                description=f"Waiting for full report for [yellow]{trace.name}[/]",
                url=formatted_link,
            )
            try:
                if not (awaited_report := await sandbox.wait_for_report(rescan_result, timeout)):
                    console.error(f"Rescan failed for [yellow]{trace.name}[/] • {formatted_link} • {rescan_result}")
                    progress.remove_task(task_id)
                    return
            except SandboxWaitTimeoutException:
                console.error(f"{final_output} • got timeout while waiting")
                progress.remove_task(task_id)
                return

            rescan_result = awaited_report

        # write report.json
        (out_dir / settings.report_name).write_text(rescan_result.model_dump_json(indent=4), encoding="utf-8")

        # get full report?
        if not (long_report := rescan_result.get_long_report()):
            console.error(f"{final_output} • full report not available")
            progress.remove_task(task_id)
            return

        progress.update(task_id=task_id, description="Downloading results...")

        await download(long_report, sandbox, out_dir, logs=True, debug=debug)

        console.done(final_output)

        progress.remove_task(task_id)

        if unpack:
            Unpack(out_dir).run()

    async def wrapper(trace: Path, out_dir: Path, idx: str) -> None:
        """
        Internal function for prepare raw traces for re-scan

        :param trace
            file - zip file with drakvuf-trace.log.gz/drakvuf-trace.log.zst and tcpdump.pcap inside

            dir - directory with drakvuf-trace.log.gz/drakvuf-trace.log.zst and tcpdump.pcap files

        :param out_dir - save dir for current trace
        :param idx - just nice index for output
        """

        drakvuf_trace: Path | BytesIO
        tcpdump_pcap: Path | BytesIO
        if trace.is_dir():
            drakvuf_trace = trace / "drakvuf-trace.log.gz"
            if not drakvuf_trace.exists():
                # handle case with modern zst format
                drakvuf_trace = trace / "drakvuf-trace.log.zst"
                if not drakvuf_trace.exists():
                    console.error(
                        f"drakvuf-trace.log.gz or drakvuf-trace.log.zst doesn't exist in {trace.expanduser().resolve()}"
                    )
                    sys.exit(1)

            tcpdump_pcap = trace / "tcpdump.pcap"
            if not tcpdump_pcap.exists():
                console.error(f"tcpdump.pcap don't exists in {trace}")
                sys.exit(1)
        else:
            try:
                with ZipFile(trace) as zip:
                    log_file = ""
                    for file in zip.filelist:
                        if file.filename in {"drakvuf-trace.log.gz", "drakvuf-trace.log.zst"}:
                            log_file = file.filename
                            break

                    raw_trace = zip.read(log_file)
                    if raw_trace == b"":
                        console.error(f"Empty {log_file} in {trace}")
                        sys.exit(1)

                    drakvuf_trace = BytesIO(raw_trace)
                    tcpdump_pcap = BytesIO(zip.read("tcpdump.pcap"))
            except BadZipFile:
                console.error(f"{trace} not a zip file")
                sys.exit(1)

        await process_trace(drakvuf_trace, tcpdump_pcap, trace, out_dir, idx)

    console.info(f"Using key: name={key.name.get_secret_value()} max_workers={key.max_workers}")

    tasks: list[Coroutine[Any, Any, None]] = []
    with progress:
        sandbox, sandbox_options = await _prepare_rescan_options(progress, rules_dir, key, is_local)
        sandbox_arguments = SandboxArguments(
            type=ScanType.RE_SCAN,
            sandbox_key_name=key.name.get_secret_value(),
            sandbox_options=sandbox_options.sandbox,
        )

        if len(traces) == 1:
            local_out_dir = out_dir / "rescan"
            local_out_dir.mkdir(parents=True, exist_ok=True)
            save_scan_arguments(local_out_dir, sandbox_arguments)
            tasks.append(wrapper(traces[0], local_out_dir, "1/1"))
        else:
            for i, trace in enumerate(traces):
                local_out_dir = out_dir / f"rescan_{i + 1}"

                # nice names for zip files
                if trace.suffix == ".zip":
                    local_out_dir = out_dir / trace.stem

                local_out_dir.mkdir(parents=True, exist_ok=True)
                save_scan_arguments(local_out_dir, sandbox_arguments)
                idx = f"{i + 1}/{len(traces)}"
                tasks.append(wrapper(trace, local_out_dir, idx))

        await asyncio.gather(*tasks)
        await sandbox.api.session.close()
