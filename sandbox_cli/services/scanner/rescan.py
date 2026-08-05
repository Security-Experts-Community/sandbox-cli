import asyncio
from collections.abc import Coroutine
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zipfile import BadZipFile, ZipFile

import aiohttp
import aiohttp.client_exceptions
from ptsandbox import Sandbox
from ptsandbox.exceptions import (
    SandboxException,
    SandboxUploadException,
    SandboxWaitTimeoutException,
)
from ptsandbox.models import SandboxBaseScanTaskRequest

from sandbox_cli.console import console
from sandbox_cli.core.browser import open_link
from sandbox_cli.core.config import settings
from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.core.progress import make_scan_progress
from sandbox_cli.core.sandbox import format_link, get_key_by_name
from sandbox_cli.core.scan import (
    SandboxArguments,
    ScanType,
    save_report,
    save_scan_arguments,
)
from sandbox_cli.services.downloader import DownloadOptions, download
from sandbox_cli.services.scanner.compile import compile_rules
from sandbox_cli.services.scanner.utils import shorten_name
from sandbox_cli.services.unpack import Unpack

if TYPE_CHECKING:
    from rich.progress import Progress

_TRACE_LOG_NAMES = {
    "drakvuf-trace.log.gz",
    "drakvuf-trace.log.zst",
}


def load_trace(trace: Path) -> tuple[Path | BytesIO, Path | BytesIO]:
    """
    Extract drakvuf trace and tcpdump pcap from a trace archive/dir.

    :param trace:
        file — zip file with drakvuf-trace.log.gz/drakvuf-trace.log.zst and tcpdump.pcap inside
        dir  — directory with drakvuf-trace.log.gz/drakvuf-trace.log.zst and tcpdump.pcap files
    """

    if trace.is_dir():
        drakvuf_trace: Path = trace / "drakvuf-trace.log.gz"
        if not drakvuf_trace.exists():
            # handle case with modern zst format
            drakvuf_trace = trace / "drakvuf-trace.log.zst"
            if not drakvuf_trace.exists():
                raise ScanError(
                    f"drakvuf-trace.log.gz or drakvuf-trace.log.zst doesn't exist in {trace.expanduser().resolve()}"
                )

        tcpdump_pcap: Path = trace / "tcpdump.pcap"
        if not tcpdump_pcap.exists():
            raise ScanError(f"tcpdump.pcap doesn't exist in {trace}")
        return drakvuf_trace, tcpdump_pcap

    try:
        with ZipFile(trace) as zf:
            log_file = next((f.filename for f in zf.filelist if f.filename in _TRACE_LOG_NAMES), "")
            if not log_file:
                raise ScanError(f"No drakvuf-trace.log.gz or drakvuf-trace.log.zst in {trace}")

            raw_trace = zf.read(log_file)
            if raw_trace == b"":
                raise ScanError(f"Empty {log_file} in {trace}")

            drakvuf_trace_buf: BytesIO = BytesIO(raw_trace)
            tcpdump_pcap_buf: BytesIO = BytesIO(zf.read("tcpdump.pcap"))
            return drakvuf_trace_buf, tcpdump_pcap_buf
    except BadZipFile as e:
        raise ScanError(f"{trace} not a zip file") from e


async def _prepare_rescan_options(
    sandbox: Sandbox,
    progress: Progress,
    rules_dir: Path | None,
    is_local: bool,
) -> SandboxBaseScanTaskRequest.Options:
    sandbox_options = SandboxBaseScanTaskRequest.Options(analysis_depth=2, passwords_for_unpack=settings.passwords)

    # enable default debug options
    # all debug options available in library
    sandbox_options.sandbox.debug_options["save_debug_files"] = True

    # process custom options
    compiled_rules = await compile_rules(rules_dir, is_local, progress=progress)

    if compiled_rules:
        try:
            rules_uri = (await sandbox.api.upload_file(compiled_rules)).data.file_uri
            sandbox_options.sandbox.debug_options["rules_url"] = rules_uri
        except aiohttp.client_exceptions.ClientResponseError:
            console.error(f"Can't upload compiled rules {rules_dir} to sandbox")

    return sandbox_options


async def rescan_internal(
    *,  # keyword-only args
    traces: list[Path],
    rules_dir: Path | None,
    out_dir: Path,
    key_name: str,
    is_local: bool,
    unpack: bool,
    download_options: DownloadOptions,
    open_browser: bool,
    timeout: int,
) -> None:
    key = get_key_by_name(key_name)
    sandbox_sem = asyncio.Semaphore(value=key.max_workers)

    progress = make_scan_progress(with_image=False, disable=True)

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
            except aiohttp.ClientError as e:
                console.error(f"[yellow]{trace}[/] • connection error • {e}")
                progress.remove_task(task_id)
                return

            link = format_link(rescan_result, key=key)
            formatted_link = f"[medium_purple]{link}[/]"
            final_output = f"[yellow]{shorten_name(trace.name)}[/] • {formatted_link}"

            if open_browser:
                open_link(link)

            progress.update(
                task_id=task_id,
                description=f"Waiting for full report for [yellow]{shorten_name(trace.name)}[/]",
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
            except SandboxException as e:
                console.error(f"{final_output} • {e}")
                progress.remove_task(task_id)
                return

            rescan_result = awaited_report

        # write report.json
        save_report(out_dir, rescan_result)

        # get full report?
        if not (long_report := rescan_result.get_long_report()):
            console.error(f"{final_output} • full report not available")
            progress.remove_task(task_id)
            return

        progress.update(task_id=task_id, description="Downloading results...")

        await download(
            long_report,
            sandbox,
            out_dir,
            replace(download_options, logs=True),
        )

        console.done(final_output)
        progress.remove_task(task_id)

        if unpack:
            await asyncio.to_thread(Unpack.run_unpack, out_dir)

    async def wrapper(trace: Path, out_dir: Path, idx: str) -> None:
        try:
            drakvuf_trace, tcpdump_pcap = load_trace(trace)
        except ScanError as e:
            console.error(str(e))
            return

        await process_trace(drakvuf_trace, tcpdump_pcap, trace, out_dir, idx)

    console.info(f"Using key: name={key.name} max_workers={key.max_workers}")

    tasks: list[Coroutine[Any, Any, None]] = []
    async with Sandbox(key=key) as sandbox:
        with progress:
            sandbox_options = await _prepare_rescan_options(
                sandbox=sandbox,
                progress=progress,
                rules_dir=rules_dir,
                is_local=is_local,
            )
            sandbox_arguments = SandboxArguments(
                type=ScanType.RE_SCAN,
                sandbox_key_name=key.name,
                sandbox_options=sandbox_options.sandbox,
            )

            total = len(traces)
            for i, trace in enumerate(traces):
                # use zip filename for nicer output dirs, fall back to "rescan" / "rescan_N"
                name = trace.stem if trace.suffix == ".zip" else ("rescan" if total == 1 else f"rescan_{i + 1}")
                local_out_dir = out_dir / name
                local_out_dir.mkdir(parents=True, exist_ok=True)
                save_scan_arguments(local_out_dir, sandbox_arguments)
                tasks.append(wrapper(trace, local_out_dir, f"{i + 1}/{total}"))

            await asyncio.gather(*tasks)
