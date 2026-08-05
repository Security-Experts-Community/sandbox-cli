import asyncio
from collections.abc import Coroutine
from dataclasses import replace
from pathlib import Path
from typing import Any

import aiohttp
import aiohttp.client_exceptions
from ptsandbox import Sandbox
from ptsandbox.exceptions import (
    SandboxException,
    SandboxUploadException,
    SandboxWaitTimeoutException,
)
from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxOptions

from sandbox_cli.console import console
from sandbox_cli.core.browser import open_link
from sandbox_cli.core.config import VMImage, settings
from sandbox_cli.core.sandbox import format_link, get_key_by_name
from sandbox_cli.core.scan import (
    SandboxArguments,
    ScanType,
    save_report,
    save_scan_arguments,
)
from sandbox_cli.services.downloader import DownloadOptions, download
from sandbox_cli.services.scanner.compile import compile_rules
from sandbox_cli.services.scanner.images import fetch_available_images, resolve_scan_images
from sandbox_cli.services.scanner.tasks import build_scan_tasks
from sandbox_cli.services.scanner.uploads import gather_uploads, upload_dll_hooks, upload_file, upload_rules
from sandbox_cli.services.scanner.utils import compute_wait_time, shorten_name
from sandbox_cli.services.unpack import Unpack


async def _prepare_scan_options(
    sandbox: Sandbox,
    scan_images: set[VMImage | str],
    rules_dir: Path | None,
    is_local: bool,
    analysis_duration: int,
    syscall_hooks: Path | None,
    dll_hooks_dir: Path | None,
    custom_command: str | None,
) -> tuple[SandboxBaseScanTaskRequest.Options, set[VMImage | str]]:
    # fetch_available_images and rule compilation are independent — run
    # them concurrently to avoid sequential round-trips.
    images_task = asyncio.create_task(fetch_available_images(sandbox))
    rules_task = asyncio.create_task(compile_rules(rules_dir, is_local))

    try:
        available_images = await images_task
    except BaseException:
        rules_task.cancel()
        raise
    images, sandbox_image = resolve_scan_images(available_images, scan_images)

    sandbox_options = SandboxBaseScanTaskRequest.Options(
        analysis_depth=2,
        passwords_for_unpack=settings.passwords,
        sandbox=SandboxOptions(
            image_id=sandbox_image.value if isinstance(sandbox_image, VMImage) else sandbox_image,
            analysis_duration=analysis_duration,
        ),
    )

    # enable default debug options
    sandbox_options.sandbox.debug_options["save_debug_files"] = True
    sandbox_options.sandbox.debug_options["extract_crashdumps"] = True

    # Collect independent uploads to run concurrently.
    uploads: list[tuple[str, Coroutine[Any, Any, str]]] = []
    compiled_rules = await rules_task
    if compiled_rules:
        uploads.append(("rules_url", upload_rules(sandbox, compiled_rules)))
    if syscall_hooks:
        uploads.append(("custom_syscall_hooks", upload_file(sandbox, syscall_hooks, label="Upload syscall hooks")))
    if dll_hooks_dir:
        uploads.append(("custom_dll_hooks", upload_dll_hooks(sandbox, dll_hooks_dir)))

    await gather_uploads(uploads, sandbox_options.sandbox.debug_options)

    if custom_command:
        console.info(f"Using custom command: {custom_command}")
        sandbox_options.sandbox.custom_command = custom_command

    return (sandbox_options, images)


async def scan_internal(
    *,  # keyword-only args
    files: list[Path],
    scan_images: set[VMImage | str],
    rules_dir: Path | None,
    out_dir: Path,
    key_name: str,
    is_local: bool,
    analysis_duration: int,
    syscall_hooks: Path | None,
    dll_hooks_dir: Path | None,
    custom_command: str | None,
    fake_name: str | None,
    unpack: bool,
    upload_timeout: int,
    download_options: DownloadOptions,
    open_browser: bool,
) -> None:
    key = get_key_by_name(key_name)
    sandbox_sem = asyncio.Semaphore(value=key.max_workers)

    async def process_file(
        sandbox_options: SandboxBaseScanTaskRequest.Options,
        file_path: Path,
        out_dir: Path,
        idx: str,
    ) -> None:
        idx = f"[cyan]{idx}[/]"
        async with sandbox_sem:
            console.info(f"{idx} Scanning [yellow]{shorten_name(file_path.name)}[/]. Output: {out_dir}")
            wait_time = compute_wait_time(sandbox_options.sandbox.analysis_duration)

            try:
                scan_result = await sandbox.create_scan(
                    file_path,
                    file_name=fake_name or file_path.name,
                    options=sandbox_options,
                    rules=None,  # we handle rules in sb_options, not inside library
                    read_timeout=wait_time,
                    upload_timeout=upload_timeout,
                    async_result=True,
                )
            except SandboxUploadException as e:
                console.error(f"{idx} Upload error for {shorten_name(file_path.name)}: {e}")
                return
            except aiohttp.client_exceptions.ClientResponseError as e:
                console.error(f"{idx} {shorten_name(file_path.name)}: {e}")
                return
            except aiohttp.ClientError as e:
                console.error(f"{idx} Connection error for {shorten_name(file_path.name)}: {e}")
                return

            link = format_link(scan_result, key=key)
            console.info(
                rf"{idx} [magenta]\[{sandbox_options.sandbox.image_id}][/magenta] Waiting [yellow]{shorten_name(file_path.name)}[/]: {link}"
            )

            if open_browser:
                open_link(link)

            try:
                awaited_report = await sandbox.wait_for_report(scan_result, wait_time)
            except SandboxWaitTimeoutException:
                console.error(f"{idx} Timeout while waiting for {shorten_name(file_path.name)}")
                return
            except SandboxException as e:
                console.error(f"{idx} {shorten_name(file_path.name)}: {e}")
                return

            if not awaited_report:
                console.error(f"{idx} Scan [yellow]{shorten_name(file_path.name)}[/] failed: {scan_result=}")
                return
            scan_result = awaited_report

        # write report.json
        save_report(out_dir, scan_result)

        long_report = scan_result.get_long_report()
        if not long_report:
            console.error("Can't get full report")
            return

        await download(
            long_report,
            sandbox,
            out_dir,
            replace(download_options, video=True, logs=True),
        )
        console.info(
            rf"\[[magenta]{sandbox_options.sandbox.image_id}[/magenta]] Scan [yellow]{shorten_name(file_path.name)}[/] completed. {link}"
        )

        if unpack:
            await asyncio.to_thread(Unpack.run_unpack, out_dir)

    async def wrapper(
        sandbox_options: SandboxBaseScanTaskRequest.Options,
        file_path: Path,
        out_dir: Path,
        idx: str,
    ) -> None:
        sandbox_arguments = SandboxArguments(
            type=ScanType.SCAN,
            sandbox_key_name=key.name,
            sandbox_options=sandbox_options.sandbox,
        )
        save_scan_arguments(out_dir, sandbox_arguments)
        await process_file(sandbox_options, file_path, out_dir, idx)

    console.info(f"Using key: name={key.name} max_workers={key.max_workers}")

    async with Sandbox(key=key) as sandbox:
        sandbox_options, images = await _prepare_scan_options(
            sandbox=sandbox,
            scan_images=scan_images,
            rules_dir=rules_dir,
            is_local=is_local,
            analysis_duration=analysis_duration,
            syscall_hooks=syscall_hooks,
            dll_hooks_dir=dll_hooks_dir,
            custom_command=custom_command,
        )
        tasks = build_scan_tasks(
            wrapper=wrapper,
            sandbox_options=sandbox_options,
            files=files,
            images=images,
            out_dir=out_dir,
            set_image_id=lambda opts, img: setattr(opts.sandbox, "image_id", img),
        )
        await asyncio.gather(*tasks)
