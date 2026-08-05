from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp
import aiohttp.client_exceptions
from ptsandbox import Sandbox
from ptsandbox.exceptions import (
    SandboxException,
    SandboxUploadException,
    SandboxWaitTimeoutException,
)
from ptsandbox.models import SandboxOptionsAdvanced
from rich.markup import escape

from sandbox_cli.console import console
from sandbox_cli.core.browser import open_link
from sandbox_cli.core.config import VMImage
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
from sandbox_cli.services.scanner.images import fetch_available_images, resolve_scan_images
from sandbox_cli.services.scanner.tasks import build_scan_tasks
from sandbox_cli.services.scanner.uploads import gather_uploads, upload_dll_hooks, upload_file, upload_rules
from sandbox_cli.services.scanner.utils import compute_wait_time, get_elapsed_time, shorten_name
from sandbox_cli.services.unpack import Unpack

if TYPE_CHECKING:
    from ptsandbox.models import VNCMode
    from rich.progress import Progress

SAFE_SUFFIXES = "_~"


async def _prepare_sandbox_new_scan(
    sandbox: Sandbox,
    progress: Progress,
    scan_images: set[VMImage | str],
    rules_dir: Path | None,
    is_local: bool,
    analysis_duration: int,
    syscall_hooks: Path | None,
    unimon_hooks: Path | None,
    dll_hooks_dir: Path | None,
    filextractor_excludes: Path | None,
    custom_command: str | None,
    no_procdumps_on_finish: bool,
    disable_lightweight_dumps: bool,
    bootkitmon: bool,
    bootkitmon_duration: int,
    mitm_disabled: bool,
    disable_clicker: bool,
    skip_sample_run: bool,
    vnc_mode: VNCMode,
    outbound_connections: list[str] | None,
    file_type_as_ext: bool | None,
) -> tuple[SandboxOptionsAdvanced, set[VMImage | str]]:
    # fetch_available_images and rule compilation are independent — run
    # them concurrently to avoid sequential round-trips.
    images_task = asyncio.create_task(fetch_available_images(sandbox))
    rules_task = asyncio.create_task(compile_rules(rules_dir, is_local, progress=progress))

    try:
        available_images = await images_task
    except BaseException:
        rules_task.cancel()
        raise
    images, sandbox_image = resolve_scan_images(available_images, scan_images)

    sandbox_options = SandboxOptionsAdvanced(
        image_id=sandbox_image.value if isinstance(sandbox_image, VMImage) else sandbox_image,
        analysis_duration=analysis_duration,
    )

    # enable default debug options
    # all debug options available in library
    sandbox_options.debug_options["save_debug_files"] = True
    sandbox_options.debug_options["extract_crashdumps"] = True
    # by default we want to use lightweight memory dumps
    sandbox_options.debug_options["procdump_lightweight_mode"] = not disable_lightweight_dumps

    # Collect independent uploads to run concurrently.
    uploads: list[tuple[str, Coroutine[Any, Any, str]]] = []
    compiled_rules = await rules_task
    if compiled_rules:
        uploads.append(
            (
                "rules_url",
                upload_rules(
                    sandbox,
                    compiled_rules,
                ),
            ),
        )
    if syscall_hooks:
        uploads.append(
            (
                "custom_syscall_hooks",
                upload_file(
                    sandbox,
                    syscall_hooks,
                    label="Upload syscall hooks",
                    progress=progress,
                ),
            )
        )
    if unimon_hooks:
        uploads.append(
            (
                "custom_unimon_hooks",
                upload_file(
                    sandbox,
                    unimon_hooks,
                    label="Upload unimon hooks",
                    progress=progress,
                ),
            )
        )
    if dll_hooks_dir:
        uploads.append(
            (
                "custom_dll_hooks",
                upload_dll_hooks(
                    sandbox,
                    dll_hooks_dir,
                    progress=progress,
                ),
            )
        )
    if filextractor_excludes:
        uploads.append(
            (
                "custom_fileextractor_exclude",
                upload_file(
                    sandbox,
                    filextractor_excludes,
                    label="Upload fileextractor excludes",
                    progress=progress,
                ),
            )
        )

    await gather_uploads(uploads, sandbox_options.debug_options)

    if custom_command:
        progress.console.print(f"{console.INFO} Commandline: {custom_command}")
        sandbox_options.custom_command = custom_command

    if file_type_as_ext is not None:
        progress.console.print(f"{console.INFO} Using magic types from the sandbox")
        sandbox_options.debug_options["file_type_as_ext"] = file_type_as_ext

    # add extra options
    sandbox_options.debug_options["allowed_outbound_connections"] = outbound_connections or []
    sandbox_options.procdump_new_processes_on_finish = not no_procdumps_on_finish
    sandbox_options.bootkitmon = bootkitmon
    sandbox_options.analysis_duration_bootkitmon = bootkitmon_duration
    sandbox_options.mitm_enabled = not mitm_disabled
    sandbox_options.disable_clicker = disable_clicker
    sandbox_options.skip_sample_run = skip_sample_run
    sandbox_options.vnc_mode = vnc_mode

    return (sandbox_options, images)


async def scan_internal_advanced(
    *,  # keyword-only args
    files: list[Path],
    scan_images: set[VMImage | str],
    rules_dir: Path | None,
    out_dir: Path,
    key_name: str,
    is_local: bool,
    analysis_duration: int,
    syscall_hooks: Path | None,
    unimon_hooks: Path | None,
    dll_hooks_dir: Path | None,
    fileextractor_excludes: Path | None,
    custom_command: str | None,
    fake_name: str | None,
    unpack: bool,
    priority: int,
    no_procdumps_on_finish: bool,
    disable_lightweight_dumps: bool,
    bootkitmon: bool,
    bootkitmon_duration: int,
    mitm_disabled: bool,
    disable_clicker: bool,
    skip_sample_run: bool,
    vnc_mode: VNCMode,
    extra_files: list[Path] | None,
    upload_timeout: int,
    wait_timeout: int | None,
    download_options: DownloadOptions,
    open_browser: bool,
    preserve_filename: bool,
    outbound_connections: list[str] | None,
    file_type_as_ext: bool | None,
) -> None:
    key = get_key_by_name(key_name)
    sandbox_sem = asyncio.Semaphore(value=key.max_workers)
    progress = make_scan_progress(with_image=True, disable=True)

    async def process_file(
        sandbox_options: SandboxOptionsAdvanced,
        file_path: Path,
        out_dir: Path,
        idx: str,
    ) -> None:
        idx = f"[turquoise2 bold]{idx}[/]"
        formatted_image = f"{escape(f'[{sandbox_options.image_id}]')}"
        image_string = rf"\[{sandbox_options.image_id}]".ljust(max_image_length + 3)

        async with sandbox_sem:
            task_id = progress.add_task(description="Creating task", idx=idx, image=formatted_image, url="...")
            # cache the task object to avoid O(n) lookup on every status update
            task = next(t for t in progress.tasks if t.id == task_id)

            wait_time = compute_wait_time(sandbox_options.analysis_duration, wait_timeout)

            try:
                guest_filename = file_path.name
                if not preserve_filename:
                    guest_filename = guest_filename.removesuffix(SAFE_SUFFIXES)

                scan_result = await sandbox.create_advanced_scan(
                    file_path,
                    file_name=fake_name or guest_filename,
                    extra_files=extra_files,
                    async_result=True,
                    priority=priority,
                    upload_timeout=upload_timeout,
                    sandbox=sandbox_options,
                )
            except SandboxUploadException as e:
                console.error(
                    f"{image_string} • [yellow]{shorten_name(file_path.name)}[/] • an error occurred when uploading a file to the server • {e}"
                )
                progress.remove_task(task_id)
                return
            except aiohttp.client_exceptions.ClientResponseError as e:
                console.error(
                    f"{image_string} • [yellow]{shorten_name(file_path.name)}[/] • {e} • {get_elapsed_time(task)}"
                )
                progress.remove_task(task_id)
                return
            except aiohttp.ClientError as e:
                console.error(f"{image_string} • [yellow]{shorten_name(file_path.name)}[/] • connection error • {e}")
                progress.remove_task(task_id)
                return

            link = format_link(scan_result, key=key)
            formatted_link = f"[medium_purple]{link}[/]"
            final_output = f"{image_string} • [yellow]{shorten_name(file_path.name)}[/] • {formatted_link}"

            if open_browser:
                open_link(link)

            progress.update(
                task_id=task_id,
                description=f"Waiting [yellow]{shorten_name(file_path.name)}[/]",
                url=formatted_link,
            )
            try:
                if not (awaited_report := await sandbox.wait_for_report(scan_result, wait_time)):
                    console.error(f"{final_output} • scan failed • {get_elapsed_time(task)}")
                    progress.remove_task(task_id)
                    return
            except SandboxWaitTimeoutException:
                console.error(f"{final_output} • got timeout while waiting • {get_elapsed_time(task)}")
                progress.remove_task(task_id)
                return
            except SandboxException as e:
                console.error(f"{final_output} • {e} • {get_elapsed_time(task)}")
                progress.remove_task(task_id)
                return

            scan_result = awaited_report

        # write report.json
        save_report(out_dir, scan_result)

        if not (long_report := scan_result.get_long_report()):
            console.error(f"{final_output} • full report not available • {get_elapsed_time(task)}")
            progress.remove_task(task_id)
            return

        progress.update(task_id=task_id, description="Downloading results...")

        try:
            await download(
                long_report,
                sandbox,
                out_dir,
                replace(download_options, video=True, logs=True),
                progress=progress,
                idx=idx,
                image=formatted_image,
                link=formatted_link,
            )
        except aiohttp.SocketTimeoutError:
            console.error(f"{final_output} • got timeout while downloading results • {get_elapsed_time(task)}")
            progress.remove_task(task_id)
            return

        console.done(f"{final_output} • {get_elapsed_time(task)}")

        progress.remove_task(task_id)

        if unpack:
            await asyncio.to_thread(Unpack.run_unpack, out_dir)

    async def wrapper(
        sandbox_options: SandboxOptionsAdvanced,
        file_path: Path,
        out_dir: Path,
        idx: str,
    ) -> None:
        sandbox_arguments = SandboxArguments(
            type=ScanType.SCAN_NEW,
            sandbox_key_name=key.name,
            sandbox_options=sandbox_options,
        )
        save_scan_arguments(out_dir, sandbox_arguments)
        await process_file(sandbox_options, file_path, out_dir, idx)

    console.info(f"Using key: name={key.name} max_workers={key.max_workers}")

    async with Sandbox(key=key) as sandbox:
        with progress:
            sandbox_options, images = await _prepare_sandbox_new_scan(
                sandbox=sandbox,
                progress=progress,
                scan_images=scan_images,
                rules_dir=rules_dir,
                is_local=is_local,
                analysis_duration=analysis_duration,
                syscall_hooks=syscall_hooks,
                unimon_hooks=unimon_hooks,
                dll_hooks_dir=dll_hooks_dir,
                filextractor_excludes=fileextractor_excludes,
                custom_command=custom_command,
                no_procdumps_on_finish=no_procdumps_on_finish,
                disable_lightweight_dumps=disable_lightweight_dumps,
                bootkitmon=bootkitmon,
                bootkitmon_duration=bootkitmon_duration,
                mitm_disabled=mitm_disabled,
                disable_clicker=disable_clicker,
                skip_sample_run=skip_sample_run,
                vnc_mode=vnc_mode,
                outbound_connections=outbound_connections,
                file_type_as_ext=file_type_as_ext,
            )
            max_image_length = max((len(str(x)) for x in images), default=0)
            tasks = build_scan_tasks(
                wrapper=wrapper,
                sandbox_options=sandbox_options,
                files=files,
                images=images,
                out_dir=out_dir,
                set_image_id=lambda opts, img: setattr(opts, "image_id", img),
            )
            await asyncio.gather(*tasks)
