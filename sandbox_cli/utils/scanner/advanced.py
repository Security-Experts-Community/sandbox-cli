import asyncio
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import aiofiles
import aiohttp
import aiohttp.client_exceptions
from ptsandbox import Sandbox, SandboxKey
from ptsandbox.models import (
    SandboxOptionsAdvanced,
    SandboxUploadException,
    SandboxWaitTimeoutException,
    VNCMode,
)
from rich.markup import escape
from rich.progress import (
    Progress,
    SpinnerColumn,
    Task,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)

from sandbox_cli.console import console
from sandbox_cli.internal.config import VMImage, settings
from sandbox_cli.internal.helpers import (
    format_link,
    get_key_by_name,
    open_link,
    save_scan_arguments,
)
from sandbox_cli.models.sandbox_arguments import SandboxArguments, ScanType
from sandbox_cli.utils.compiler import compile_rules_internal
from sandbox_cli.utils.downloader import download
from sandbox_cli.utils.merge_dll_hooks import merge_dll_hooks
from sandbox_cli.utils.unpack import Unpack

DELIMETER = "\n"


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


def get_elapsed_time(task: Task) -> str:
    hours = int(task.elapsed) // 3600
    minutes = (int(task.elapsed) % 3600) // 60
    seconds = int(task.elapsed) % 60
    return f"[yellow]{hours}:{minutes:02d}:{seconds:02d}[/]"


async def _prepare_sandbox_new_scan(
    progress: Progress,
    scan_images: set[VMImage | str],
    rules_dir: Path | None,
    sandbox_key: SandboxKey,
    is_local: bool,
    analysis_duration: int,
    syscall_hooks: Path | None,
    dll_hooks_dir: Path | None,
    custom_command: str | None,
    no_procdumps_on_finish: bool,
    bootkitmon: bool,
    bootkitmon_duration: int,
    mitm_disabled: bool,
    disable_clicker: bool,
    skip_sample_run: bool,
    vnc_mode: VNCMode,
    outbound_connections: list[str] | None,
) -> tuple[Sandbox, SandboxOptionsAdvanced, set[VMImage | str]]:
    sandbox = Sandbox(key=sandbox_key)

    # detect correct image
    available_images: set[VMImage | str] = set()
    for check_image in (await sandbox.api.get_images()).data:
        if not check_image.image_id:
            continue

        try:
            available_images.add(VMImage(check_image.image_id))
        except ValueError:
            # maybe it is custom image?
            available_images.add(check_image.image_id)

    images: set[VMImage | str] = set()
    sandbox_image: VMImage | str = settings.default_image
    for image in scan_images:
        match image:
            case VMImage.LINUX:
                sandbox_image = VMImage.UBUNTU_JAMMY_X64
                images = available_images & settings.linux_images
                if len(images) == 0:
                    console.log("Sandbox doesn't support linux images", style="bold red")
                    sys.exit(1)

                console.info(f"Scanning on: [turquoise2]{', '.join(images)}[/]")
            case VMImage.WINDOWS:
                sandbox_image = VMImage.WIN10_1803_X64
                images = available_images & settings.windows_images

                if len(images) == 0:
                    console.log("Sandbox doesn't support windows images", style="bold red")
                    sys.exit(1)

                console.info(f"Scanning on: [turquoise2]{', '.join(images)}[/]")
            case _:
                if image not in available_images:
                    console.error(f"Sandbox doesn't support {image}.")
                    console.info(f"Available: [turquoise2]{', '.join(available_images)}[/]")
                    sys.exit(1)

                images.add(image)
                sandbox_image = image

    sandbox_options = SandboxOptionsAdvanced(
        image_id=sandbox_image.value if isinstance(sandbox_image, VMImage) else sandbox_image,
        analysis_duration=analysis_duration,
    )

    # some enabled options by default
    # all debug options available in library
    sandbox_options.debug_options["save_debug_files"] = True
    sandbox_options.debug_options["extract_crashdumps"] = True

    # process custom options
    compiled_rules = await _get_compiled_rules(rules_dir=rules_dir, is_local=is_local, progress=progress)

    if compiled_rules:
        rules_uri = (await sandbox.api.upload_file(compiled_rules)).data.file_uri
        sandbox_options.debug_options["rules_url"] = rules_uri

    if syscall_hooks:
        progress.console.print(f"{console.INFO} Upload syscall hooks: {syscall_hooks}")
        async with aiofiles.open(syscall_hooks, mode="rb") as fd:
            data = await fd.read()
        syscall_hooks_uri = (await sandbox.api.upload_file(data)).data.file_uri
        sandbox_options.debug_options["custom_syscall_hooks"] = syscall_hooks_uri

    if dll_hooks_dir:
        progress.console.print(f"{console.INFO} Upload dll hooks: {dll_hooks_dir}")
        data = merge_dll_hooks(Path(dll_hooks_dir))
        dll_hooks_uri = (await sandbox.api.upload_file(data)).data.file_uri
        sandbox_options.debug_options["custom_dll_hooks"] = dll_hooks_uri

    if custom_command:
        progress.console.print(f"{console.INFO} Commandline: {custom_command}")
        sandbox_options.custom_command = custom_command

    # add extra options
    sandbox_options.debug_options["allowed_outbound_connections"] = outbound_connections or []
    sandbox_options.procdump_new_processes_on_finish = not no_procdumps_on_finish
    sandbox_options.bootkitmon = bootkitmon
    sandbox_options.analysis_duration_bootkitmon = bootkitmon_duration
    sandbox_options.mitm_enabled = not mitm_disabled
    sandbox_options.disable_clicker = disable_clicker
    sandbox_options.skip_sample_run = skip_sample_run
    sandbox_options.vnc_mode = vnc_mode

    # add here some commands if new options available

    return (sandbox, sandbox_options, images)


async def scan_internal_advanced(
    *,  # no not keyword args
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
    priority: int,
    no_procdumps_on_finish: bool,
    bootkitmon: bool,
    bootkitmon_duration: int,
    mitm_disabled: bool,
    disable_clicker: bool,
    skip_sample_run: bool,
    vnc_mode: VNCMode,
    extra_files: list[Path] | None,
    upload_timeout: int,
    wait_timeout: int | None,
    all: bool,
    debug: bool,
    artifacts: bool,
    download_files: bool,
    crashdumps: bool,
    procdumps: bool,
    decompress: bool,
    open_browser: bool,
    outbound_connections: list[str] | None,
) -> None:
    key = get_key_by_name(key_name)
    sandbox_sem = asyncio.Semaphore(value=key.max_workers)
    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.fields[idx]}"),
        "•",
        TextColumn("{task.fields[image]}"),
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
    max_image_length = 0

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
            # because progress.tasks is .values() from dict, not an actual list
            task = next(t for t in progress.tasks if t.id == task_id)

            wait_time = sandbox_options.analysis_duration * 4 + (300 if sandbox_options.analysis_duration < 80 else 120)
            if wait_timeout is not None:
                wait_time = wait_timeout

            try:
                scan_result = await sandbox.create_advanced_scan(
                    file_path,
                    file_name=fake_name or file_path.name,
                    extra_files=extra_files,
                    async_result=True,
                    priority=priority,
                    upload_timeout=upload_timeout,
                    sandbox=sandbox_options,
                )
            except SandboxUploadException as e:
                console.error(
                    f"{image_string} • [yellow]{file_path.name}[/] • an error occurred when uploading a file to the server • {e}"
                )
                progress.remove_task(task_id)
                return
            except aiohttp.client_exceptions.ClientResponseError as e:
                console.error(f"{image_string} • [yellow]{file_path.name}[/] • {e} • {get_elapsed_time(task)}")
                progress.remove_task(task_id)
                return

            formatted_link = f"[medium_purple]{format_link(scan_result, key=key)}[/]"
            final_output = f"{image_string} • [yellow]{file_path.name}[/] • {formatted_link}"

            if open_browser:
                open_link(format_link(scan_result, key=key))

            progress.update(
                task_id=task_id,
                description=f"Waiting [yellow]{file_path.name}[/]",
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

            scan_result = awaited_report

        # write report.json
        (out_dir / settings.report_name).write_text(scan_result.model_dump_json(indent=4), encoding="utf-8")

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
                all=all,
                artifacts=artifacts,
                crashdumps=crashdumps,
                debug=debug,
                decompress=decompress,
                files=download_files,
                logs=True,  # by default download logs
                procdumps=procdumps,
                progress=progress,
                video=True,  # by default download video
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
            Unpack(out_dir).run()

    async def wrapper(
        sandbox_options: SandboxOptionsAdvanced,
        file_path: Path,
        out_dir: Path,
        idx: str,
    ) -> None:
        sandbox_arguments = SandboxArguments(
            type=ScanType.SCAN_NEW,
            sandbox_key_name=key.name.get_secret_value(),
            sandbox_options=sandbox_options,
        )
        save_scan_arguments(out_dir, sandbox_arguments)

        # try:
        await process_file(sandbox_options, file_path, out_dir, idx)
        # except Exception as ex:
        #     console.log(f"[cyan]{idx}[/] {file_path} Error: {ex!r}")

    console.info(f"Using key: name={key.name.get_secret_value()} max_workers={key.max_workers}")

    tasks: list[Coroutine[Any, Any, None]] = []
    with progress:
        sandbox, sandbox_options, images = await _prepare_sandbox_new_scan(
            progress,
            scan_images,
            rules_dir,
            key,
            is_local,
            analysis_duration,
            syscall_hooks,
            dll_hooks_dir,
            custom_command,
            no_procdumps_on_finish,
            bootkitmon,
            bootkitmon_duration,
            mitm_disabled,
            disable_clicker,
            skip_sample_run,
            vnc_mode,
            outbound_connections,
        )
        max_image_length = max(len(x) for x in images)
        for i, image_id in enumerate(images):
            options = sandbox_options.model_copy(deep=True)
            options.image_id = image_id

            if len(files) == 1:
                local_out_dir = out_dir / f"{image_id}"
                local_out_dir.mkdir(parents=True, exist_ok=True)
                tasks.append(wrapper(options, files[0], local_out_dir, f"{i + 1}/{len(images)}"))
            else:
                for j, file in enumerate(files):
                    local_out_dir = out_dir / f"{file.stem}" / f"{image_id}"
                    local_out_dir.mkdir(parents=True, exist_ok=True)
                    idx = f"{(i + 1) * (j + 1)}/{len(files) * len(images)}"
                    tasks.append(wrapper(options, file, local_out_dir, idx))

        await asyncio.gather(*tasks)
        await sandbox.api.session.close()

    # clear last line
    sys.stdout.write("\033[F\033[K")
