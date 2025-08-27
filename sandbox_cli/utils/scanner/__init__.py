import asyncio
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import aiofiles
from ptsandbox import Sandbox
from ptsandbox.models import SandboxBaseScanTaskRequest, SandboxKey, SandboxOptions

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


async def _get_compiled_rules(rules_dir: Path | None, is_local: bool) -> bytes | None:
    if not rules_dir:
        return None

    text = "Compiling rules locally" if is_local else f"Compiling rules on the remote: {settings.sandbox[0].host}"
    console.info(text)

    return await compile_rules_internal(rules_dir=rules_dir, is_local=is_local)


async def _prepare_scan_options(
    scan_images: set[VMImage],
    rules_dir: Path | None,
    sandbox_key: SandboxKey,
    is_local: bool,
    analysis_duration: int,
    syscall_hooks: Path | None,
    dll_hooks_dir: Path | None,
    custom_command: str | None,
) -> tuple[Sandbox, SandboxBaseScanTaskRequest.Options, set[VMImage | str]]:
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
    sandbox_image = VMImage.WIN10_1803_X64
    for image in scan_images:
        match image:
            case VMImage.LINUX:
                sandbox_image = VMImage.UBUNTU_JAMMY_X64
                images = available_images & settings.linux_images
                if len(images) == 0:
                    console.error("Sandbox doesn't support linux images")
                    sys.exit(1)

                console.info(f"Scanning on: [cyan]{', '.join(images)}[/]")
            case VMImage.WINDOWS:
                sandbox_image = VMImage.WIN10_1803_X64
                images = available_images & settings.windows_images

                if len(images) == 0:
                    console.error("Sandbox doesn't support windows images")
                    sys.exit(1)

                console.info(f"Scanning on: [cyan]{', '.join(images)}[/]")
            case _:
                if image not in available_images:
                    console.error(f"Sandbox doesn't support {image}.")
                    console.info(f"Available: [turquoise2]{', '.join(available_images)}[/]")
                    sys.exit(1)

                images.add(image)
                sandbox_image = image

    sandbox_options = SandboxBaseScanTaskRequest.Options(
        analysis_depth=2,
        passwords_for_unpack=settings.passwords,
        sandbox=SandboxOptions(
            image_id=sandbox_image.value if isinstance(sandbox_image, VMImage) else sandbox_image,
            analysis_duration=analysis_duration,
        ),
    )

    # some enabled options by default
    # All debug options available in library
    sandbox_options.sandbox.debug_options["save_debug_files"] = True
    sandbox_options.sandbox.debug_options["extract_crashdumps"] = True

    # process custom options
    compiled_rules = await _get_compiled_rules(rules_dir=rules_dir, is_local=is_local)

    if compiled_rules:
        rules_uri = (await sandbox.api.upload_file(compiled_rules)).data.file_uri
        sandbox_options.sandbox.debug_options["rules_url"] = rules_uri

    if syscall_hooks:
        console.info(f"Uploading syscall hooks by {syscall_hooks}")
        async with aiofiles.open(syscall_hooks, mode="rb") as fd:
            data = await fd.read()

        syscall_hooks_uri = (await sandbox.api.upload_file(data)).data.file_uri
        sandbox_options.sandbox.debug_options["custom_syscall_hooks"] = syscall_hooks_uri

    if dll_hooks_dir:
        console.info(f"Uploading dll hooks from directory {dll_hooks_dir}")
        data = merge_dll_hooks(Path(dll_hooks_dir))
        dll_hooks_uri = (await sandbox.api.upload_file(data)).data.file_uri
        sandbox_options.sandbox.debug_options["custom_dll_hooks"] = dll_hooks_uri

    if custom_command:
        console.info(f"Using custom command: {custom_command}")
        sandbox_options.sandbox.custom_command = custom_command

    # add here some commands if new options available

    return (sandbox, sandbox_options, images)


async def scan_internal(
    *,  # no not keyword args
    files: list[Path],
    scan_images: set[VMImage],
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
    all: bool,
    debug: bool,
    artifacts: bool,
    download_files: bool,
    crashdumps: bool,
    procdumps: bool,
    decompress: bool,
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
        idx = f"[cyan]{idx}[/]"  # make fancy
        async with sandbox_sem:
            console.info(f"{idx} Scanning [yellow]{file_path.name}[/]. Output: {out_dir}")
            wait_time = sandbox_options.sandbox.analysis_duration * 4 + (
                300 if sandbox_options.sandbox.analysis_duration < 80 else 120
            )

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
            except TimeoutError:
                console.error(f"{idx} Timeout for {file_path.name}")
                return

            console.info(
                rf"{idx} [magenta]\[{sandbox_options.sandbox.image_id}][/magenta] Waiting [yellow]{file_path.name}[/]: {format_link(scan_result, key=key)}"
            )

            if open_browser:
                open_link(format_link(scan_result, key=key))

            awaited_report = await sandbox.wait_for_report(scan_result, wait_time)
            if not awaited_report:
                console.error(f"{idx} Scan [yellow]{file_path.name}[/] failed: {scan_result=}")
                return
            scan_result = awaited_report

        # write report.json
        (out_dir / settings.report_name).write_text(scan_result.model_dump_json(indent=4), encoding="utf-8")

        long_report = scan_result.get_long_report()
        if not long_report:
            console.error("Can't get full report")
            return

        await download(
            long_report,
            sandbox,
            out_dir,
            all=all,
            debug=debug,
            artifacts=artifacts,
            files=download_files,
            crashdumps=crashdumps,
            procdumps=procdumps,
            video=True,
            logs=True,
            decompress=decompress,
        )
        console.info(
            rf"\[[magenta]{sandbox_options.sandbox.image_id}[/magenta]] Scan [yellow]{file_path.name}[/] completed. {format_link(scan_result, key=key)}"
        )

        if unpack:
            Unpack(out_dir).run()

    async def wrapper(
        sandbox_options: SandboxBaseScanTaskRequest.Options,
        file_path: Path,
        out_dir: Path,
        idx: str,
    ) -> None:
        sandbox_arguments = SandboxArguments(
            type=ScanType.SCAN,
            sandbox_key_name=key.name.get_secret_value(),
            sandbox_options=sandbox_options.sandbox,
        )
        save_scan_arguments(out_dir, sandbox_arguments)

        # try:
        await process_file(sandbox_options, file_path, out_dir, idx)
        # except Exception as ex:
        #     console.log(f"[cyan]{idx}[/] {file_path} Error: {ex!r}")

    console.info(f"Using key: name={key.name.get_secret_value()} max_workers={key.max_workers}")

    tasks: list[Coroutine[Any, Any, None]] = []
    sandbox, sandbox_options, images = await _prepare_scan_options(
        scan_images,
        rules_dir,
        key,
        is_local,
        analysis_duration,
        syscall_hooks,
        dll_hooks_dir,
        custom_command,
    )
    for i, image_id in enumerate(images):
        options = sandbox_options.model_copy(deep=True)
        options.sandbox.image_id = image_id

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

    # handle case with specific image
    if not images:
        if len(files) == 1:
            tasks.append(wrapper(sandbox_options, files[0], out_dir, "1/1"))
        else:
            for i, file in enumerate(files):
                local_out_dir = out_dir / f"{file.stem}"
                local_out_dir.mkdir(parents=True, exist_ok=True)
                tasks.append(wrapper(sandbox_options, file, local_out_dir, f"{i + 1}/{len(files)}"))

    await asyncio.gather(*tasks)
    await sandbox.api.session.close()
