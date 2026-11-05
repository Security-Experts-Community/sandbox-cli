"""
Preparation shared by all scan commands: rules, images and hook uploads.
"""

from __future__ import annotations

import asyncio
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from sandbox_cli.console import console
from sandbox_cli.core.config import DEFAULT_IMAGE, VMImage
from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.services.compiler import get_compiler
from sandbox_cli.services.compiler.abc import COMPILED_FILES
from sandbox_cli.services.scanner.compile import compile_rules
from sandbox_cli.services.scanner.hooks import merge_dll_hooks
from sandbox_cli.services.scanner.images import fetch_available_images, resolve_scan_images
from sandbox_cli.services.scanner.uploads import UploadKey, upload_bytes

if TYPE_CHECKING:
    from ptsandbox import Sandbox

__all__ = ["HookFiles", "PreparedScan", "check_compiled_rules", "prepare_scan"]


@dataclass(frozen=True, slots=True)
class HookFiles:
    """
    Optional files uploaded once and referenced from ``debug_options``.
    """

    syscall_hooks: Path | None = None
    dll_hooks_dir: Path | None = None
    unimon_hooks: Path | None = None
    fileextractor_excludes: Path | None = None
    procdump_excludes: Path | None = None


@dataclass(slots=True)
class PreparedScan:
    images: list[VMImage | str]
    """Concrete images to scan on."""
    default_image: VMImage | str
    """Image id for the base sandbox options."""
    uploads: dict[str, dict[UploadKey, str]] = field(default_factory=dict)
    """Per key name: ``debug_options`` entries pointing at the files uploaded to that sandbox."""


async def _first_error(*tasks: asyncio.Task[Any]) -> None:
    """
    Wait for ``tasks``; on the first failure cancel the rest and raise that error.
    """
    if not tasks:
        return
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    failed = next((t for t in done if not t.cancelled() and t.exception() is not None), None)
    if failed is None:
        return
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    raise failed.exception()  # type: ignore[misc]


def check_compiled_rules(archive: Path) -> None:
    """
    Ensure ``archive`` is a tar archive with the compiled rules inside.

    The sandbox silently ignores an archive it can't unpack, so a wrong file would
    mean a scan with the default rules instead of the given ones.
    """
    try:
        with tarfile.open(archive) as tar:
            members = {PurePosixPath(member.name).name for member in tar.getmembers() if member.isfile()}
    except OSError as e:
        raise ScanError(f"Can't read {archive}: {e}") from e
    except tarfile.TarError as e:
        raise ScanError(f"{archive} is not a tar archive with compiled rules") from e

    if missing := [name for name in COMPILED_FILES if name not in members]:
        raise ScanError(f"{archive} is not an archive with compiled rules: no {', '.join(missing)} inside")


def _check_image_everywhere(available: Mapping[str, set[VMImage | str]], scan_images: set[VMImage | str]) -> None:
    """
    Name the key that lacks a requested image, rather than report the common images of all keys.
    """
    for image in scan_images:
        if image in (VMImage.LINUX, VMImage.WINDOWS):
            continue
        for name, images in available.items():
            if image not in images:
                console.info(f"Available on {name}: [turquoise2]{', '.join(sorted(map(str, images)))}[/]")
                raise ScanError(f'Sandbox "{name}" doesn\'t support {image}.')


async def _read_hook_files(hooks: HookFiles) -> dict[UploadKey, bytes]:
    files: dict[UploadKey, tuple[str, Path | None]] = {
        "custom_syscall_hooks": ("Upload syscall hooks", hooks.syscall_hooks),
        "custom_unimon_hooks": ("Upload unimon hooks", hooks.unimon_hooks),
        "custom_fileextractor_exclude": ("Upload fileextractor excludes", hooks.fileextractor_excludes),
        "custom_procdump_exclude": ("Upload procdump excludes", hooks.procdump_excludes),
    }
    payloads: dict[UploadKey, bytes] = {}
    for key, (label, path) in files.items():
        if path is not None:
            console.info(f"{label}: {path}")
            payloads[key] = await asyncio.to_thread(path.read_bytes)
    if hooks.dll_hooks_dir:
        console.info(f"Upload dll hooks: {hooks.dll_hooks_dir}")
        payloads["custom_dll_hooks"] = await asyncio.to_thread(merge_dll_hooks, hooks.dll_hooks_dir)
    return payloads


async def _upload_all(sandbox: Sandbox, payloads: Mapping[UploadKey, bytes]) -> dict[UploadKey, str]:
    uris = await asyncio.gather(*(upload_bytes(sandbox, data) for data in payloads.values()))
    return dict(zip(payloads, uris, strict=True))


async def prepare_scan(
    sandboxes: Mapping[str, Sandbox],
    *,
    rules: Path | None,
    is_local: bool,
    scan_images: set[VMImage | str] | None = None,
    hooks: HookFiles | None = None,
) -> PreparedScan:
    """
    Resolve images, compile rules and upload hook files to every sandbox (keyed by key name).

    ``rules`` is a folder with raw rules, which is compiled once here, or an archive with
    already compiled rules, which is checked and uploaded as is. Fetches the images while
    the rules compile, then uploads everything to all sandboxes in parallel. Only images
    every sandbox has are used. ``scan_images=None`` skips image resolution (re-scan
    doesn't need it).
    """
    ready_rules = rules if rules is not None and rules.is_file() else None
    if ready_rules is not None:
        await asyncio.to_thread(check_compiled_rules, ready_rules)

    compiler = get_compiler(is_local=is_local) if rules is not None and ready_rules is None else None
    rules_task = (
        asyncio.create_task(compile_rules(rules, compiler, is_local=is_local))
        if rules is not None and compiler is not None
        else None
    )
    images_tasks = (
        {name: asyncio.create_task(fetch_available_images(sandbox)) for name, sandbox in sandboxes.items()}
        if scan_images is not None
        else {}
    )
    await _first_error(*(t for t in (rules_task, *images_tasks.values()) if t is not None))
    compiled_rules = rules_task.result() if rules_task is not None else None

    images: list[VMImage | str] = []
    default_image: VMImage | str = DEFAULT_IMAGE
    if scan_images is not None:
        available = {name: task.result() for name, task in images_tasks.items()}
        if len(available) > 1:
            _check_image_everywhere(available, scan_images)
        common = set.intersection(*available.values()) if available else set()
        resolved, default_image = resolve_scan_images(common, scan_images)
        images = sorted(resolved, key=str) or [default_image]

    payloads = await _read_hook_files(hooks or HookFiles())
    if ready_rules is not None:
        console.info(f"Upload compiled rules: {ready_rules}")
        payloads["rules_url"] = await asyncio.to_thread(ready_rules.read_bytes)
    elif compiled_rules:
        payloads["rules_url"] = compiled_rules

    uploads = await asyncio.gather(*(_upload_all(sandbox, payloads) for sandbox in sandboxes.values()))
    return PreparedScan(
        images=images,
        default_image=default_image,
        uploads=dict(zip(sandboxes, uploads, strict=True)),
    )
