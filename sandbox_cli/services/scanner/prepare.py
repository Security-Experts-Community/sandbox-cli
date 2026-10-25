"""
Preparation shared by all scan commands: rules, images and hook uploads.
"""

from __future__ import annotations

import asyncio
import tarfile
from collections.abc import Coroutine
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from sandbox_cli.core.config import DEFAULT_IMAGE, VMImage
from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.services.compiler import get_compiler
from sandbox_cli.services.compiler.abc import COMPILED_FILES
from sandbox_cli.services.scanner.compile import compile_rules
from sandbox_cli.services.scanner.images import fetch_available_images, resolve_scan_images
from sandbox_cli.services.scanner.uploads import UploadKey, gather_uploads, upload_bytes, upload_dll_hooks, upload_file

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
    uploads: dict[UploadKey, str] = field(default_factory=dict)
    """``debug_options`` entries pointing at uploaded files."""


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


async def prepare_scan(
    sandbox: Sandbox,
    *,
    rules: Path | None,
    is_local: bool,
    scan_images: set[VMImage | str] | None = None,
    hooks: HookFiles | None = None,
) -> PreparedScan:
    """
    Resolve images, compile rules and upload hook files.

    ``rules`` is a folder with raw rules, which is compiled here, or an archive with
    already compiled rules, which is checked and uploaded as is. Fetches the images while
    the rules compile, then runs all uploads in parallel. ``scan_images=None`` skips image
    resolution (re-scan doesn't need it).
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
    images_task = asyncio.create_task(fetch_available_images(sandbox)) if scan_images is not None else None
    await _first_error(*(t for t in (rules_task, images_task) if t is not None))
    compiled_rules = rules_task.result() if rules_task is not None else None
    available = images_task.result() if images_task is not None else set()

    images: list[VMImage | str] = []
    default_image: VMImage | str = DEFAULT_IMAGE
    if scan_images is not None:
        resolved, default_image = resolve_scan_images(available, scan_images)
        images = sorted(resolved, key=str) or [default_image]

    hooks = hooks or HookFiles()
    uploads: dict[UploadKey, Coroutine[Any, Any, str]] = {}
    if ready_rules is not None:
        uploads["rules_url"] = upload_file(sandbox, ready_rules, label="Upload compiled rules")
    elif compiled_rules:
        uploads["rules_url"] = upload_bytes(sandbox, compiled_rules)
    if hooks.syscall_hooks:
        uploads["custom_syscall_hooks"] = upload_file(sandbox, hooks.syscall_hooks, label="Upload syscall hooks")
    if hooks.unimon_hooks:
        uploads["custom_unimon_hooks"] = upload_file(sandbox, hooks.unimon_hooks, label="Upload unimon hooks")
    if hooks.dll_hooks_dir:
        uploads["custom_dll_hooks"] = upload_dll_hooks(sandbox, hooks.dll_hooks_dir)
    if hooks.fileextractor_excludes:
        uploads["custom_fileextractor_exclude"] = upload_file(
            sandbox, hooks.fileextractor_excludes, label="Upload fileextractor excludes"
        )
    if hooks.procdump_excludes:
        uploads["custom_procdump_exclude"] = upload_file(
            sandbox, hooks.procdump_excludes, label="Upload procdump excludes"
        )

    return PreparedScan(images=images, default_image=default_image, uploads=await gather_uploads(uploads))
