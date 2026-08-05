from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiofiles
from rich.progress import Progress

from sandbox_cli.console import console
from sandbox_cli.services.scanner.hooks import merge_dll_hooks

if TYPE_CHECKING:
    from ptsandbox import Sandbox

__all__ = [
    "gather_uploads",
    "upload_dll_hooks",
    "upload_file",
    "upload_rules",
]


def _log(message: str, progress: Progress | None = None) -> None:
    """
    Print ``message`` via progress console (if active) or plain console.
    """
    if progress is not None:
        progress.console.print(f"{console.INFO} {message}")
    else:
        console.info(message)


async def upload_file(
    sandbox: Sandbox,
    path: Path,
    *,
    label: str | None = None,
    progress: Progress | None = None,
) -> str:
    """
    Read ``path`` and upload it, returning the sandbox ``file_uri``.
    """
    if label:
        _log(f"{label}: {path}", progress)
    async with aiofiles.open(path, mode="rb") as fd:
        data = await fd.read()
    return (await sandbox.api.upload_file(data)).data.file_uri


async def upload_dll_hooks(
    sandbox: Sandbox,
    dll_hooks_dir: Path,
    *,
    progress: Progress | None = None,
) -> str:
    """
    Merge DLL hooks from ``dll_hooks_dir`` and upload them.
    """
    _log(f"Upload dll hooks: {dll_hooks_dir}", progress)
    data = await asyncio.to_thread(merge_dll_hooks, Path(dll_hooks_dir))
    return (await sandbox.api.upload_file(data)).data.file_uri


async def upload_rules(sandbox: Sandbox, compiled_rules: bytes) -> str:
    """
    Upload compiled rules and return the sandbox ``file_uri``.
    """
    return (await sandbox.api.upload_file(compiled_rules)).data.file_uri


async def gather_uploads(
    uploads: list[tuple[str, Coroutine[Any, Any, str]]],
    debug_options: Any,
) -> None:
    """
    Run upload coroutines concurrently and assign URIs to ``debug_options``.
    """
    if not uploads:
        return
    results = await asyncio.gather(*(coro for _, coro in uploads))
    for (key, _), uri in zip(uploads, results, strict=True):
        debug_options[key] = uri
