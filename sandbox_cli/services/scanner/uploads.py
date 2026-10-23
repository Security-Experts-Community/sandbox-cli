from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import aiofiles

from sandbox_cli.console import console
from sandbox_cli.services.scanner.hooks import merge_dll_hooks

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models.api import DebugOptions

__all__ = [
    "UploadKey",
    "apply_uploads",
    "gather_uploads",
    "upload_bytes",
    "upload_dll_hooks",
    "upload_file",
]

UploadKey = Literal[
    "rules_url",
    "custom_syscall_hooks",
    "custom_unimon_hooks",
    "custom_dll_hooks",
    "custom_fileextractor_exclude",
    "custom_procdump_exclude",
]


async def upload_bytes(sandbox: Sandbox, data: bytes) -> str:
    """
    Upload ``data`` and return the sandbox ``file_uri``.
    """
    return (await sandbox.api.upload_file(data)).data.file_uri


async def upload_file(sandbox: Sandbox, path: Path, *, label: str) -> str:
    """
    Read ``path`` and upload it, returning the sandbox ``file_uri``.
    """
    console.info(f"{label}: {path}")
    async with aiofiles.open(path, mode="rb") as fd:
        data = await fd.read()
    return await upload_bytes(sandbox, data)


async def upload_dll_hooks(sandbox: Sandbox, dll_hooks_dir: Path) -> str:
    """
    Merge DLL hooks from ``dll_hooks_dir`` and upload them.
    """
    console.info(f"Upload dll hooks: {dll_hooks_dir}")
    data = await asyncio.to_thread(merge_dll_hooks, dll_hooks_dir)
    return await upload_bytes(sandbox, data)


async def gather_uploads(uploads: dict[UploadKey, Coroutine[Any, Any, str]]) -> dict[UploadKey, str]:
    """
    Run upload coroutines concurrently; return the URI for each key.
    """
    results = await asyncio.gather(*uploads.values())
    return dict(zip(uploads, results, strict=True))


def apply_uploads(debug_options: DebugOptions, uris: dict[UploadKey, str]) -> None:
    for key, uri in uris.items():
        debug_options[key] = uri
