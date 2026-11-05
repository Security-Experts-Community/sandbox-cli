from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models.api import DebugOptions

__all__ = [
    "UploadKey",
    "apply_uploads",
    "upload_bytes",
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


def apply_uploads(debug_options: DebugOptions, uris: dict[UploadKey, str]) -> None:
    for key, uri in uris.items():
        debug_options[key] = uri
