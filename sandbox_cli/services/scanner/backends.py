"""
Sandboxes a scan runs on: one per ``--key``.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Iterable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ptsandbox import Sandbox

from sandbox_cli.console import console
from sandbox_cli.core.sandbox import get_key_by_name

if TYPE_CHECKING:
    from ptsandbox import SandboxKey

    from sandbox_cli.services.scanner.uploads import UploadKey

__all__ = ["ScanBackend", "open_backends"]


@dataclass(frozen=True, slots=True)
class ScanBackend:
    """
    A sandbox to run tasks on and the ``debug_options`` entries of the files uploaded to it.
    """

    key: SandboxKey
    sandbox: Sandbox
    uploads: dict[UploadKey, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.key.name


@asynccontextmanager
async def open_backends(key_names: Iterable[str]) -> AsyncGenerator[list[ScanBackend]]:
    """
    Open a sandbox client for every distinct key name, in the given order.
    """
    keys = [get_key_by_name(name) for name in dict.fromkeys(key_names)]
    for key in keys:
        console.info(f"Using key: name={key.name} max_workers={key.max_workers}")

    async with AsyncExitStack() as stack:
        yield [ScanBackend(key=key, sandbox=await stack.enter_async_context(Sandbox(key=key))) for key in keys]
