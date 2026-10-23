from __future__ import annotations

import time
from pathlib import Path

from sandbox_cli.console import console
from sandbox_cli.core.config import get_settings
from sandbox_cli.core.exceptions import CompilationError
from sandbox_cli.core.reporting import format_elapsed
from sandbox_cli.services.compiler import AbstractCompiler

__all__ = ["compile_rules"]


async def compile_rules(rules_dir: Path, compiler: AbstractCompiler, *, is_local: bool) -> bytes:
    """
    Compile rules with ``compiler`` (local docker or the remote sandbox host) and close it.

    Shows its own spinner before the scan progress starts.
    """
    where = "locally" if is_local else f"on the remote • [medium_purple]{get_settings().sandbox[0].host}[/]"
    started = time.monotonic()

    with console.status_info(f"Compiling rules {where}"):
        async with compiler:
            result = await compiler.compile_rules(rules_dir, None)

    if not result:
        raise CompilationError("Bad rules")

    console.info(f"Rules compiled {where} • {format_elapsed(time.monotonic() - started)}")
    return result
