from __future__ import annotations

from pathlib import Path
from typing import Annotated

from sandbox_cli.cli._params import RULES, IsLocal, OutDir
from sandbox_cli.console import console
from sandbox_cli.core.exceptions import CompilationError
from sandbox_cli.services.compiler import get_compiler

__all__ = ["compile_rules"]


async def compile_rules(
    rules_dir: Annotated[Path, RULES],
    /,
    *,
    out: OutDir = Path("compiled-rules.local.tmp"),
    is_local: IsLocal = False,
) -> None:
    """
    Compile rules into an archive for third-party services.
    """

    if not rules_dir.is_dir():
        raise CompilationError(f"{rules_dir} is not a folder with raw rules")

    with console.status_info("Waiting for the rules to be compiled"):
        async with get_compiler(is_local=is_local) as compiler:
            data = await compiler.compile_rules(rules_dir, out)
            if not data:
                raise CompilationError("Bad rules")
            (out / "compiled-rules.local.tar.gz").write_bytes(data)

    console.info(f"Rules saved to {out / 'compiled-rules.local.tar.gz'}")
