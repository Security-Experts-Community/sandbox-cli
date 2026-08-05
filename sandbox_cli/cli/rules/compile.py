from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyclopts import Parameter, validators

from sandbox_cli.cli._converters import out_dir_converter, out_dir_validator
from sandbox_cli.console import console
from sandbox_cli.core.exceptions import CompilationError
from sandbox_cli.services.compiler import get_compiler

__all__ = ["compile_rules"]


async def compile_rules(
    rules_dir: Annotated[
        Path,
        Parameter(
            name=["--rules", "-r"],
            help="The path to the folder with the rules",
            validator=validators.Path(exists=True),
        ),
    ],
    /,
    out: Annotated[
        Path,
        Parameter(
            name=["--out", "-o"],
            help="The path where to save the compiled rules",
            required=False,
            converter=out_dir_converter,
            validator=out_dir_validator,
        ),
    ] = Path("compiled-rules.local.tmp"),
    is_local: Annotated[
        bool,
        Parameter(
            name=["--local", "-l"],
            negative="",
            help="The rules will be compiled locally using Docker (unix only)",
        ),
    ] = False,
) -> None:
    """
    Get compiled rules for working with third-party services.
    """

    with console.status_info("Waiting for the rules to be compiled"):
        async with get_compiler(is_local=is_local) as compiler:
            data = await compiler.compile_rules(rules_dir, out)
            if not data:
                raise CompilationError("Bad rules")
            (out / "compiled-rules.local.tar.gz").write_bytes(data)

    console.info(f"Rules saved to {out / 'compiled-rules.local.tar.gz'}")
