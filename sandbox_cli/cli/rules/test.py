from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyclopts import Parameter, validators

from sandbox_cli.cli._params import IsLocal
from sandbox_cli.console import console
from sandbox_cli.core.exceptions import CompilationError
from sandbox_cli.services.compiler import get_compiler

__all__ = ["test_rules"]


async def test_rules(
    rules_dir: Annotated[
        Path,
        Parameter(
            help="A rule or a folder with rules inside correlation/ or normalization/",
            validator=validators.Path(exists=True),
        ),
    ],
    /,
    *,
    is_local: IsLocal = False,
) -> None:
    """
    Run the tests of the rules.
    """

    # Don't scan folder ~/rules/<platform>/correlation to avoid stupidly long
    # testing — find the correlation/normalization root and compute the
    # container-relative path from there.
    root_rules_dir: Path | None = None
    for parent in rules_dir.parents:
        if parent.name in {"correlation", "normalization"}:
            root_rules_dir = parent
            break

    if not root_rules_dir:
        raise CompilationError(f"Invalid rule path (read help): {rules_dir}")

    container_rules_dir = root_rules_dir.name / rules_dir.relative_to(root_rules_dir)
    root_rules_dir = root_rules_dir.parent

    with console.status_info("Testing rules"):
        async with get_compiler(is_local=is_local) as compiler:
            success = await compiler.test_rules(root_rules_dir, container_rules_dir)

    if not success:
        raise CompilationError("Rule tests failed")
    console.info("Rules fine")
