from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rich.progress import Progress

from sandbox_cli.console import console
from sandbox_cli.core.config import settings
from sandbox_cli.core.exceptions import CompilationError
from sandbox_cli.core.progress import make_progress
from sandbox_cli.services.compiler import get_compiler

if TYPE_CHECKING:
    from rich.progress import TaskID

__all__ = ["compile_rules"]


async def compile_rules(
    rules_dir: Path | None,
    is_local: bool,
    *,
    progress: Progress | None = None,
) -> bytes | None:
    """
    Compile rules locally or remotely.

    When ``progress`` is provided a nested progress bar is shown and the
    parent progress is re-enabled after compilation. Without ``progress``
    a plain console info line is printed.
    """
    if not rules_dir:
        if progress is not None:
            progress.disable = False
            progress.start()
        return None

    if progress is not None:
        return await _compile_rules_with_progress(rules_dir, is_local, progress)

    text = "Compiling rules locally" if is_local else f"Compiling rules on the remote: {settings.sandbox[0].host}"
    console.info(text)

    async with get_compiler(is_local=is_local) as compiler:
        result = await compiler.compile_rules(rules_dir, None)
        if not result:
            raise CompilationError("Bad rules")
        return result


async def _compile_rules_with_progress(
    rules_dir: Path,
    is_local: bool,
    progress: Progress,
) -> bytes | None:
    inner_progress = make_progress(transient=False)

    text = (
        "Compiling rules locally"
        if is_local
        else f"Compiling rules on the remote • [medium_purple]{settings.sandbox[0].host}[/]"
    )
    task_id: TaskID = inner_progress.add_task(f"{console.INFO} {text}")

    with inner_progress:
        async with get_compiler(is_local=is_local) as compiler:
            result = await compiler.compile_rules(rules_dir, None)
            if not result:
                raise CompilationError("Bad rules")
        inner_progress.stop_task(task_id=task_id)

    progress.disable = False
    progress.start()

    return result
