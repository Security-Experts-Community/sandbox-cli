from __future__ import annotations

import sys
from collections import deque
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyclopts import validators

from sandbox_cli.console import console
from sandbox_cli.core.config import Platform, VMImage, parse_image, settings
from sandbox_cli.core.exceptions import ConfigError

if TYPE_CHECKING:
    from cyclopts import Token

__all__ = [
    "files_path_resolver",
    "image_converter",
    "out_dir_converter",
    "out_dir_validator",
    "rules_path_resolver",
    "trace_converter",
    "trace_validator",
]


def image_converter(_: Any, tokens: Sequence[Token]) -> set[VMImage | str]:
    """
    Convert ``--image`` tokens into a set of ``VMImage`` or custom image ids.
    """
    return {parse_image(token.value) for token in tokens}


def out_dir_converter(_: Any, tokens: Sequence[Token]) -> Path:
    """
    Resolve ``--out`` value: expand ``~``, create the directory, return absolute path.
    """
    path = Path(tokens[0].value).expanduser()
    path.mkdir(exist_ok=True, parents=True)
    return path.resolve()


def out_dir_validator(_: Any, value: Any) -> None:
    """
    Ensure the output directory exists (also covers default values).
    """
    if isinstance(value, Path):
        value.mkdir(exist_ok=True, parents=True)


def trace_converter(_: Any, tokens: Sequence[Token]) -> list[Path]:
    """
    Resolve trace paths: expand ``~`` and return absolute paths.
    """
    return [Path(t.value).expanduser().resolve() for t in tokens]


def trace_validator(_: Any, value: Any) -> None:
    """
    Validate that all trace paths exist.
    """
    path_validator = validators.Path(exists=True)
    if isinstance(value, list):
        for v in value:
            path_validator(_, v)
    elif isinstance(value, Path):
        path_validator(_, value)


def rules_path_resolver(_: Any, tokens: Sequence[Token]) -> Path | None:
    """
    Resolve ``--rules`` tokens into a rules directory path.

    Accepts either a platform alias (``windows``/``linux``) resolved
    against ``settings.rules_path``, or an explicit path.
    """
    path: Path | None = None
    for token in tokens:
        if token.value in {Platform.LINUX, Platform.WINDOWS}:
            if not settings.rules_path:
                raise ConfigError("You can't use aliases without specifying the path in the config")

            path = settings.rules_path / token.value
            break
        else:
            # no platform alias — use the specified value as a path
            path = Path(token.value)

    return path


def files_path_resolver(files: list[Path]) -> list[Path] | None:
    """
    Expand a list of file/folder paths into a flat list of files.

    Handles wildcards on Windows and recurses into directories. Returns
    ``None`` when one or more inputs are invalid so the caller can bail out.
    """
    files_queue: deque[Path] = deque(files)
    files_for_analysis: set[Path] = set()

    is_ok = True
    while files_queue:
        file = files_queue.popleft()

        # process wildcards
        if sys.platform == "win32" and "*" in str(file):
            for f in Path.cwd().glob(str(file)):
                if f.is_file():
                    files_queue.append(f)
            continue

        file = file.expanduser().resolve()

        if not file.exists():
            console.error(f"{file!s} doesn't exist")
            is_ok = False

        if file.is_dir():
            files_for_analysis.update(file.glob("**/*"))
            continue

        files_for_analysis.add(file)

    if len(files_for_analysis) == 0:
        console.error("Nothing to scan")
        is_ok = False

    return list(files_for_analysis) if is_ok else None
