from __future__ import annotations

import ipaddress
import sys
from collections import deque
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from cyclopts import validators

from sandbox_cli.core.config import Platform, VMImage, get_settings, parse_image
from sandbox_cli.core.exceptions import ConfigError, ScanError
from sandbox_cli.services.scanner.hooks import merge_dll_hooks

if TYPE_CHECKING:
    from cyclopts import Token

__all__ = [
    "dll_hooks_validator",
    "existing",
    "files_path_resolver",
    "image_converter",
    "ip_addresses_validator",
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
    against the configured ``rules-path``, or an explicit path.
    """
    path: Path | None = None
    rules_path = get_settings().rules_path
    for token in tokens:
        if token.value in {Platform.LINUX, Platform.WINDOWS}:
            if not rules_path:
                raise ConfigError("You can't use aliases without specifying the path in the config")

            path = rules_path / token.value
            break
        else:
            # no platform alias — use the specified value as a path
            path = Path(token.value)

    return path


def files_path_resolver(files: list[Path]) -> list[Path]:
    """
    Expand a list of file/folder paths into a flat list of files.

    Handles wildcards on Windows and recurses into directories. Raises
    ``ScanError`` listing every missing path, or when nothing is left to scan.
    """
    files_queue: deque[Path] = deque(files)
    files_for_analysis: set[Path] = set()
    missing: list[Path] = []

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
            missing.append(file)
            continue

        if file.is_dir():
            files_for_analysis.update(f for f in file.rglob("*") if f.is_file())
            continue

        files_for_analysis.add(file)

    if missing:
        raise ScanError("Paths don't exist: " + ", ".join(str(p) for p in missing))
    if not files_for_analysis:
        raise ScanError("Nothing to scan")

    return sorted(files_for_analysis)


def existing(kind: Literal["file", "dir"]) -> Callable[[Any, Any], None]:
    """
    cyclopts validator: every given path exists and is a file (or a directory).
    """

    def validator(_: Any, value: Any) -> None:
        for path in value if isinstance(value, list) else [value]:
            if path is None:
                continue
            if not path.exists():
                raise ValueError(f"{path} doesn't exist")
            if kind == "file" and not path.is_file():
                raise ValueError(f"{path} is not a file")
            if kind == "dir" and not path.is_dir():
                raise ValueError(f"{path} is not a directory")

    return validator


def dll_hooks_validator(_: Any, value: Any) -> None:
    """
    cyclopts validator: the DLL hooks directory exists and every hook in it is valid.
    """
    if value is None:
        return
    existing("dir")(_, value)
    try:
        merge_dll_hooks(value)
    except ScanError as e:
        raise ValueError(str(e)) from None


def ip_addresses_validator(_: Any, value: Any) -> None:
    """
    cyclopts validator: every value is an IPv4 or IPv6 address.
    """
    for item in value or []:
        try:
            ipaddress.ip_address(item)
        except ValueError:
            raise ValueError(f"{item} is not an IP address") from None
