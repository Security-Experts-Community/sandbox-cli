from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from rich.console import Console

__all__ = ["SandboxConsole", "console"]


class SandboxConsole(Console):
    """
    Console with leveled logging helpers and status spinners.

    Each level renders a coloured prefix tag before the message so the
    output is easy to scan visually::

        [INFO] Using key: name=master max_workers=8
        [WARN] Docker image not found, start pulling, be patient
        [ERROR] Invalid task id: abc123
        [DONE] scan.exe • 0:01:23
    """

    INFO = "[turquoise2 bold][INFO][/]"
    WARNING = "[yellow1 bold][WARN][/]"
    ERROR = "[red3 bold][ERROR][/]"
    DONE = "[green3 bold][DONE][/]"
    _LEVEL_STYLE = "bold"

    def done(self, message: str) -> None:
        self.print(f"{self.DONE} {message}", style=self._LEVEL_STYLE)

    def info(self, message: str) -> None:
        self.print(f"{self.INFO} {message}")

    def warning(self, message: str) -> None:
        self.print(f"{self.WARNING} {message}", style=self._LEVEL_STYLE)

    def error(self, message: str) -> None:
        self.print(f"{self.ERROR} {message}", style=self._LEVEL_STYLE)

    @contextmanager
    def status_info(self, message: str) -> Generator[None]:
        """
        Context manager: show a spinner with an ``[INFO]`` prefix.
        """
        with self.status(f"{self.INFO} {message}"):
            yield

    @contextmanager
    def status_warning(self, message: str) -> Generator[None]:
        """
        Context manager: show a spinner with a ``[WARN]`` prefix.
        """
        with self.status(f"{self.WARNING} {message}"):
            yield

    @contextmanager
    def status_error(self, message: str) -> Generator[None]:
        """
        Context manager: show a spinner with an ``[ERROR]`` prefix.
        """
        with self.status(f"{self.ERROR} {message}"):
            yield

    def print_exception(self, *, show_locals: bool = False, **kwargs: Any) -> None:
        """
        Print an exception traceback without leaking local variables by default.
        """
        super().print_exception(show_locals=show_locals, **kwargs)


console = SandboxConsole(color_system="auto", emoji=True)
