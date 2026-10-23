from __future__ import annotations

import json
import sys
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from typing import IO, TYPE_CHECKING, Any

from rich.console import Console

from sandbox_cli.core.terminal import BEGIN_SYNC, END_SYNC, TerminalProgress, env_flag

if TYPE_CHECKING:
    from rich.segment import Segment

__all__ = ["SandboxConsole", "console"]


class SandboxConsole(Console):
    """
    Console with leveled logging helpers and status spinners.

    Each level renders a coloured prefix tag before the message::

        [INFO] Using key: name=master max_workers=8
        [WARN] Docker image not found, start pulling, be patient
        [ERROR] Invalid task id: abc123
        [DONE] scan.exe • 0:01:23

    While a live display (progress, status) runs, the console wraps every write
    in synchronized-output markers, and ``terminal_progress`` mirrors the overall
    progress to the terminal tab or taskbar.
    """

    INFO = "[turquoise2 bold][INFO][/]"
    WARNING = "[yellow1 bold][WARN][/]"
    ERROR = "[red3 bold][ERROR][/]"
    DONE = "[green3 bold][DONE][/]"
    _LEVEL_STYLE = "bold"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if "soft_wrap" not in kwargs and not self.is_terminal:
            self.soft_wrap = True
        self._sync_output: bool | None = None
        self.terminal_progress = TerminalProgress(self)
        self.json_stream: IO[str] | None = None

    def use_stderr_for_messages(self) -> None:
        """
        Keep stdout for JSON results (``json_stream``) and print everything else to stderr.

        Calling it again does nothing.
        """
        if self.json_stream is not None:
            return
        self.json_stream = sys.stdout
        self.file = sys.stderr
        self.soft_wrap = not self.is_terminal
        self._sync_output = None
        self.terminal_progress = TerminalProgress(self)

    def emit_json(self, record: dict[str, Any]) -> None:
        """
        Write one JSON line to ``json_stream``; no-op unless JSON output is on.
        """
        if self.json_stream is not None:
            self.json_stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self.json_stream.flush()

    @property
    def sync_output(self) -> bool:
        """
        Whether live displays use synchronized output (DEC mode 2026).
        """
        if self._sync_output is None:
            override = env_flag("SANDBOX_CLI_SYNC_OUTPUT")
            self._sync_output = (
                self.is_terminal and not self.is_dumb_terminal if override is None else override and self.is_terminal
            )
        return self._sync_output

    def _render_buffer(self, buffer: Iterable[Segment]) -> str:
        output = super()._render_buffer(buffer)
        if output and self._live_stack and self.sync_output:
            return f"{BEGIN_SYNC}{output}{END_SYNC}"
        return output

    def done(self, message: str) -> None:
        self.print(f"{self.DONE} {message}", style=self._LEVEL_STYLE)

    def info(self, message: str) -> None:
        self.print(f"{self.INFO} {message}")

    def warning(self, message: str) -> None:
        self.print(f"{self.WARNING} {message}", style=self._LEVEL_STYLE)

    def error(self, message: str) -> None:
        self.print(f"{self.ERROR} {message}", style=self._LEVEL_STYLE)
        self.terminal_progress.mark_error()

    @contextmanager
    def status_info(self, message: str) -> Generator[None]:
        """
        Context manager: show a spinner with an ``[INFO]`` prefix.
        """
        with self.status(f"{self.INFO} {message}"), self.terminal_progress.activity():
            yield

    def print_exception(self, *, show_locals: bool = False, **kwargs: Any) -> None:
        """
        Print an exception traceback without leaking local variables by default.
        """
        super().print_exception(show_locals=show_locals, **kwargs)


console = SandboxConsole(color_system="auto", emoji=True)
