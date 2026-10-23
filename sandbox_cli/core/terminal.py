"""
Terminal integration: synchronized output and native progress reporting.

Both features do nothing when stdout is not a terminal:

* **Synchronized output** (DEC private mode 2026). The console wraps every frame
  of a live display in begin/end markers, and the terminal paints the frame at
  once. Without them Ghostty and other fast terminals can show half-drawn frames,
  which flicker in an unfocused window. Terminals without the mode ignore it.

* **Native progress** (ConEmu ``OSC 9;4``). The terminal shows overall progress in
  the tab bar, taskbar or on top of the split. Older iTerm2 versions treat OSC 9
  as a desktop notification, so only terminals known to support it get it.

``SANDBOX_CLI_SYNC_OUTPUT`` and ``SANDBOX_CLI_TERM_PROGRESS`` (``1``/``0``) force them on or off.
"""

from __future__ import annotations

import os
import subprocess
import threading
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from enum import IntEnum
from typing import TYPE_CHECKING

from rich.control import Control
from rich.segment import ControlType, Segment

if TYPE_CHECKING:
    from rich.console import Console

__all__ = [
    "BEGIN_SYNC",
    "END_SYNC",
    "ProgressState",
    "TerminalProgress",
    "env_flag",
    "supports_osc_progress",
]

BEGIN_SYNC = "\x1b[?2026h"
END_SYNC = "\x1b[?2026l"

_KEEPALIVE_INTERVAL = 1.0

_OSC_PROGRESS_TERM_PROGRAMS = frozenset({"ghostty", "WezTerm", "mintty"})
_ITERM_MIN_VERSION = (3, 6, 6)
_TMUX_MIN_VERSION = (3, 8)


class ProgressState(IntEnum):
    REMOVE = 0
    NORMAL = 1
    ERROR = 2
    INDETERMINATE = 3
    WARNING = 4


def env_flag(name: str, env: Mapping[str, str] | None = None) -> bool | None:
    """
    Read a boolean override from the environment; ``None`` when unset.
    """
    value = (env if env is not None else os.environ).get(name)
    if value is None or value == "":
        return None
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _parse_version(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for part in value.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def tmux_client_info() -> tuple[tuple[int, ...], frozenset[str]] | None:
    """
    Version of the running tmux and the terminal features of its current client.
    """
    try:
        result = subprocess.run(
            ["tmux", "display-message", "-p", "#{version}|#{client_termfeatures}"],
            capture_output=True,
            text=True,
            timeout=1,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    version, _, features = result.stdout.strip().partition("|")
    return _parse_version(version), frozenset(features.split(","))


def supports_osc_progress(
    env: Mapping[str, str],
    tmux_info: Callable[[], tuple[tuple[int, ...], frozenset[str]] | None] = tmux_client_info,
) -> bool:
    """
    Best-effort detection of terminals that understand ``OSC 9;4``.

    tmux 3.8 and newer track the progress per pane and forward it to clients
    with the ``progressbar`` feature.
    """
    if env.get("STY") or env.get("ZELLIJ"):
        return False
    if env.get("TMUX"):
        info = tmux_info()
        return info is not None and info[0] >= _TMUX_MIN_VERSION and "progressbar" in info[1]

    term_program = env.get("TERM_PROGRAM", "")
    if term_program in _OSC_PROGRESS_TERM_PROGRAMS or env.get("TERM") == "xterm-ghostty":
        return True
    if term_program == "iTerm.app":
        return _parse_version(env.get("TERM_PROGRAM_VERSION", "")) >= _ITERM_MIN_VERSION

    return bool(env.get("WT_SESSION") or env.get("ConEmuANSI") == "ON" or env.get("VTE_VERSION"))


class _RawControl(Control):
    """
    A control segment carrying an arbitrary escape sequence.

    Control segments have zero width, and rich drops them when the output is not a terminal.
    """

    def __init__(self, sequence: str) -> None:
        self.segment = Segment(sequence, None, [(ControlType.SET_WINDOW_TITLE, "")])


class TerminalProgress:
    """
    Overall progress reported to the terminal via ``OSC 9;4``.

    Activities nest: the indicator stays while at least one activity runs and
    disappears when the last one ends. Without a total it is indeterminate
    (a pulsing bar in most terminals).
    """

    def __init__(self, console: Console) -> None:
        self._console = console
        self._lock = threading.RLock()
        self._enabled: bool | None = None
        self._depth = 0
        self._total: int | None = None
        self._done = 0
        self._failed = False
        self._last_sequence: str | None = None
        self._stop = threading.Event()
        self._keepalive: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        if self._enabled is None:
            override = env_flag("SANDBOX_CLI_TERM_PROGRESS")
            if override is not None:
                self._enabled = override and self._console.is_terminal
            else:
                self._enabled = (
                    self._console.is_terminal
                    and not self._console.is_dumb_terminal
                    and supports_osc_progress(os.environ)
                )
        return self._enabled

    @property
    def active(self) -> bool:
        return self._depth > 0

    def begin(self) -> None:
        with self._lock:
            self._depth += 1
            if self._depth == 1:
                self._emit()
                self._start_keepalive()

    def end(self) -> None:
        with self._lock:
            if self._depth == 0:
                return
            self._depth -= 1
            if self._depth == 0:
                self.reset()

    @contextmanager
    def activity(self, total: int | None = None) -> Generator[None]:
        """
        Show the indicator for the duration of the block.
        """
        with self._lock:
            if total is not None and not self.active:
                self._total, self._done = max(total, 0) or None, 0
            self.begin()
            if total is not None and self._depth > 1:
                self.set_total(total)
        try:
            yield
        finally:
            self.end()

    def set_total(self, total: int) -> None:
        with self._lock:
            self._total = max(total, 0) or None
            self._done = 0
            self._emit()

    def advance(self, amount: int = 1) -> None:
        with self._lock:
            self._done += amount
            self._emit()

    def mark_error(self) -> None:
        """
        Switch the indicator to the error state for the rest of the activity.
        """
        with self._lock:
            if self.active and not self._failed:
                self._failed = True
                self._emit()

    def reset(self) -> None:
        """
        Remove the indicator and forget all state.
        """
        with self._lock:
            self._depth = 0
            self._total = None
            self._done = 0
            self._failed = False
            keepalive = self._stop_keepalive()
            if self._last_sequence is not None:
                self._write(self._sequence(ProgressState.REMOVE, 0))
            self._last_sequence = None

        if keepalive is not None and keepalive is not threading.current_thread():
            keepalive.join(timeout=_KEEPALIVE_INTERVAL)

    def _percent(self) -> int:
        if not self._total:
            return 0
        return min(100, max(0, self._done * 100 // self._total))

    def _state(self) -> ProgressState:
        if self._failed:
            return ProgressState.ERROR
        return ProgressState.NORMAL if self._total else ProgressState.INDETERMINATE

    @staticmethod
    def _sequence(state: ProgressState, percent: int) -> str:
        return f"\x1b]9;4;{int(state)};{percent}\x1b\\"

    def _emit(self, *, force: bool = False) -> None:
        if not self.active or not self.enabled:
            return
        sequence = self._sequence(self._state(), self._percent())
        if force or sequence != self._last_sequence:
            self._write(sequence)
            self._last_sequence = sequence

    def _write(self, sequence: str) -> None:
        if self.enabled:
            self._console.control(_RawControl(sequence))

    def _start_keepalive(self) -> None:
        if not self.enabled or self._keepalive is not None:
            return
        self._stop = threading.Event()
        self._keepalive = threading.Thread(
            target=self._keepalive_loop, args=(self._stop,), name="osc-progress", daemon=True
        )
        self._keepalive.start()

    def _stop_keepalive(self) -> threading.Thread | None:
        keepalive, self._keepalive = self._keepalive, None
        if keepalive is not None:
            self._stop.set()
        return keepalive

    def _keepalive_loop(self, stop: threading.Event) -> None:
        while not stop.wait(_KEEPALIVE_INTERVAL):
            with self._lock:
                if stop.is_set():
                    return
                self._emit(force=True)
