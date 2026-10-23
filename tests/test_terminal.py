from __future__ import annotations

import io
import re

import pytest

from sandbox_cli.console import SandboxConsole
from sandbox_cli.core.terminal import BEGIN_SYNC, END_SYNC, env_flag, supports_osc_progress

OSC_PROGRESS = re.compile(r"\x1b\]9;4;(\d);(\d+)\x1b\\")


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"TERM_PROGRAM": "ghostty"}, True),
        ({"TERM": "xterm-ghostty"}, True),
        ({"TERM_PROGRAM": "WezTerm"}, True),
        ({"WT_SESSION": "1"}, True),
        ({"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.6.6"}, True),
        ({"TERM_PROGRAM": "iTerm.app", "TERM_PROGRAM_VERSION": "3.5.14"}, False),
        ({"TERM_PROGRAM": "kitty"}, False),
        ({"TERM_PROGRAM": "Apple_Terminal"}, False),
    ],
)
def test_supports_osc_progress(env: dict[str, str], expected: bool) -> None:
    assert supports_osc_progress(env) is expected


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        (((3, 8), frozenset({"RGB", "progressbar", "sync"})), True),
        (((3, 8), frozenset({"RGB", "sync"})), False),
        (((3, 5), frozenset({"progressbar"})), False),
        (None, False),
    ],
)
def test_osc_progress_inside_tmux(info: tuple[tuple[int, ...], frozenset[str]] | None, expected: bool) -> None:
    env = {"TMUX": "/tmp/tmux-501/default,1,0", "TERM_PROGRAM": "tmux"}
    assert supports_osc_progress(env, tmux_info=lambda: info) is expected


def test_screen_and_zellij_are_disabled() -> None:
    assert not supports_osc_progress({"TERM_PROGRAM": "ghostty", "STY": "1.pts"})
    assert not supports_osc_progress({"TERM_PROGRAM": "ghostty", "ZELLIJ": "0"})


@pytest.mark.parametrize(("value", "expected"), [(None, None), ("", None), ("1", True), ("off", False), ("0", False)])
def test_env_flag(monkeypatch: pytest.MonkeyPatch, value: str | None, expected: bool | None) -> None:
    if value is None:
        monkeypatch.delenv("X_FLAG", raising=False)
    else:
        monkeypatch.setenv("X_FLAG", value)
    assert env_flag("X_FLAG") is expected


def _terminal_console(monkeypatch: pytest.MonkeyPatch) -> tuple[SandboxConsole, io.StringIO]:
    monkeypatch.setenv("SANDBOX_CLI_TERM_PROGRESS", "1")
    monkeypatch.setenv("SANDBOX_CLI_SYNC_OUTPUT", "1")
    out = io.StringIO()
    return SandboxConsole(file=out, force_terminal=True, width=80), out


def test_progress_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    console, out = _terminal_console(monkeypatch)
    progress = console.terminal_progress

    with progress.activity(total=2):
        progress.advance()
        console.error("one task failed")
        progress.advance()

    states = OSC_PROGRESS.findall(out.getvalue())
    assert states[0] == ("1", "0")
    assert ("1", "50") in states
    assert ("2", "100") in states
    assert states[-1] == ("0", "0")
    assert not progress.active


def test_nested_activities_clear_once(monkeypatch: pytest.MonkeyPatch) -> None:
    console, out = _terminal_console(monkeypatch)
    progress = console.terminal_progress

    with progress.activity():
        with progress.activity():
            pass
        assert progress.active
    assert OSC_PROGRESS.findall(out.getvalue()) == [("3", "0"), ("0", "0")]


def test_nothing_is_written_when_not_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SANDBOX_CLI_TERM_PROGRESS", "1")
    out = io.StringIO()
    console = SandboxConsole(file=out, force_terminal=False)
    with console.terminal_progress.activity(total=1):
        console.terminal_progress.advance()
    assert "\x1b" not in out.getvalue()


def test_live_frames_are_synchronized(monkeypatch: pytest.MonkeyPatch) -> None:
    console, out = _terminal_console(monkeypatch)
    with console.status("working"):
        console.print("inside")
    console.print("outside")

    text = out.getvalue()
    assert text.count(BEGIN_SYNC) == text.count(END_SYNC) > 0
    assert text.rindex("outside") > text.rindex(END_SYNC)
