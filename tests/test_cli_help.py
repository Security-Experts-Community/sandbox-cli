"""
Snapshot tests for ``--help`` of every command.

They pin the public CLI surface: flag names, short aliases and defaults.
Regenerate after an intended change with ``UPDATE_SNAPSHOTS=1 pytest``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SNAPSHOTS = Path(__file__).parent / "snapshots" / "help"

COMMANDS = [
    [],
    ["scanner", "scan"],
    ["scanner", "scan-new"],
    ["scanner", "re-scan"],
    ["download"],
    ["email"],
    ["images"],
    ["report"],
    ["browser"],
    ["unpack"],
    ["rules", "compile"],
    ["rules", "test"],
    ["completion"],
]


def _help(command: list[str]) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "sandbox_cli", *command, "--help"],
        capture_output=True,
        text=True,
        check=True,
        env=os.environ | {"COLUMNS": "120", "NO_COLOR": "1", "TERM": "dumb"},
    )
    return "\n".join(line.rstrip() for line in result.stdout.splitlines()) + "\n"


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: " ".join(c) or "root")
def test_help_snapshot(command: list[str]) -> None:
    snapshot = SNAPSHOTS / f"{'_'.join(command) or 'root'}.txt"
    actual = _help(command)

    if os.environ.get("UPDATE_SNAPSHOTS"):
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(actual, encoding="utf-8")

    assert actual == snapshot.read_text(encoding="utf-8")


def test_broken_config_is_reported_without_traceback(tmp_path: Path) -> None:
    (tmp_path / "sandbox-cli").mkdir()
    (tmp_path / "sandbox-cli" / "config.toml").write_text("[[sandbox]\nname=", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "sandbox_cli", "--help"],
        capture_output=True,
        text=True,
        env=os.environ | {"XDG_CONFIG_HOME": str(tmp_path)},
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stdout + result.stderr
    assert "invalid config" in result.stdout


def test_report_without_key(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sandbox_cli", "report", str(tmp_path), "-m", "md"],
        capture_output=True,
        text=True,
        env=os.environ | {"COLUMNS": "120", "NO_COLOR": "1", "TERM": "dumb"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "| Sample | Image |" in result.stdout


def test_invalid_key_is_rejected() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sandbox_cli", "images", "-k", "missing"],
        capture_output=True,
        text=True,
        env=os.environ | {"COLUMNS": "120", "NO_COLOR": "1", "TERM": "dumb"},
    )

    assert result.returncode == 1
    assert 'Key "missing" doesn\'t exist in config. Available keys: "main", "second"' in result.stdout


def test_report_json_keeps_stdout_clean(tmp_path: Path) -> None:
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "report.json").write_text('{"data": {"scan_id": "1", "status": "FULL"}}')

    result = subprocess.run(
        [sys.executable, "-m", "sandbox_cli", "report", str(tmp_path), "--json"],
        capture_output=True,
        text=True,
        env=os.environ | {"COLUMNS": "120", "NO_COLOR": "1", "TERM": "dumb"},
    )

    assert result.returncode == 1
    [line] = result.stdout.splitlines()
    assert json.loads(line) == {"status": "error", "reason": "Failed to read 1 of 1 reports"}
    assert "Can't read" in result.stderr
