"""
Mistakes the CLI can detect locally fail before anything is uploaded.

The fake config points at ``sandbox.example.com``: a test that reached the network
would hang or fail with a connection error instead of the expected message.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


def _run(*args: str) -> tuple[int, dict[str, str]]:
    result = subprocess.run(
        [sys.executable, "-m", "sandbox_cli", *args, "--json"],
        capture_output=True,
        text=True,
        timeout=60,
        env=os.environ | {"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"},
    )
    [line] = result.stdout.splitlines()
    return result.returncode, json.loads(line)


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


@pytest.mark.parametrize("flag", ["-s", "-u", "-fe", "-pe", "-e"])
def test_missing_hook_files(sample: Path, tmp_path: Path, flag: str) -> None:
    code, record = _run("scanner", "scan-new", str(sample), flag, str(tmp_path / "missing.txt"))
    assert code == 1
    assert record["status"] == "error"
    assert "missing.txt doesn't exist" in record["reason"]


def test_invalid_dll_hook(sample: Path, tmp_path: Path) -> None:
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    (hooks / "kernel32.txt").write_text("CreateFileW,log\nRtlAllocateHeap,log\n")

    code, record = _run("scanner", "scan-new", str(sample), "-dll", str(hooks))

    assert code == 1
    assert "kernel32.txt:2" in record["reason"]
    assert "RtlAllocateHeap" in record["reason"]


@pytest.mark.parametrize("value", ["not-an-ip", "c2.example.com", "999.1.1.1", "10.0.0.0/24"])
def test_invalid_outbound_ip(sample: Path, value: str) -> None:
    code, record = _run("scanner", "scan-new", str(sample), "-oc", "10.0.0.1", "-oc", value)
    assert code == 1
    assert f"{value} is not an IP address" in record["reason"]


def test_missing_rules_dir(sample: Path, tmp_path: Path) -> None:
    code, record = _run("scanner", "scan-new", str(sample), "-r", str(tmp_path / "no-rules"))
    assert code == 1
    assert "no-rules doesn't exist" in record["reason"]


def test_local_rules_without_docker_config(sample: Path, tmp_path: Path) -> None:
    code, record = _run("scanner", "scan-new", str(sample), "-r", str(tmp_path), "-l")
    assert code == 1
    assert "docker" in record["reason"]


def test_bad_traces_are_listed_together(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    archive = tmp_path / "logs.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("drakvuf-trace.log.zst", b"trace")

    code, record = _run("scanner", "re-scan", str(empty_dir), str(archive))

    assert code == 1
    assert "doesn't exist in" in record["reason"]
    assert "No tcpdump.pcap in" in record["reason"]


def test_invalid_task_ids_are_listed_together() -> None:
    code, record = _run(
        "download", "not-a-task", "https://unknown.example.com/tasks/eafc5f87-ffac-11ef-96ad-72ab1bd29c47"
    )
    assert code == 1
    assert "Invalid task id: not-a-task" in record["reason"]
    assert "Unknown sandbox host: unknown.example.com" in record["reason"]


def test_missing_report_dir(tmp_path: Path) -> None:
    code, record = _run("report", str(tmp_path / "nothing"))
    assert code == 1
    assert "nothing doesn't exist" in record["reason"]
