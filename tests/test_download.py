from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from uuid import UUID

import pytest
from ptsandbox.models import ArtifactType, LogType

from sandbox_cli.cli.download.artifacts import _parse_task_url, resolve_task
from sandbox_cli.core.exceptions import ConfigError, DownloadError
from sandbox_cli.services.downloader import (
    DownloadOptions,
    _collect_artifact_downloads,
    _collect_log_downloads,
    _unique_path,
)

TASK = UUID("eafc5f87-ffac-11ef-96ad-72ab1bd29c47")


class TestParseTaskUrl:
    def test_tasks_path(self) -> None:
        assert _parse_task_url(f"https://sandbox.example.com/tasks/{TASK}") == ("sandbox.example.com", TASK)

    def test_bare_uuid_path(self) -> None:
        assert _parse_task_url(f"https://sandbox.example.com/{TASK}/") == ("sandbox.example.com", TASK)

    def test_without_scheme(self) -> None:
        assert _parse_task_url(f"sandbox.example.com/tasks/{TASK}") == ("sandbox.example.com", TASK)

    def test_port_query_and_case(self) -> None:
        url = f"https://Sandbox.Example.com:8443/tasks/{TASK}?tab=report"
        assert _parse_task_url(url) == ("sandbox.example.com", TASK)

    def test_not_a_url(self) -> None:
        assert _parse_task_url(str(TASK)) is None

    def test_bad_uuid(self) -> None:
        assert _parse_task_url("https://sandbox.example.com/tasks/nope") is None


class TestResolveTask:
    def test_bare_uuid_uses_given_key(self) -> None:
        key, uuid = resolve_task("second", str(TASK))
        assert (key.name, uuid) == ("second", TASK)

    def test_url_selects_key_by_host(self) -> None:
        key, uuid = resolve_task("main", f"https://second.example.com/tasks/{TASK}")
        assert (key.name, uuid) == ("second", TASK)

    def test_host_matching_ignores_case_scheme_and_port(self) -> None:
        key, _ = resolve_task("main", f"SECOND.example.com:443/tasks/{TASK}")
        assert key.name == "second"

    def test_unknown_host(self) -> None:
        with pytest.raises(ConfigError, match="Unknown sandbox host"):
            resolve_task("main", f"https://nope.example.com/tasks/{TASK}")

    def test_garbage(self) -> None:
        with pytest.raises(DownloadError):
            resolve_task("main", "not-a-task")

    def test_unknown_key_lists_available(self) -> None:
        with pytest.raises(ConfigError, match='"main", "second"'):
            resolve_task("missing", str(TASK))


def test_unique_path_skips_existing_and_claimed(tmp_path: Path) -> None:
    (tmp_path / "a.bin").touch()
    claimed = {tmp_path / "a_1.bin"}
    assert _unique_path(tmp_path / "a.bin", claimed) == tmp_path / "a_2.bin"
    assert _unique_path(tmp_path / "b.bin", claimed) == tmp_path / "b.bin"


def _log(type_: LogType, name: str) -> SimpleNamespace:
    return SimpleNamespace(type=type_, file_name=name, file_uri=f"uri-{name}")


def _artifact(type_: ArtifactType, **file_info: object) -> SimpleNamespace:
    defaults: dict[str, object] = {"file_uri": "uri", "sha256": "f" * 64, "file_path": "/C/x.exe"}
    return SimpleNamespace(type=type_, file_info=SimpleNamespace(**(defaults | file_info)))


class TestCollectLogs:
    logs: ClassVar[list[SimpleNamespace]] = [
        _log(LogType.EVENT_CORRELATED, "events-correlated.log.gz"),
        _log(LogType.SCREENSHOT, "video.webm"),
        _log(LogType.DEBUG, "debug.log"),
        _log(LogType.NETWORK, "tcpdump.pcap"),
    ]

    def test_nothing_by_default(self, tmp_path: Path) -> None:
        assert _collect_log_downloads(self.logs, tmp_path, DownloadOptions()) == []

    def test_logs_only(self, tmp_path: Path) -> None:
        names = [item[1] for item in _collect_log_downloads(self.logs, tmp_path, DownloadOptions(logs=True))]
        assert names == ["events-correlated.log.gz", "tcpdump.pcap"]

    def test_all_routes_debug_into_subdir(self, tmp_path: Path) -> None:
        items = _collect_log_downloads(self.logs, tmp_path, DownloadOptions(all=True))
        assert (tmp_path / "debug", "debug.log", "uri-debug.log", False, False) in items
        assert len(items) == 4


class TestCollectArtifacts:
    def test_files_and_procdumps(self, tmp_path: Path) -> None:
        artifacts = [
            _artifact(ArtifactType.FILE, file_path="/C/Users/drop.exe"),
            _artifact(
                ArtifactType.PROCESS_DUMP,
                details=SimpleNamespace(process_dump=SimpleNamespace(process_name="/C/evil.exe")),
            ),
            _artifact(ArtifactType.AMSI),
        ]
        items = _collect_artifact_downloads(artifacts, tmp_path, DownloadOptions(artifacts=True, decompress=True))
        assert items == [
            (tmp_path / "artifacts", "C/Users/drop.exe", "uri", False, False),
            (tmp_path / "process_dump", "C/evil.exe", "uri", True, False),
        ]

    def test_unknown_types_only_with_all(self, tmp_path: Path) -> None:
        artifacts = [_artifact(ArtifactType("SOMETHING_NEW"))]
        assert _collect_artifact_downloads(artifacts, tmp_path, DownloadOptions(files=True)) == []
        items = _collect_artifact_downloads(artifacts, tmp_path, DownloadOptions(all=True))
        assert items == [(tmp_path / "other", "f" * 64, "uri", False, False)]
