from __future__ import annotations

import asyncio
import sys
import zipfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.core.sandbox import get_key_by_name
from sandbox_cli.core.scan import SandboxArguments, ScanType
from sandbox_cli.services.downloader import DownloadOptions
from sandbox_cli.services.scanner.rescan import open_trace
from sandbox_cli.services.scanner.runner import ScanFailure, ScanJob, run_scan_jobs


class FakeTask:
    def __init__(self, *, long_report: object | None = None) -> None:
        self._long_report = long_report

    def get_short_report(self) -> None:
        return None

    def get_long_report(self) -> object | None:
        return self._long_report

    def model_dump_json(self, **_: Any) -> str:
        return "{}"


class FakeSandbox:
    def __init__(self, result: FakeTask | None) -> None:
        self.result = result

    async def wait_for_report(self, task: FakeTask, wait_time: float) -> FakeTask | None:
        return self.result


class RecordingReporter:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    @contextmanager
    def session(self, total: int) -> Generator[None, None, None]:
        self.events.append(("session", str(total)))
        yield

    def job_started(self, job: ScanJob) -> None:
        self.events.append(("started", job.name))

    def job_submitted(self, job: ScanJob, link: str) -> None:
        self.events.append(("submitted", job.name))

    def job_downloading(self, job: ScanJob) -> None:
        self.events.append(("downloading", job.name))

    def job_done(self, job: ScanJob) -> None:
        self.events.append(("done", job.name))

    def job_failed(self, job: ScanJob, reason: str) -> None:
        self.events.append(("failed", f"{job.name}: {reason}"))

    def job_finished(self, job: ScanJob) -> None:
        self.events.append(("finished", job.name))

    def download_tracker(self, job: ScanJob) -> None:
        return None


def _job(tmp_path: Path, name: str, submit: Any) -> ScanJob:
    from ptsandbox.models import SandboxOptions

    out = tmp_path / name
    out.mkdir()
    return ScanJob(
        name=name,
        out_dir=out,
        idx="1/1",
        submit=submit,
        wait_timeout=1,
        download_options=DownloadOptions(),
        arguments=SandboxArguments(type=ScanType.SCAN, sandbox_key_name="main", sandbox_options=SandboxOptions()),
    )


def _run(sandbox: FakeSandbox, jobs: list[ScanJob], reporter: RecordingReporter) -> str | None:
    """
    Run the jobs; return the final error message (``None`` when every job succeeded).
    """
    key = get_key_by_name("main")
    try:
        asyncio.run(run_scan_jobs(sandbox, key, jobs, reporter, unpack=False, open_browser=False))  # type: ignore[arg-type]
    except ScanFailure as e:
        return str(e)
    return None


def test_every_job_is_finished_whatever_happens(tmp_path: Path) -> None:
    async def ok(_: object) -> FakeTask:
        return FakeTask()

    async def boom(_: object) -> FakeTask:
        raise RuntimeError("upload exploded")

    reporter = RecordingReporter()
    error = _run(FakeSandbox(FakeTask()), [_job(tmp_path, "a", ok), _job(tmp_path, "b", boom)], reporter)

    assert error == "Failed 2 of 2 tasks"

    assert ("session", "2") in reporter.events
    assert ("failed", "a: full report not available") in reporter.events
    assert ("failed", "b: unexpected error • RuntimeError: upload exploded") in reporter.events
    assert [e for e in reporter.events if e[0] == "finished"] == [("finished", "a"), ("finished", "b")]
    assert (tmp_path / "a" / "report.json").exists()
    assert (tmp_path / "b" / "scan_config.json").exists()


def test_missing_report_is_a_failure(tmp_path: Path) -> None:
    async def ok(_: object) -> FakeTask:
        return FakeTask()

    reporter = RecordingReporter()
    _run(FakeSandbox(None), [_job(tmp_path, "a", ok)], reporter)
    assert ("failed", "a: scan failed") in reporter.events
    assert reporter.events[-1] == ("finished", "a")


class TestOpenTrace:
    def test_directory(self, tmp_path: Path) -> None:
        (tmp_path / "drakvuf-trace.log.zst").write_bytes(b"trace")
        (tmp_path / "tcpdump.pcap").write_bytes(b"pcap")

        async def check() -> None:
            async with open_trace(tmp_path) as (trace, pcap):
                assert (trace.name, pcap.name) == ("drakvuf-trace.log.zst", "tcpdump.pcap")

        asyncio.run(check())

    def test_zip_is_extracted_and_cleaned_up(self, tmp_path: Path) -> None:
        archive = tmp_path / "sandbox_logs.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("drakvuf-trace.log.gz", b"trace")
            zf.writestr("tcpdump.pcap", b"pcap")

        async def check() -> Path:
            async with open_trace(archive) as (trace, pcap):
                assert trace.read_bytes() == b"trace"
                assert pcap.read_bytes() == b"pcap"
                return trace

        assert not asyncio.run(check()).exists()

    @pytest.mark.parametrize(
        ("members", "error"),
        [
            ({"tcpdump.pcap": b"p"}, "No drakvuf-trace"),
            ({"drakvuf-trace.log.zst": b"", "tcpdump.pcap": b"p"}, "Empty"),
            ({"drakvuf-trace.log.zst": b"t"}, "No tcpdump.pcap"),
        ],
    )
    def test_bad_archives(self, tmp_path: Path, members: dict[str, bytes], error: str) -> None:
        archive = tmp_path / "logs.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)

        async def check() -> None:
            async with open_trace(archive):
                pass

        with pytest.raises(ScanError, match=error):
            asyncio.run(check())


def test_hook_files_are_uploaded_to_their_debug_options(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from ptsandbox.models import SandboxOptionsAdvanced

    from sandbox_cli.services.scanner.prepare import HookFiles, prepare_scan
    from sandbox_cli.services.scanner.uploads import apply_uploads

    uploaded: list[bytes] = []

    async def upload_file(data: bytes) -> SimpleNamespace:
        uploaded.append(data)
        return SimpleNamespace(data=SimpleNamespace(file_uri=f"uri-{data.decode()}"))

    sandbox = SimpleNamespace(api=SimpleNamespace(upload_file=upload_file))
    files = {}
    for name in ("syscall", "unimon", "fileextractor", "procdump"):
        files[name] = tmp_path / name
        files[name].write_text(name)

    hooks = HookFiles(
        syscall_hooks=files["syscall"],
        unimon_hooks=files["unimon"],
        fileextractor_excludes=files["fileextractor"],
        procdump_excludes=files["procdump"],
    )
    prepared = asyncio.run(prepare_scan(sandbox, rules=None, is_local=False, hooks=hooks))  # type: ignore[arg-type]

    options = SandboxOptionsAdvanced()
    apply_uploads(options.debug_options, prepared.uploads)
    assert options.debug_options["custom_syscall_hooks"] == "uri-syscall"
    assert options.debug_options["custom_unimon_hooks"] == "uri-unimon"
    assert options.debug_options["custom_fileextractor_exclude"] == "uri-fileextractor"
    assert options.debug_options["custom_procdump_exclude"] == "uri-procdump"


def _compiled_rules_archive(path: Path, *members: str) -> Path:
    import io
    import tarfile

    names = members or ("event_correlation_graph.json", "event_normalization_graph.json")
    with tarfile.open(path, "w:gz") as tar:
        for name in names:
            data = b"{}"
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def test_compiled_rules_archive_is_uploaded_as_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from sandbox_cli.services.scanner import prepare as prepare_module
    from sandbox_cli.services.scanner.prepare import prepare_scan

    archive = _compiled_rules_archive(tmp_path / "compiled-rules.local.tar.gz")

    async def upload_file(data: bytes) -> SimpleNamespace:
        return SimpleNamespace(data=SimpleNamespace(file_uri=f"uri-{len(data)}"))

    def unused_compiler(*_: object, **__: object) -> object:
        raise AssertionError("a ready archive must not be compiled")

    monkeypatch.setattr(prepare_module, "get_compiler", unused_compiler)
    sandbox = SimpleNamespace(api=SimpleNamespace(upload_file=upload_file))

    prepared = asyncio.run(prepare_scan(sandbox, rules=archive, is_local=False))  # type: ignore[arg-type]

    assert prepared.uploads["rules_url"] == f"uri-{archive.stat().st_size}"


def test_rules_archive_without_graphs_is_rejected(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from sandbox_cli.services.scanner.prepare import prepare_scan

    archive = _compiled_rules_archive(tmp_path / "rules.tar.gz", "event_correlation_graph.json")

    with pytest.raises(ScanError, match=r"no event_normalization_graph\.json inside"):
        asyncio.run(prepare_scan(SimpleNamespace(), rules=archive, is_local=False))  # type: ignore[arg-type]


def test_rules_file_that_is_not_an_archive_is_rejected(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from sandbox_cli.services.scanner.prepare import prepare_scan

    archive = tmp_path / "rules.tar.gz"
    archive.write_bytes(b"raw rules, not an archive")

    with pytest.raises(ScanError, match="is not a tar archive with compiled rules"):
        asyncio.run(prepare_scan(SimpleNamespace(), rules=archive, is_local=False))  # type: ignore[arg-type]


def test_json_reporter_prints_one_line_per_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import json

    from sandbox_cli.console import console
    from sandbox_cli.core.reporting import JsonScanReporter

    stdout, stderr = io.StringIO(), io.StringIO()
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    console.use_stderr_for_messages()

    async def boom(_: object) -> FakeTask:
        raise RuntimeError("upload exploded")

    try:
        _run(FakeSandbox(None), [_job(tmp_path, "a", boom)], JsonScanReporter(RecordingReporter()))  # type: ignore[arg-type]
    finally:
        console.json_stream = None
        console.file = sys.__stdout__  # type: ignore[assignment]

    [line] = stdout.getvalue().splitlines()
    record = json.loads(line)
    assert record["status"] == "failed"
    assert record["name"] == "a"
    assert record["reason"] == "unexpected error • RuntimeError: upload exploded"
    assert record["out_dir"] == str(tmp_path / "a")


def test_open_trace_finds_unpacked_raw(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "drakvuf-trace.log.zst").write_bytes(b"trace")
    (raw / "tcpdump.pcap").write_bytes(b"pcap")

    async def check() -> None:
        async with open_trace(tmp_path) as (trace, pcap):
            assert (trace.parent, pcap.parent) == (raw, raw)

    asyncio.run(check())
