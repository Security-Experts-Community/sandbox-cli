from __future__ import annotations

import gzip
from pathlib import Path
from zipfile import ZipFile

import orjson
import zstandard

from sandbox_cli.services.report import extract_network_from_trace, extract_verdict_from_trace
from sandbox_cli.services.unpack import unpack_trace

CORRELATED = [
    {"detect.type": "malware", "detect.name": "Trojan.Win32.Generic"},
    {"detect.type": "suspicious", "detect.name": "Persistence.RunKey"},
    {"detect.type": "silent", "detect.name": "Discovery.Hostname"},
    {"event.name": "Auxiliary.ObtainNetworkAlert", "s_msg": "C2 beacon"},
    {"event.name": "Other"},
]
NORMALIZED = [{"plugin": "procmon", "x": 1}, {"plugin": "filetracer", "x": 2}, {"plugin": "procmon", "x": 3}]


def _jsonl(events: list[dict[str, object]]) -> bytes:
    return b"".join(orjson.dumps(e) + b"\n" for e in events)


def _make_logs(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "events-correlated.log.gz").write_bytes(gzip.compress(_jsonl(CORRELATED)))
    (root / "events-normalized.log.gz").write_bytes(gzip.compress(_jsonl(NORMALIZED)))
    (root / "drakvuf-trace.log.zst").write_bytes(zstandard.ZstdCompressor().compress(b"raw trace\n"))
    (root / "tcpdump.pcap").write_bytes(b"pcap")


def test_unpack_directory(tmp_path: Path) -> None:
    _make_logs(tmp_path)

    unpack_trace(tmp_path)

    correlated = tmp_path / "correlated"
    assert (correlated / "malware.log").read_bytes().count(b"\n") == 1
    assert (correlated / "Persistence.RunKey.suspicious.log").exists()
    assert (correlated / "Discovery.Hostname.silent.log").exists()

    normalized = tmp_path / "normalized"
    assert (normalized / "procmon.log").read_bytes().count(b"\n") == 2
    assert (normalized / "filetracer.log").exists()

    assert (tmp_path / "drakvuf-trace" / "drakvuf-trace.log").read_bytes() == b"raw trace\n"
    assert (tmp_path / "network" / "tcpdump.pcap").read_bytes() == b"pcap"
    assert sorted(p.name for p in (tmp_path / "raw").iterdir()) == [
        "drakvuf-trace.log.zst",
        "events-correlated.log.gz",
        "events-normalized.log.gz",
        "tcpdump.pcap",
    ]
    assert not (tmp_path / "events-correlated.log.gz").exists()


def test_unpack_zip_extracts_next_to_archive(tmp_path: Path) -> None:
    _make_logs(tmp_path / "src")
    archive = tmp_path / "sandbox_logs.zip"
    with ZipFile(archive, "w") as zf:
        for f in (tmp_path / "src").iterdir():
            zf.write(f, f.name)

    unpack_trace(archive)

    assert (tmp_path / "sandbox_logs" / "correlated" / "malware.log").exists()


def test_report_extractors() -> None:
    trace = _jsonl(CORRELATED)
    assert extract_verdict_from_trace(trace) == ["Trojan.Win32.Generic"]
    assert extract_verdict_from_trace(trace, suspicious=True) == ["Trojan.Win32.Generic", "Persistence.RunKey"]
    assert extract_network_from_trace(trace) == {"C2 beacon"}


def test_unpack_is_idempotent(tmp_path: Path) -> None:
    _make_logs(tmp_path)
    unpack_trace(tmp_path)
    first = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}

    unpack_trace(tmp_path)
    second = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}

    assert second == first


def test_grouped_writer_flushes_in_chunks(tmp_path: Path) -> None:
    from sandbox_cli.services.unpack.plugins.abc import GroupedWriter

    with GroupedWriter(tmp_path, threshold=10) as writer:
        for i in range(100):
            writer.add(f"k{i % 3}.log", f"line{i}\n".encode())

    assert sum((tmp_path / f"k{i}.log").read_text().count("\n") for i in range(3)) == 100
    assert (tmp_path / "k0.log").read_text().splitlines()[:2] == ["line0", "line3"]
