"""
``re-scan``: run new rules over the trace and pcap of a finished task, without a VM.
"""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING
from zipfile import BadZipFile, ZipFile

from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.core.scan import ScanType
from sandbox_cli.services.scanner.kinds.base import ScanKind, full_scan_options
from sandbox_cli.services.scanner.pipeline.jobs import ScanJob, Submission, unique_names
from sandbox_cli.services.scanner.requests import RescanRequest
from sandbox_cli.services.unpack import RAW_DIR

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.prepare import PreparedScan

__all__ = ["Rescan", "check_traces", "open_trace", "out_dir_names"]

_TRACE_LOG_NAMES = ("drakvuf-trace.log.zst", "drakvuf-trace.log.gz")
_PCAP_NAME = "tcpdump.pcap"
DEFAULT_WAIT_TIMEOUT = 300


def _find_trace_files(trace_dir: Path) -> tuple[Path, Path]:
    """
    Trace and pcap of a result folder: in the folder itself, or in ``raw/`` after unpacking.
    """
    for base in (trace_dir, trace_dir / RAW_DIR):
        drakvuf_trace = next((base / n for n in _TRACE_LOG_NAMES if (base / n).is_file()), None)
        if drakvuf_trace is not None:
            pcap = base / _PCAP_NAME
            if not pcap.is_file():
                raise ScanError(f"{_PCAP_NAME} doesn't exist in {base}")
            return drakvuf_trace, pcap
    raise ScanError(f"{' or '.join(_TRACE_LOG_NAMES)} doesn't exist in {trace_dir.resolve()}")


def _trace_members(archive: Path, zf: ZipFile) -> str:
    members = {info.filename: info for info in zf.infolist()}
    log_name = next((n for n in _TRACE_LOG_NAMES if n in members), None)
    if log_name is None:
        raise ScanError(f"No {' or '.join(_TRACE_LOG_NAMES)} in {archive}")
    if members[log_name].file_size == 0:
        raise ScanError(f"Empty {log_name} in {archive}")
    if _PCAP_NAME not in members:
        raise ScanError(f"No {_PCAP_NAME} in {archive}")
    return log_name


def _extract_trace(archive: Path, target: Path) -> tuple[Path, Path]:
    try:
        with ZipFile(archive) as zf:
            log_name = _trace_members(archive, zf)
            return Path(zf.extract(log_name, target)), Path(zf.extract(_PCAP_NAME, target))
    except BadZipFile as e:
        raise ScanError(f"{archive} not a zip file") from e


def check_traces(traces: list[Path]) -> None:
    """
    Raise ``ScanError`` listing every trace folder or archive that can't be re-scanned.
    """
    problems: list[str] = []
    for trace in traces:
        try:
            if trace.is_dir():
                _find_trace_files(trace)
                continue
            with ZipFile(trace) as zf:
                _trace_members(trace, zf)
        except BadZipFile:
            problems.append(f"{trace} not a zip file")
        except ScanError as e:
            problems.append(str(e))
    if problems:
        raise ScanError("; ".join(problems))


@asynccontextmanager
async def open_trace(trace: Path) -> AsyncGenerator[tuple[Path, Path]]:
    """
    Yield ``(drakvuf_trace, tcpdump_pcap)`` paths for a trace folder or ``sandbox_logs.zip``.

    An archive is extracted to a temporary directory that lives as long as the block.
    """
    if trace.is_dir():
        yield _find_trace_files(trace)
        return

    with tempfile.TemporaryDirectory(prefix="sandbox-cli-trace-") as tmp:
        yield await asyncio.to_thread(_extract_trace, trace, Path(tmp))


def out_dir_names(traces: list[Path]) -> list[str]:
    """
    ``<zip name>`` for archives, ``rescan`` / ``rescan_<N>`` for folders, made distinct.
    """
    names = [
        trace.stem if trace.suffix == ".zip" else ("rescan" if len(traces) == 1 else f"rescan_{i + 1}")
        for i, trace in enumerate(traces)
    ]
    return unique_names(names)


class Rescan(ScanKind[RescanRequest]):
    def check(self) -> None:
        check_traces(self.request.traces)

    def default_wait_timeout(self) -> int:
        return DEFAULT_WAIT_TIMEOUT

    def jobs(self, prepared: PreparedScan) -> list[ScanJob]:
        request = self.request
        download_options = replace(request.download_options, logs=True)
        dir_names = out_dir_names(request.traces)
        jobs: list[ScanJob] = []
        for index, trace in enumerate(request.traces):
            out_dir = request.out_dir / dir_names[index]
            out_dir.mkdir(parents=True, exist_ok=True)
            jobs.append(
                ScanJob(
                    name=trace.name if trace.is_file() else "/".join(trace.parts[-2:]),
                    out_dir=out_dir,
                    idx=f"{index + 1}/{len(request.traces)}",
                    submission=partial(self.submission, trace),
                    wait_timeout=self.wait_timeout,
                    download_options=download_options,
                )
            )
        return jobs

    def submission(self, trace: Path) -> Submission:
        options = full_scan_options()
        wait_timeout = self.wait_timeout

        async def submit(sandbox: Sandbox) -> SandboxBaseTaskResponse:
            async with open_trace(trace) as (drakvuf_trace, tcpdump_pcap):
                return await sandbox.create_rescan(
                    drakvuf_trace,
                    tcpdump_pcap,
                    options=options,
                    rules=None,
                    read_timeout=wait_timeout,
                )

        return Submission(type=ScanType.RE_SCAN, options=options.sandbox, submit=submit)
