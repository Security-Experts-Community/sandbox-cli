from __future__ import annotations

import gzip
import multiprocessing
import os
import textwrap
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Annotated, Any, Literal, TypedDict

from cyclopts import Parameter
from rich.table import Table

from sandbox_cli.cli._converters import existing
from sandbox_cli.cli._params import JsonOutput, Key, switch
from sandbox_cli.console import console
from sandbox_cli.core.config import REPORT_NAME
from sandbox_cli.core.exceptions import SandboxCliError
from sandbox_cli.core.sandbox import (
    format_link,
    get_sandbox_config,
)
from sandbox_cli.core.scan import SCAN_CONFIG_NAME, load_report, load_scan_arguments
from sandbox_cli.services.report import (
    extract_memory,
    extract_network_from_trace,
    extract_static,
    extract_verdict_from_trace,
)

__all__ = ["generate_report"]

_INLINE_REPORTS_THRESHOLD = 2


class TableData(TypedDict):
    sample: str
    image: str
    sandbox: str
    verdict: str
    static: str
    memory: str
    network: str


def _find_correlated_trace(root: Path) -> Path | None:
    candidates = [
        root / "events-correlated.log.gz",
        root / "raw" / "events-correlated.log.gz",
        root / "correlated" / "events-correlated.log",
    ]
    return next((p for p in candidates if p.exists()), None)


def _read_trace(path: Path) -> bytes:
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as f:
            return f.read()
    return path.read_bytes()


def _has_nested_runs(root: Path) -> bool:
    """
    Whether ``root`` only groups the runs of an archive (``<image>/<file>/report.json``).
    """
    return any(child.is_dir() and (child / REPORT_NAME).exists() for child in root.iterdir())


def _resolve_link(scan_data: Any, root: Path, fallback_key: str | None) -> str:
    """
    Resolve the sandbox link from scan_config.json or ``--key`` fallback.
    """

    key_name = ""
    for scan_config_file in (root / SCAN_CONFIG_NAME, root.parent / SCAN_CONFIG_NAME):
        if scan_config_file.exists():
            key_name = load_scan_arguments(scan_config_file).sandbox_key_name
            break

    if not key_name and fallback_key is not None:
        key_name = fallback_key

    if key_name:
        return format_link(scan_data, get_sandbox_config(key_name).host)
    return "Unknown"


def _process_report_dir(
    report_file: Path,
    suspicious: bool,
    fallback_key: str | None,
) -> TableData | _ReportError | None:
    """
    Process a single report directory: ``TableData``, ``_ReportError`` for an unreadable report, ``None`` to skip.
    """

    root = report_file.parent

    try:
        scan_data = load_report(report_file)
    except (OSError, ValueError) as e:
        return _ReportError(f"Can't read {report_file}: {e}")

    if (report := scan_data.get_long_report()) is None:
        console.warning(f"A report without behavioral analysis: {root}")
        return None

    corr_trace_path = _find_correlated_trace(root)
    if corr_trace_path is None:
        if not _has_nested_runs(root):
            console.error(f"Can't find events-correlated trace: {root}")
        return None

    corr_trace = _read_trace(corr_trace_path)
    sample: str = report.artifacts[0].file_info.file_path  # type: ignore[union-attr]
    nested = (root.parent / REPORT_NAME).exists()

    image: str = root.parent.name if nested else root.name
    if nested:
        sample = f"{Path(sample).name}/{root.name}"
    else:
        try:
            found_image = report.artifacts[0].find_sandbox_result().details.sandbox.image.image_id  # type: ignore[union-attr]
            if found_image is not None:
                image = found_image
        except (AttributeError, IndexError):
            pass

    link = _resolve_link(scan_data, root, fallback_key)

    return TableData(
        sample=sample,
        image=image,
        verdict="\n".join(extract_verdict_from_trace(corr_trace, suspicious)),
        static="\n".join(extract_static(report)),
        memory="\n".join(extract_memory(report)),
        network="\n".join(extract_network_from_trace(corr_trace)),
        sandbox=link,
    )


def _render_cli(data: list[TableData]) -> None:
    table = Table(highlight=True, show_lines=True)
    table.add_column("File", overflow="fold")
    table.add_column("Image", overflow="fold")
    table.add_column("Verdict", overflow="fold", style="bold")
    table.add_column("Static", overflow="fold", style="bold")
    table.add_column("Memory", overflow="fold")
    table.add_column("Network", overflow="fold")
    table.add_column("Sandbox", overflow="fold")

    for d in data:
        table.add_row(d["sample"], d["image"], d["verdict"], d["static"], d["memory"], d["network"], d["sandbox"])
    console.print(table)


@dataclass(frozen=True, slots=True)
class _ReportError:
    message: str


def _messages_to_stderr() -> None:
    console.use_stderr_for_messages()


def _render_json(data: list[TableData]) -> None:
    for d in data:
        console.emit_json(
            {
                "sample": d["sample"],
                "image": d["image"],
                "sandbox": d["sandbox"],
                **{field: d[field].splitlines() for field in ("verdict", "static", "memory", "network")},
            }
        )


def _render_md(data: list[TableData]) -> None:
    delimiter = "<br/>"
    md_data = [
        {
            **d,
            "verdict": d["verdict"].replace("\n", delimiter),
            "static": d["static"].replace("\n", delimiter),
            "memory": d["memory"].replace("\n", delimiter),
            "network": d["network"].replace("\n", delimiter),
        }
        for d in data
    ]
    header = textwrap.dedent("""
    | Sample | Image | Verdict | Static | Memory | Network | Sandbox |
    | --- | --- | --- | --- | --- | --- | --- |""").strip()
    row_fmt = "|{sample}|{image}|{verdict}|{static}|{memory}|{network}|{sandbox}|"
    console.print(header + "\n" + "\n".join(row_fmt.format(**d) for d in md_data))


def generate_report(
    src: Annotated[
        list[Path],
        Parameter(
            help="Folder(s) with sandbox reports (recursive search will be used)",
            validator=existing("dir"),
        ),
    ],
    /,
    *,
    mode: Annotated[
        Literal["cli", "md"],
        Parameter(
            name=["--mode", "-m"],
            help="Report output format",
        ),
    ] = "cli",
    suspicious: Annotated[bool, switch(["--suspicious", "-su"], "Include suspicious detects")] = False,
    key: Key | None = None,
    json_output: JsonOutput = False,
) -> None:
    """
    Generate short report from sandbox scans.

    Task links come from ``scan_config.json`` next to each report. Results without it
    (e.g. fetched with ``download``) use ``--key``.
    """

    report_files = sorted({p for d in src for p in d.rglob(REPORT_NAME)})
    worker = partial(_process_report_dir, suspicious=suspicious, fallback_key=key)

    workers = min(len(report_files), os.cpu_count() or 1)
    if workers <= _INLINE_REPORTS_THRESHOLD:
        results = list(map(worker, report_files))
    else:
        initializer = _messages_to_stderr if json_output else None
        with ProcessPoolExecutor(
            max_workers=workers, initializer=initializer, mp_context=multiprocessing.get_context("spawn")
        ) as executor:
            results = list(executor.map(worker, report_files))

    data = [r for r in results if r is not None and not isinstance(r, _ReportError)]
    errors = [r for r in results if isinstance(r, _ReportError)]
    for error in errors:
        console.error(error.message)

    if json_output:
        _render_json(data)
    elif mode == "md":
        _render_md(data)
    else:
        _render_cli(data)

    if errors:
        raise SandboxCliError(f"Failed to read {len(errors)} of {len(results)} reports")
