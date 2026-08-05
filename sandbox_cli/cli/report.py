from __future__ import annotations

import gzip
import os
import textwrap
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path
from typing import Annotated, Any, Literal, TypedDict

from cyclopts import Parameter
from rich.table import Table

from sandbox_cli.console import console
from sandbox_cli.core.config import key_help
from sandbox_cli.core.sandbox import (
    format_link,
    get_key_by_name,
)
from sandbox_cli.core.scan import load_report, load_scan_arguments
from sandbox_cli.services.report import (
    extract_memory,
    extract_network_from_trace,
    extract_static,
    extract_verdict_from_trace,
)

__all__ = ["generate_report"]


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


def _resolve_link(scan_data: Any, root: Path, fallback_key: str | None) -> str:
    """
    Resolve the sandbox link from scan_config.json or ``--key`` fallback.
    """

    scan_config_file = root / "scan_config.json"
    key_name = ""
    if scan_config_file.exists():
        key_name = load_scan_arguments(scan_config_file).sandbox_key_name

    if not key_name and fallback_key is not None:
        key_name = fallback_key

    if key_name:
        return format_link(scan_data, key=get_key_by_name(key_name))
    return "Unknown"


def _process_report_dir(
    report_file: Path,
    suspicious: bool,
    fallback_key: str | None,
) -> TableData | None:
    """
    Process a single report directory; return ``TableData`` or ``None`` on skip/error.
    """

    root = report_file.parent

    scan_data = load_report(report_file)

    if (report := scan_data.get_long_report()) is None:
        console.warning(f"A report without behavioral analysis: {root}")
        return None

    corr_trace_path = _find_correlated_trace(root)
    if corr_trace_path is None:
        console.error(f"Can't find events-correlated trace: {root}")
        return None

    corr_trace = _read_trace(corr_trace_path)

    image: str = root.name
    try:
        found_image = report.artifacts[0].find_sandbox_result().details.sandbox.image.image_id  # type: ignore[union-attr]
        if found_image is not None:
            image = found_image
    except (AttributeError, IndexError):
        pass

    link = _resolve_link(scan_data, root, fallback_key)

    return TableData(
        sample=report.artifacts[0].file_info.file_path,  # type: ignore[union-attr]
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
    suspicious: Annotated[
        bool,
        Parameter(
            name=["--suspicious", "-s"],
            help="Include suspicious detects",
            negative="",
        ),
    ] = False,
    key: Annotated[
        str | None,
        Parameter(
            name=["--key", "-k"],
            help=f"{key_help()}. Used only for link generation when scan_config.json is missing",
            group="Sandbox",
        ),
    ] = None,
) -> None:
    """
    Generate short report from sandbox scans.
    """

    # Lazily yield report.json paths — no upfront collection.
    report_files = (p for d in src for p in d.rglob("report.json"))

    worker = partial(_process_report_dir, suspicious=suspicious, fallback_key=key)
    with ProcessPoolExecutor(max_workers=os.cpu_count() or 1) as executor:
        data = [r for r in executor.map(worker, report_files) if r is not None]

    match mode:
        case "md":
            _render_md(data)
        case "cli":
            _render_cli(data)
