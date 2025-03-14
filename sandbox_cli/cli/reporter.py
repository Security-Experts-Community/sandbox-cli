import datetime
import gzip
import textwrap
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from cyclopts import Parameter
from ptsandbox.models import SandboxBaseTaskResponse
from rich.table import Table

from sandbox_cli.console import console
from sandbox_cli.utils.extractors import (
    extract_memory,
    extract_network_from_trace,
    extract_static,
    extract_verdict_from_trace,
)


class TableData(TypedDict):
    sample: str
    image: str
    sandbox: str
    verdict: str
    static: str
    memory: str
    network: str


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
    latest: Annotated[
        bool,
        Parameter(
            name=["--latest", "-l"],
            help="Reports created in the last 2 hours",
            negative="",
        ),
    ] = False,
) -> None:
    """
    Generate short report from sandbox scans.
    """

    data: list[TableData] = []
    match mode:
        case "md":
            delimeter = "&nbsp;"
        case _:
            delimeter = "\n"

    for directory in src:
        for root in directory.rglob("*"):
            if not root.is_dir():
                continue

            report_file = root / "report.json"
            if not report_file.exists():
                continue

            if latest and (
                datetime.datetime.now() - datetime.datetime.fromtimestamp(report_file.stat().st_mtime)
            ) > datetime.timedelta(hours=2):
                continue

            with open(report_file, encoding="utf-8") as fd:
                report_data = fd.read()
                scan_data = SandboxBaseTaskResponse.model_validate_json(report_data)

            if (report := scan_data.get_long_report()) is None:
                console.warning(f"A report without behavioral analysis: {root}")
                continue

            corr_trace_path = root / "events-correlated.log.gz"
            if not corr_trace_path.exists():
                corr_trace_path = root / "raw" / "events-correlated.log.gz"

            if not corr_trace_path.exists():
                console.error(f"Can't find events-correlated.log.gz: {root}")
                continue

            corr_trace = gzip.open(corr_trace_path, "rb").read()
            image = root.name
            try:
                image = report.artifacts[0].find_sandbox_result().details.sandbox.image.image_id  # type: ignore
            finally:
                if image is None:
                    image = root.name

            data.append(
                {
                    "sample": report.artifacts[0].file_info.file_path,  # type: ignore
                    "image": image,
                    "verdict": delimeter.join(extract_verdict_from_trace(corr_trace)),
                    "static": delimeter.join(extract_static(report)),
                    "memory": delimeter.join(extract_memory(report)),
                    "network": delimeter.join(extract_network_from_trace(corr_trace)),
                }
            )

    match mode:
        case "md":
            md_report_head = textwrap.dedent(
                """
            | Sample | Image | Verdict | Static | Memory | Network |
            | --- | --- | --- | --- | --- | --- |"""
            ).strip()

            md_report_base = "|{sample}|{image}|{verdict}|{static}|{memory}|{network}|"
            table_md = md_report_head + "\n"
            table_md += "\n".join(md_report_base.format(**d) for d in data)
            print(table_md)
        case "cli":
            table = Table(highlight=True, show_lines=True)
            table.add_column("File", overflow="fold")
            table.add_column("Image", overflow="fold")
            table.add_column("Verdict", overflow="fold", style="bold")
            table.add_column("Static", overflow="fold", style="bold")
            table.add_column("Memory", overflow="fold")
            table.add_column("Network", overflow="fold")
            for d in data:
                table.add_row(
                    d["sample"],
                    d["image"],
                    d["verdict"],
                    d["static"],
                    d["memory"],
                    d["network"],
                )
            console.print(table)
        case _:
            pass
