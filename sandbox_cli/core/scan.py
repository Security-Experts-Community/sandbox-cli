from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from ptsandbox.models.api import SandboxOptions, SandboxOptionsAdvanced
from pydantic import BaseModel

from sandbox_cli.core.config import settings

if TYPE_CHECKING:
    from ptsandbox.models import SandboxBaseTaskResponse

__all__ = [
    "SandboxArguments",
    "ScanType",
    "load_report",
    "load_scan_arguments",
    "save_report",
    "save_scan_arguments",
]


class ScanType(str, Enum):
    SCAN = "scan"
    RE_SCAN = "re-scan"
    SCAN_NEW = "scan-new"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)


class SandboxArguments(BaseModel):
    type: ScanType
    sandbox_key_name: str
    sandbox_options: SandboxOptions | SandboxOptionsAdvanced


def save_scan_arguments(out_dir: Path, scan_args: SandboxArguments) -> None:
    scan_config_path = out_dir / "scan_config.json"
    scan_config_path.write_text(
        scan_args.model_dump_json(exclude={"debug_options"}, indent=4),
        encoding="utf-8",
    )


def save_report(out_dir: Path, report: SandboxBaseTaskResponse) -> None:
    """
    Write ``report.json`` into ``out_dir``.
    """
    (out_dir / settings.report_name).write_text(report.model_dump_json(indent=4), encoding="utf-8")


def load_report(path: Path) -> SandboxBaseTaskResponse:
    """
    Load a ``SandboxBaseTaskResponse`` from a JSON file.
    """
    from ptsandbox.models import SandboxBaseTaskResponse

    return SandboxBaseTaskResponse.model_validate_json(path.read_text(encoding="utf-8"))


def load_scan_arguments(path: Path) -> SandboxArguments:
    """
    Load ``SandboxArguments`` from a ``scan_config.json`` file.
    """

    return SandboxArguments.model_validate_json(path.read_text(encoding="utf-8"))
