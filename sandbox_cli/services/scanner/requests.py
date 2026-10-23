"""
Parameter objects for the scan services (one per command).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ptsandbox.models import VNCMode

from sandbox_cli.core.config import DEFAULT_DURATION, VMImage
from sandbox_cli.services.downloader import DownloadOptions
from sandbox_cli.services.scanner.prepare import HookFiles

__all__ = ["AdvancedScanRequest", "BasicScanRequest", "RescanRequest", "ScanRequest"]


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanRequest:
    """
    Options shared by every scan command.
    """

    key_name: str
    out_dir: Path
    rules_dir: Path | None = None
    is_local: bool = False
    unpack: bool = False
    open_browser: bool = False
    download_options: DownloadOptions = field(default_factory=DownloadOptions)


@dataclass(frozen=True, slots=True, kw_only=True)
class BasicScanRequest(ScanRequest):
    files: list[Path]
    images: set[VMImage | str]
    hooks: HookFiles = field(default_factory=HookFiles)
    analysis_duration: int = DEFAULT_DURATION
    custom_command: str | None = None
    fake_name: str | None = None
    upload_timeout: int = 300


@dataclass(frozen=True, slots=True, kw_only=True)
class AdvancedScanRequest(BasicScanRequest):
    wait_timeout: int | None = None
    priority: int = 3
    preserve_filename: bool = False
    unpack_archives: bool = False
    extra_files: list[Path] = field(default_factory=list)
    no_procdumps_on_finish: bool = False
    disable_lightweight_dumps: bool = False
    bootkitmon: bool = False
    bootkitmon_duration: int = 60
    mitm_disabled: bool = False
    disable_clicker: bool = False
    skip_sample_run: bool = False
    vnc_mode: VNCMode = VNCMode.DISABLED
    outbound_connections: list[str] = field(default_factory=list)
    file_type_as_ext: bool | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class RescanRequest(ScanRequest):
    traces: list[Path]
    wait_timeout: int | None = None
