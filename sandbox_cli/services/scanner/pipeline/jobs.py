"""
What a scan runs: targets, jobs and the sandbox task a job submits.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ptsandbox.models import SandboxOptions, SandboxOptionsAdvanced

from sandbox_cli.core.config import VMImage
from sandbox_cli.core.scan import ScanType
from sandbox_cli.services.downloader import DownloadOptions

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

__all__ = ["ScanJob", "ScanTarget", "Submission", "plan_targets", "unique_names"]


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """
    One cell of the files x images matrix.
    """

    file: Path
    image: VMImage | str
    out_dir: Path
    idx: str


@dataclass(frozen=True, slots=True)
class Submission:
    """
    The sandbox task of a job.

    The runner records ``type`` and ``options`` in ``scan_config.json`` and points
    ``options.debug_options`` at the files uploaded to the sandbox the job runs on,
    so ``submit`` must send these very ``options``.
    """

    type: ScanType
    options: SandboxOptions | SandboxOptionsAdvanced
    submit: Callable[[Sandbox], Awaitable[SandboxBaseTaskResponse]]


@dataclass(slots=True)
class ScanJob:
    """
    Everything needed to run and report one sandbox task.
    """

    name: str
    """File or trace name shown in the output."""
    out_dir: Path
    idx: str
    submission: Callable[[], Submission]
    """Build the task when a slot takes the job; every call returns fresh ``options``."""
    wait_timeout: int
    download_options: DownloadOptions
    image: str | None = None
    key_name: str | None = None
    """Set once the job is given to a sandbox."""
    task_id: str | None = None
    """Set once the sandbox accepts the task."""
    link: str | None = None


def unique_names(preferred: list[str], fallback: list[str] | None = None) -> list[str]:
    """
    Make the names distinct: ``preferred[i]``, ``fallback[i]`` when the preferred name
    clashes, then ``_1``, ``_2`` suffixes (``a.exe`` + ``a.dll``, ``x86/a.dll`` + ``x64/a.dll``).
    """
    counts = Counter(preferred)
    fallback = fallback or preferred
    used: set[str] = set()
    result: list[str] = []
    for name, other in zip(preferred, fallback, strict=True):
        base = name if counts[name] == 1 else other
        candidate, n = base, 1
        while candidate in used:
            candidate, n = f"{base}_{n}", n + 1
        used.add(candidate)
        result.append(candidate)
    return result


def plan_targets(files: list[Path], images: Iterable[VMImage | str], out_dir: Path) -> list[ScanTarget]:
    """
    Lay out the files x images matrix and create the output directories.

    A single file goes to ``out/<image>``, several files to ``out/<file>/<image>``
    (see ``unique_names``).
    """
    images = sorted(images, key=str)
    total = len(files) * len(images)
    dir_names = unique_names([file.stem for file in files], [file.name for file in files])
    targets: list[ScanTarget] = []
    for i, image in enumerate(images):
        for j, file in enumerate(files):
            target_dir = out_dir / str(image) if len(files) == 1 else out_dir / dir_names[j] / str(image)
            target_dir.mkdir(parents=True, exist_ok=True)
            targets.append(ScanTarget(file, image, target_dir, f"{i * len(files) + j + 1}/{total}"))
    return targets
