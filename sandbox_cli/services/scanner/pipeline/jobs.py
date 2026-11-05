"""
What a scan runs: targets, jobs and the sandbox submission bound to a job.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from sandbox_cli.core.config import VMImage
from sandbox_cli.core.scan import SandboxArguments
from sandbox_cli.services.downloader import DownloadOptions

if TYPE_CHECKING:
    from ptsandbox import Sandbox
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.services.scanner.pipeline.backends import ScanBackend

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
    A job bound to a sandbox: what to save in ``scan_config.json`` and how to create the task.
    """

    arguments: SandboxArguments
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
    bind: Callable[[ScanBackend], Submission]
    """Build the task for the sandbox the job was given to."""
    wait_timeout: int
    download_options: DownloadOptions
    image: str | None = None
    key_name: str | None = None
    """Set once the job is given to a sandbox."""
    task_id: str | None = None
    """Set once the sandbox accepts the task."""
    link: str | None = None


def unique_names(
    paths: list[Path],
    name: Callable[[Path], str] = lambda p: p.stem,
    fallback: Callable[[Path], str] = lambda p: p.name,
) -> list[str]:
    """
    A distinct folder name per path: ``name(path)``, ``fallback(path)`` when that
    clashes, then ``_1``, ``_2`` suffixes (``a.exe`` + ``a.dll``, ``x86/a.dll`` + ``x64/a.dll``).
    """
    counts = Counter(name(path) for path in paths)
    used: set[str] = set()
    result: list[str] = []
    for path in paths:
        base = name(path) if counts[name(path)] == 1 else fallback(path)
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
    dir_names = unique_names(files)
    targets: list[ScanTarget] = []
    for i, image in enumerate(images):
        for j, file in enumerate(files):
            target_dir = out_dir / str(image) if len(files) == 1 else out_dir / dir_names[j] / str(image)
            target_dir.mkdir(parents=True, exist_ok=True)
            targets.append(ScanTarget(file, image, target_dir, f"{i * len(files) + j + 1}/{total}"))
    return targets
