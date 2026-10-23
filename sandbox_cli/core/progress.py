from __future__ import annotations

from rich.progress import (
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Column

from sandbox_cli.console import console

__all__ = ["SandboxProgress", "make_progress", "make_scan_progress"]

# Dim separator between progress columns.
_SEP = "[dim]•[/]"


class SandboxProgress(Progress):
    """
    ``Progress`` that mirrors itself to the terminal's native progress indicator.

    The indicator is indeterminate by default; call
    ``console.terminal_progress.set_total`` / ``advance`` to report real
    progress.
    """

    _terminal_active = False

    def start(self) -> None:
        super().start()
        if not self.disable and not self._terminal_active:
            self._terminal_active = True
            console.terminal_progress.begin()

    def stop(self) -> None:
        try:
            super().stop()
        finally:
            if self._terminal_active:
                self._terminal_active = False
                console.terminal_progress.end()


def make_progress(*, transient: bool = True) -> SandboxProgress:
    """
    Spinner • description • elapsed.

    For single-purpose progress bars (images, download, compile-rules).
    """
    return SandboxProgress(
        SpinnerColumn(),
        TextColumn("{task.description}", table_column=Column(overflow="ellipsis", no_wrap=True)),
        _SEP,
        TimeElapsedColumn(),
        console=console,
        transient=transient,
    )


def make_scan_progress(
    *,
    with_image: bool = False,
    transient: bool = True,
) -> SandboxProgress:
    """
    Spinner • idx • [image] • description • url • elapsed.

    For scan / re-scan progress bars where each task shows its index,
    optional VM image, status description, and sandbox link.

    ``idx`` and ``url`` are task fields set via ``add_task(..., idx=..., url=...)``.
    """

    columns: list[ProgressColumn | str] = [
        SpinnerColumn(),
        TextColumn("{task.fields[idx]}"),
        _SEP,
    ]
    if with_image:
        columns.append(
            TextColumn(
                "{task.fields[image]}",
                table_column=Column(
                    overflow="ellipsis",
                    no_wrap=True,
                ),
            )
        )
        columns.append(_SEP)

    columns.extend(
        [
            TextColumn(
                "{task.description}",
                table_column=Column(
                    overflow="ellipsis",
                    no_wrap=True,
                ),
            ),
            _SEP,
            TextColumn(
                "{task.fields[url]}",
                table_column=Column(
                    overflow="ellipsis",
                    no_wrap=True,
                ),
            ),
            _SEP,
            TimeElapsedColumn(),
        ]
    )
    return SandboxProgress(
        *columns,
        console=console,
        transient=transient,
    )
