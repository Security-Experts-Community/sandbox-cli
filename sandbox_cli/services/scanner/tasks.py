from __future__ import annotations

from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sandbox_cli.core.config import VMImage

if TYPE_CHECKING:
    pass

__all__ = ["build_scan_tasks"]


def build_scan_tasks(
    wrapper: Callable[..., Coroutine[Any, Any, None]],
    sandbox_options: Any,
    files: list[Path],
    images: set[VMImage | str],
    out_dir: Path,
    set_image_id: Callable[[Any, VMImage | str], None],
) -> list[Coroutine[Any, Any, None]]:
    """
    Build the list of scan coroutines for the files x images matrix.

    ``set_image_id`` is a callback that assigns ``image_id`` on a copy of
    ``sandbox_options`` — needed because ``scan`` and ``scan-new`` use
    different model types with the field at different paths.
    """
    tasks: list[Coroutine[Any, Any, None]] = []

    # No images → single-image scan using the default options as-is.
    if not images:
        if len(files) == 1:
            tasks.append(wrapper(sandbox_options, files[0], out_dir, "1/1"))
        else:
            for i, file in enumerate(files):
                local_out_dir = out_dir / f"{file.stem}"
                local_out_dir.mkdir(parents=True, exist_ok=True)
                tasks.append(wrapper(sandbox_options, file, local_out_dir, f"{i + 1}/{len(files)}"))
        return tasks

    total = len(files) * len(images)
    for i, image_id in enumerate(images):
        options = sandbox_options.model_copy()
        set_image_id(options, image_id)

        if len(files) == 1:
            local_out_dir = out_dir / f"{image_id}"
            local_out_dir.mkdir(parents=True, exist_ok=True)
            tasks.append(wrapper(options, files[0], local_out_dir, f"{i + 1}/{len(images)}"))
        else:
            for j, file in enumerate(files):
                local_out_dir = out_dir / f"{file.stem}" / f"{image_id}"
                local_out_dir.mkdir(parents=True, exist_ok=True)
                idx = f"{i * len(files) + j + 1}/{total}"
                tasks.append(wrapper(options, file, local_out_dir, idx))

    return tasks
