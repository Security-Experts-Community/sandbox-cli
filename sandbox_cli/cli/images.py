from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Annotated

from ptsandbox import Sandbox
from rich.table import Table

from sandbox_cli.cli._params import JsonOutput, Key, default_key, switch
from sandbox_cli.console import console
from sandbox_cli.core.config import get_settings
from sandbox_cli.core.exceptions import SandboxCliError
from sandbox_cli.core.progress import make_progress
from sandbox_cli.core.sandbox import (
    get_key_by_name,
)
from sandbox_cli.services.scanner.runner import describe_error

if TYPE_CHECKING:
    from ptsandbox.models import SandboxImageInfo


async def _fetch_images(key_name: str) -> tuple[str, list[SandboxImageInfo]]:
    """
    Fetch images from a single sandbox, returning ``(key_name, images)``.
    """
    async with Sandbox(get_key_by_name(key_name)) as sandbox:
        images = await sandbox.get_images()
        return key_name, images


async def get_images(
    *,
    key: Key = default_key(),
    all_keys: Annotated[bool, switch(["--all-keys", "-ak"], "Fetch images from all configured sandboxes")] = False,
    json_output: JsonOutput = False,
) -> None:
    """
    Get available images in the sandbox.
    """

    key_names = [s.name for s in get_settings().sandbox] if all_keys else [key]

    progress = make_progress()

    with progress:
        task_ids = {
            name: progress.add_task(description=f"Fetching images from [turquoise2]{name}[/]") for name in key_names
        }

        async def _fetch_with_progress(name: str) -> tuple[str, list[SandboxImageInfo]] | None:
            try:
                return await _fetch_images(name)
            except Exception as e:
                console.error(f"[turquoise2]{name}[/] • {describe_error(e)}")
                return None
            finally:
                progress.remove_task(task_ids[name])
                console.terminal_progress.advance()

        console.terminal_progress.set_total(len(key_names))
        results = await asyncio.gather(*(_fetch_with_progress(name) for name in key_names))

    fetched = [r for r in results if r is not None]
    for key_name, images in fetched:
        if json_output:
            for image in sorted(images, key=lambda img: img.image_id or ""):
                console.emit_json(
                    {
                        "key": key_name,
                        "image_id": image.image_id,
                        "name": image.os.name if image.os else None,
                        "version": image.os.version if image.os else None,
                        "product_version": image.version,
                        "locale": image.os.locale if image.os else None,
                    }
                )
            continue

        title = f"Images: {key_name}" if len(key_names) > 1 else None

        table = Table(title=title)
        table.add_column("Name")
        table.add_column("Image ID", style="turquoise2")
        table.add_column("Version")
        table.add_column("Product version")
        table.add_column("Locale")

        for image in sorted(images, key=lambda img: img.image_id or ""):
            if not image.os:
                console.warning(f"{image.image_id} doesn't contain OS information")
                continue

            table.add_row(image.os.name, image.image_id, image.os.version, image.version, image.os.locale)

        console.print(table)

    if len(fetched) < len(key_names):
        raise SandboxCliError(
            f"Failed to fetch images from {len(key_names) - len(fetched)} of {len(key_names)} sandboxes"
        )
