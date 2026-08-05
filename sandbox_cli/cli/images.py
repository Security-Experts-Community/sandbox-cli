import asyncio
from typing import TYPE_CHECKING, Annotated

from cyclopts import Parameter
from ptsandbox import Sandbox
from rich.table import Table

from sandbox_cli.console import console
from sandbox_cli.core.config import key_help, settings
from sandbox_cli.core.progress import make_progress
from sandbox_cli.core.sandbox import (
    get_key_by_name,
    validate_key,
)

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
    key: Annotated[
        str,
        Parameter(
            name=["--key", "-k"],
            help=key_help(),
            validator=validate_key,
            group="Sandbox",
        ),
    ] = settings.default_key_name,
    all: Annotated[
        bool,
        Parameter(
            name=["--all", "-a"],
            help="Fetch images from all configured sandboxes",
            negative="",
        ),
    ] = False,
) -> None:
    """
    Get available images in the sandbox.
    """

    key_names = [k.name for k in settings.sandbox_keys] if all else [key]

    progress = make_progress()

    with progress:
        task_ids = {
            name: progress.add_task(description=f"Fetching images from [turquoise2]{name}[/]") for name in key_names
        }

        async def _fetch_with_progress(name: str) -> tuple[str, list[SandboxImageInfo]]:
            result = await _fetch_images(name)
            progress.update(task_ids[name], description=f"Fetched images from [turquoise2]{name}[/]")
            return result

        results = await asyncio.gather(*(_fetch_with_progress(name) for name in key_names))

    for key_name, images in results:
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
