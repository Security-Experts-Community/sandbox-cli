from __future__ import annotations

from typing import TYPE_CHECKING

from sandbox_cli.console import console
from sandbox_cli.core.config import DEFAULT_IMAGE, LINUX_IMAGES, WINDOWS_IMAGES, VMImage, parse_image
from sandbox_cli.core.exceptions import ScanError

if TYPE_CHECKING:
    from ptsandbox import Sandbox

__all__ = [
    "fetch_available_images",
    "resolve_scan_images",
]


def resolve_scan_images(
    available_images: set[VMImage | str],
    scan_images: set[VMImage | str],
) -> tuple[set[VMImage | str], VMImage | str]:
    """
    Pick the images to scan on from the images the sandbox has.

    Returns ``(images, default_image)``: the concrete image ids to scan on and the
    image id for the base sandbox options. Raises ``ScanError`` when the sandbox
    lacks a requested image or platform.
    """
    images: set[VMImage | str] = set()
    sandbox_image: VMImage | str = DEFAULT_IMAGE
    for image in scan_images:
        match image:
            case VMImage.LINUX:
                sandbox_image = VMImage.UBUNTU_JAMMY_X64
                images = available_images & LINUX_IMAGES
                if not images:
                    raise ScanError("Sandbox doesn't support linux images")
            case VMImage.WINDOWS:
                sandbox_image = VMImage.WIN10_1803_X64
                images = available_images & WINDOWS_IMAGES
                if not images:
                    raise ScanError("Sandbox doesn't support windows images")
            case _:
                if image not in available_images:
                    console.error(f"Sandbox doesn't support {image}.")
                    console.info(f"Available: [turquoise2]{', '.join(available_images)}[/]")
                    raise ScanError(f"Sandbox doesn't support {image}.")

                images.add(image)
                sandbox_image = image

    if images:
        console.info(f"Scanning on: [turquoise2]{', '.join(images)}[/]")

    return images, sandbox_image


async def fetch_available_images(sandbox: Sandbox) -> set[VMImage | str]:
    """
    Fetch the set of image ids the sandbox reports as available.
    """
    available_images: set[VMImage | str] = set()
    for check_image in (await sandbox.api.get_images()).data:
        if not check_image.image_id:
            continue
        available_images.add(parse_image(check_image.image_id))

    return available_images
