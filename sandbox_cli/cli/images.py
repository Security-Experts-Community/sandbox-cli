from typing import Annotated

from cyclopts import Parameter
from ptsandbox import Sandbox
from rich.table import Table

from sandbox_cli.console import console
from sandbox_cli.internal.config import settings
from sandbox_cli.internal.helpers import get_key_by_name, validate_key


async def get_images(
    *,
    key: Annotated[
        str,
        Parameter(
            name=["--key", "-k"],
            help=f"The key to access the sandbox **{'**,**'.join(x.name.get_secret_value() for x in settings.sandbox_keys)}**",
            validator=validate_key,
            group="Sandbox",
        ),
    ] = settings.sandbox_keys[0].name.get_secret_value(),
) -> None:
    """
    Get available images in the sandbox.
    """

    sandbox = Sandbox(get_key_by_name(key))
    images = await sandbox.get_images()

    table = Table()
    table.add_column("Name")
    table.add_column("Image ID", style="turquoise2")
    table.add_column("Version")
    table.add_column("Product version")
    table.add_column("Locale")

    for image in images:
        if not image.os:
            console.warning(f"{image.image_id} doesn't contain OS information")
            continue

        table.add_row(image.os.name, image.image_id, image.os.version, image.version, image.os.locale)

    console.print(table)
