from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import aiofiles
from cyclopts import Parameter, validators
from ptsandbox import Sandbox

from sandbox_cli.cli._converters import out_dir_converter, out_dir_validator
from sandbox_cli.core.config import key_help, settings
from sandbox_cli.core.progress import make_progress
from sandbox_cli.core.sandbox import get_key_by_name, validate_key

__all__ = ["download_email"]


async def download_email(
    emails: Annotated[
        list[Path],
        Parameter(
            help="The path to the email files",
            validator=validators.Path(exists=True),
        ),
    ],
    /,
    *,
    out_dir: Annotated[
        Path,
        Parameter(
            name=["--out", "-o"],
            help="Output directory",
            converter=out_dir_converter,
            validator=out_dir_validator,
        ),
    ] = Path("./downloads"),
    key: Annotated[
        str,
        Parameter(
            name=["--key", "-k"],
            help=key_help(),
            validator=validate_key,
            group="Sandbox",
        ),
    ] = settings.default_key_name,
) -> None:
    """
    Upload an email and get its headers.
    """

    progress = make_progress()

    async with Sandbox(get_key_by_name(key)) as sandbox:
        with progress:

            async def _internal(email: Path, out_dir: Path) -> None:
                task_id = progress.add_task(description=f"Fetching headers [green]{email.name}[/]")
                try:
                    async with aiofiles.open(out_dir / f"{email}.headers", "wb") as fd:
                        async for chunk in sandbox.get_email_headers(email):
                            await fd.write(chunk)
                finally:
                    progress.remove_task(task_id)

            await asyncio.gather(*(_internal(email, out_dir) for email in emails))
