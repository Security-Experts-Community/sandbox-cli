from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import aiofiles
from cyclopts import Parameter, validators
from ptsandbox import Sandbox

from sandbox_cli.cli._params import JsonOutput, Key, OutDir, default_key
from sandbox_cli.console import console
from sandbox_cli.core.exceptions import SandboxCliError
from sandbox_cli.core.progress import make_progress
from sandbox_cli.core.sandbox import get_key_by_name
from sandbox_cli.services.scanner.runner import describe_error

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
    out_dir: OutDir = Path("./downloads"),
    key: Key = default_key(),
    json_output: JsonOutput = False,
) -> None:
    """
    Upload an email and get its headers.
    """

    progress = make_progress()

    async with Sandbox(get_key_by_name(key)) as sandbox:
        with progress:

            async def _internal(email: Path, out_dir: Path) -> bool:
                task_id = progress.add_task(description=f"Fetching headers [green]{email.name}[/]")
                target = out_dir / f"{email.name}.headers"
                try:
                    async with aiofiles.open(target, "wb") as fd:
                        async for chunk in sandbox.get_email_headers(email):
                            await fd.write(chunk)
                except Exception as e:
                    target.unlink(missing_ok=True)
                    reason = describe_error(e)
                    console.error(f"[yellow]{email.name}[/] • {reason}")
                    console.emit_json({"status": "failed", "email": str(email), "reason": reason})
                    return False
                finally:
                    progress.remove_task(task_id)
                    console.terminal_progress.advance()
                console.done(f"[yellow]{email.name}[/] • {target}")
                console.emit_json({"status": "done", "email": str(email), "headers": str(target)})
                return True

            console.terminal_progress.set_total(len(emails))
            results = await asyncio.gather(*(_internal(email, out_dir) for email in emails))

    if failed := results.count(False):
        raise SandboxCliError(f"Failed to fetch headers for {failed} of {len(emails)} emails")
