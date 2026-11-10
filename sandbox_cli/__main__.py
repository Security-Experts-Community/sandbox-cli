from __future__ import annotations

import os
import sys
from http import HTTPStatus
from typing import NoReturn

from sandbox_cli.console import console
from sandbox_cli.core.exceptions import SandboxCliError


def _http_status(error: BaseException) -> int | None:
    """
    Return the HTTP status of an aiohttp response error, ``None`` otherwise.

    Looks aiohttp up in ``sys.modules``: if nothing imported it, the error can't come from it.
    """
    client_exceptions = sys.modules.get("aiohttp.client_exceptions")
    if client_exceptions is not None and isinstance(error, client_exceptions.ClientResponseError):
        return int(error.status)
    return None


def _leaves(error: BaseException) -> list[BaseException]:
    """
    The errors inside (nested) exception groups, or just ``error``.
    """
    if isinstance(error, BaseExceptionGroup):
        return [leaf for inner in error.exceptions for leaf in _leaves(inner)]
    return [error]


def _json_requested(argv: list[str]) -> bool:
    return any(arg in {"--json", "-J"} for arg in argv)


def _fail(reason: str, *, printed: bool = False, exit_code: int = 1) -> NoReturn:
    """
    Report an error (also as a JSON line with ``--json``) and exit with the given code.
    """
    if not printed:
        console.error(reason)
    console.emit_json({"status": "error", "reason": reason})
    sys.exit(exit_code)


def main() -> None:
    if sys.platform == "win32":
        import asyncio

        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    json_mode = _json_requested(sys.argv[1:])
    if json_mode:
        console.use_stderr_for_messages()

    try:
        from cyclopts import CycloptsError

        from sandbox_cli.cli import app

        try:
            app(exit_on_error=not json_mode)
        except CycloptsError as e:
            _fail(str(e), printed=True, exit_code=2)
    except KeyboardInterrupt:
        console.warning("Operation cancelled")
        console.emit_json({"status": "error", "reason": "cancelled"})
        sys.exit(130)
    except Exception as group:
        error, *others = _leaves(group)
        more = f" (+{len(others)} more)" if others else ""
        if isinstance(error, SandboxCliError):
            _fail(f"{error}{more}")
        if _http_status(error) == HTTPStatus.UNAUTHORIZED:
            _fail(f"The specified token is not valid. {error}{more}")
        if os.environ.get("DEBUG"):
            console.print_exception()
            console.emit_json({"status": "error", "reason": f"{type(error).__name__}: {error}{more}"})
            sys.exit(1)
        # Show a concise error by default; full traceback only with DEBUG env var.
        reason = f"{type(error).__name__}: {error}{more}"
        console.error(reason)
        console.info("Set DEBUG=1 for a full traceback.")
        _fail(reason, printed=True)
    finally:
        console.terminal_progress.reset()


if __name__ == "__main__":
    main()
