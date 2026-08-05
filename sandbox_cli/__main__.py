import os
import sys
from http import HTTPStatus

import aiohttp
import aiohttp.client_exceptions

from sandbox_cli.cli import app
from sandbox_cli.console import console
from sandbox_cli.core.exceptions import SandboxCliError


def main() -> None:
    if sys.platform == "win32":
        import asyncio

        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        app()
    except aiohttp.client_exceptions.ClientResponseError as e:
        # global handler for 401 error
        if e.status == HTTPStatus.UNAUTHORIZED:
            console.error(f"The specified token is not valid. {e}")
    except SandboxCliError as e:
        console.error(str(e))
    except KeyboardInterrupt:
        console.warning("Operation cancelled")
        sys.exit(130)
    except Exception as e:
        # Show a concise error by default; full traceback only with DEBUG env var
        # (see https://no-color.org/ style conventions for CLI tools).
        if os.environ.get("DEBUG"):
            console.print_exception()
        else:
            console.error(f"{type(e).__name__}: {e}")
            console.info("Set DEBUG=1 for a full traceback.")


if __name__ == "__main__":
    main()
