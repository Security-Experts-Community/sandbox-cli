import sys
from http import HTTPStatus

import aiohttp
import aiohttp.client_exceptions

from sandbox_cli.cli import app
from sandbox_cli.console import console


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
    except Exception:
        console.print_exception()


if __name__ == "__main__":
    main()
