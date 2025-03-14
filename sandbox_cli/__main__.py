import sys

from sandbox_cli.cli import app
from sandbox_cli.console import console


def main() -> None:
    if sys.platform == "win32":
        import asyncio

        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        app()
    except Exception:
        console.print_exception()


if __name__ == "__main__":
    main()
