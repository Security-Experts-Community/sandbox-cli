"""
Register all commands here
"""

from colorama import init
from cyclopts import App

from sandbox_cli.cli.reporter import generate_report, open_browser
from sandbox_cli.cli.unpack import unpack_logs
from sandbox_cli.console import console
from sandbox_cli.internal.config import configpath, settings

init()  # colorama stuff for working on windows


def get_version() -> str:
    import importlib.metadata

    version = importlib.metadata.version("sandbox-cli")
    return f"sandbox-cli {version}"


app = App(
    name="sandbox-cli",
    help="Work with sandbox like a pro"
    + (
        f"\n\nTo access other commands, specify at least one sandbox in the config at **{configpath}**"
        if len(settings.sandbox_keys) == 0
        else ""
    ),
    help_format="markdown",
    version=get_version,
    console=console,
)

app.register_install_completion_command(add_to_startup=False)

app.command(name=["conv", "unpack"])(unpack_logs)
app.command(name="report")(generate_report)
app.command(name="browser")(open_browser)

if len(settings.sandbox_keys) > 0:
    from sandbox_cli.cli.downloader import download_command, download_email
    from sandbox_cli.cli.images import get_images
    from sandbox_cli.cli.rules import rules
    from sandbox_cli.cli.scanner import scanner

    app.command(scanner)
    app.command(rules)
    app.command(name="images")(get_images)
    app.command(name="download")(download_command)
    app.command(name="email")(download_email)
