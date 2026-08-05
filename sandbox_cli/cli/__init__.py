from __future__ import annotations

import importlib.metadata
from typing import Annotated, Literal

from colorama import init
from cyclopts import App, Parameter

from sandbox_cli.console import console
from sandbox_cli.core.config import configpath, settings

init()  # enable ANSI colors on Windows

__all__ = ["app"]


def get_version() -> str:
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


def completion(
    shell: Annotated[
        Literal["bash", "zsh", "fish"],
        Parameter(
            help="Shell to generate completion for",
        ),
    ],
    /,
    *,
    install: Annotated[
        bool,
        Parameter(
            name=["--install", "-i"],
            help="Install the completion script to the default location for the current shell and add it to the RC file",
            negative="",
        ),
    ] = False,
) -> None:
    """
    Generate or install shell completion.
    """
    if install:
        path = app.install_completion(shell=shell)
        console.info(f"Completion installed to {path}")
    else:
        console.print(app.generate_completion(shell=shell), end="")


app.command(name="completion")(completion)

# Lazy-loaded commands — modules are imported only when the command is invoked,
# keeping ``--help`` and ``--version`` fast by avoiding heavy imports
app.command(
    "sandbox_cli.cli.unpack:unpack_logs",
    name=["conv", "unpack"],
    help="Convert sandbox logs into an analysis-friendly format.",
)
app.command(
    "sandbox_cli.cli.report:generate_report",
    name="report",
    help="Generate short report from sandbox scans.",
)
app.command(
    "sandbox_cli.cli.browser:open_browser",
    name="browser",
    help="Open sandbox link in the default browser.",
)

if len(settings.sandbox_keys) > 0:
    scanner_app = App(name="scanner", help="Scan with the sandbox.", help_format="markdown", console=console)
    scanner_app.command(
        "sandbox_cli.cli.scanner.scan:scan",
        name="scan",
        help="Send files to scan with the sandbox.",
    )
    scanner_app.command(
        "sandbox_cli.cli.scanner.scan_new:scan_new",
        name="scan-new",
        help="Send files to scan with the sandbox (advanced scan).",
    )
    scanner_app.command(
        "sandbox_cli.cli.scanner.re_scan:re_scan",
        name="re-scan",
        help="Send traces to re-scan.",
    )
    app.command(scanner_app)

    rules_app = App(
        name="rules",
        help="Working with raw sandbox rules.",
        help_format="markdown",
        console=console,
    )
    rules_app.command(
        "sandbox_cli.cli.rules.compile:compile_rules",
        name="compile",
        help="Get compiled rules for working with third-party services.",
    )
    rules_app.command(
        "sandbox_cli.cli.rules.test:test_rules",
        name="test",
        help="Testing written rules.",
    )
    app.command(rules_app)

    app.command(
        "sandbox_cli.cli.images:get_images",
        name="images",
        help="Get available images in the sandbox.",
    )
    app.command(
        "sandbox_cli.cli.download:download_command",
        name="download",
        help="Download any artifact from the sandbox.",
    )
    app.command(
        "sandbox_cli.cli.download:download_email",
        name="email",
        help="Upload an email and get its headers.",
    )
