from __future__ import annotations

from cyclopts import App

from sandbox_cli.cli.rules.compile import compile_rules
from sandbox_cli.cli.rules.test import test_rules

__all__ = ["rules"]

rules = App(
    name="rules",
    help="Working with raw sandbox rules.",
    help_format="markdown",
)

rules.command(name="compile")(compile_rules)
rules.command(name="test")(test_rules)
