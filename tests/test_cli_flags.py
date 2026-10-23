"""
Every flag must mean the same thing in every command.

A flag that appears in several commands has to come from the same
declaration in ``sandbox_cli/cli/_params.py``: same names, help and group.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from cyclopts import App

from sandbox_cli.cli import app

_DEFAULT_GROUPS = {"Arguments", "Parameters"}


def _leaf_commands(root: App, path: tuple[str, ...] = ()) -> Iterator[tuple[str, App]]:
    for name in root:
        if name.startswith("-"):
            continue
        sub = root[name]
        if sub.default_command is not None:
            yield " ".join((*path, name)), sub
        yield from _leaf_commands(sub, (*path, name))


def _flags() -> dict[str, set[tuple[tuple[str, ...], str, str]]]:
    definitions: dict[str, set[tuple[tuple[str, ...], str, str]]] = defaultdict(set)
    for _command, sub in _leaf_commands(app):
        for argument in sub.assemble_argument_collection():
            names = tuple(n for n in argument.parameter.name or () if n.startswith("-"))
            if not names or not argument.parse:
                continue
            group = ",".join(g.name for g in argument.parameter.group or () if g.name not in _DEFAULT_GROUPS)
            for name in names:
                definitions[name].add((names, argument.parameter.help or "", group))
    return definitions


def test_flags_have_a_single_definition() -> None:
    conflicts = {flag: defs for flag, defs in _flags().items() if len(defs) > 1}
    assert not conflicts, "\n".join(f"{flag}: {sorted(defs)}" for flag, defs in conflicts.items())


def test_shared_flags_are_really_shared() -> None:
    flags = _flags()
    for flag in ("--key", "--out", "--rules", "--unpack", "--wait-timeout", "--all", "--crashdumps"):
        assert flag in flags, flag
