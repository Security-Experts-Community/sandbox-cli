import sys
from functools import lru_cache
from pathlib import Path

from sandbox_cli.console import console
from sandbox_cli.internal.config import settings
from sandbox_cli.utils.compiler.abc import AbstractCompiler
from sandbox_cli.utils.compiler.docker import DockerCompiler
from sandbox_cli.utils.compiler.ssh import RemoteCompiler

default_out_dir: str = "compiled-rules.local.tmp"


@lru_cache
def get_compiler(*, is_local: bool) -> AbstractCompiler:
    if is_local:
        if not settings.docker.token and not settings.docker.registry:
            console.warning("If you want use local docker container specify options in config")
            sys.exit(1)

        return DockerCompiler()
    return RemoteCompiler()


async def compile_rules_internal(*, rules_dir: Path, is_local: bool, compiled_rules_dir: Path | None = None) -> bytes:
    compiler = get_compiler(is_local=is_local)

    if rules := await compiler.compile_rules(rules_dir, compiled_rules_dir):
        return rules

    console.error("Bad rules")
    sys.exit(1)


async def test_rules_internal(*, rules: Path, is_local: bool) -> None:
    compiler = get_compiler(is_local=is_local)

    root_rules_dir: Path | None = None

    # maybe bug or feature
    # don't scan folder ~/rules/<platform>/correlation to avoid stupidly long testing
    for parent in rules.parents:
        if parent.name in {"correlation", "normalization"}:
            root_rules_dir = parent
            break

    if not root_rules_dir:
        console.error(f"Invalid rule path (read help): {rules}")
        sys.exit(1)

    # Generate special path for remote container
    container_rules_dir = root_rules_dir.name / rules.relative_to(root_rules_dir)

    # after extracting special path take path without correlation/normalization suffix
    root_rules_dir = root_rules_dir.parent

    if await compiler.test_rules(root_rules_dir, container_rules_dir):
        console.info("Rules fine")
    else:
        console.error("Bad rules")
