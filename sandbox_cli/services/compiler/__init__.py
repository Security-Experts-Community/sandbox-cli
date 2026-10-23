from __future__ import annotations

from sandbox_cli.core.config import get_settings
from sandbox_cli.core.exceptions import ConfigError
from sandbox_cli.core.secrets import is_set
from sandbox_cli.services.compiler.abc import AbstractCompiler
from sandbox_cli.services.compiler.docker import DockerCompiler
from sandbox_cli.services.compiler.ssh import RemoteCompiler

__all__ = [
    "AbstractCompiler",
    "DockerCompiler",
    "RemoteCompiler",
    "get_compiler",
]


def get_compiler(*, is_local: bool) -> AbstractCompiler:
    """
    Create a compiler for local docker or the remote sandbox host.

    Use it as an async context manager to release its resources::

        async with get_compiler(is_local=True) as compiler:
            data = await compiler.compile_rules(rules_dir, None)
    """
    if is_local:
        docker = get_settings().docker
        if not is_set(docker.token) and not docker.registry:
            raise ConfigError("If you want use local docker container specify options in config")

        return DockerCompiler()
    return RemoteCompiler()
