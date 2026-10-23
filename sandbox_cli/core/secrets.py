"""
Secrets in the config file: plain strings, environment variables or commands.

::

    key = "plain token"
    key = { env = "SANDBOX_KEY" }
    key = { command = "pass show sandbox/staging" }

Environment variables and commands are resolved on first use, so commands that
don't need a secret (``--help``, other sandboxes) never run them.
"""

from __future__ import annotations

import os
import subprocess
from functools import cache
from typing import Self

from pydantic import BaseModel, ConfigDict, SecretStr, model_validator

from sandbox_cli.core.exceptions import ConfigError

__all__ = ["Secret", "SecretRef", "is_set", "reveal"]


class SecretRef(BaseModel):
    """
    A secret stored outside the config file.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    env: str | None = None
    command: str | None = None

    @model_validator(mode="after")
    def _exactly_one_source(self) -> Self:
        if (self.env is None) == (self.command is None):
            raise ValueError('specify exactly one of "env" or "command"')
        return self

    def resolve(self) -> str:
        if self.env is not None:
            if (value := os.environ.get(self.env)) is None:
                raise ConfigError(f"Environment variable {self.env} with a secret is not set")
            return value
        assert self.command is not None
        return _run_command(self.command)

    def __repr__(self) -> str:
        source = f"env={self.env!r}" if self.env is not None else f"command={self.command!r}"
        return f"SecretRef({source})"


Secret = SecretStr | SecretRef


@cache
def _run_command(command: str) -> str:
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
    except OSError as e:
        raise ConfigError(f"Can't run secret command {command!r}: {e}") from e
    if result.returncode != 0:
        raise ConfigError(f"Secret command {command!r} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.rstrip("\r\n")


def reveal(secret: Secret) -> str:
    """
    The secret value, resolving environment variables and commands.
    """
    if isinstance(secret, SecretRef):
        return secret.resolve()
    return secret.get_secret_value()


def is_set(secret: Secret) -> bool:
    """
    Whether the config sets the secret (without resolving it).
    """
    return isinstance(secret, SecretRef) or bool(secret.get_secret_value())
