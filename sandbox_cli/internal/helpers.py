import sys
from typing import Any

from ptsandbox import SandboxKey

from sandbox_cli.console import console
from sandbox_cli.internal.config import settings


def get_key_by_name(key_name: str) -> SandboxKey:
    for sandbox_key in settings.sandbox_keys:
        if sandbox_key.name == key_name:
            return sandbox_key
    raise KeyError()


def get_sandbox_key_by_host(task_host: str) -> SandboxKey:
    for sandbox_key in settings.sandbox_keys:
        if sandbox_key.host == task_host:
            return sandbox_key

    raise KeyError()


def validate_key(_: Any, value: Any) -> None:
    try:
        get_key_by_name(value)
    except KeyError:
        console.error(
            f'Key "{value}" doesn\'t exists in config. Available keys: "{'","'.join(x.name for x in settings.sandbox_keys)}"'
        )
        sys.exit(1)
