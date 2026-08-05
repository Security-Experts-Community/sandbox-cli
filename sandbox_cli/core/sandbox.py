from __future__ import annotations

from typing import TYPE_CHECKING, Any, overload

from sandbox_cli.core.config import settings
from sandbox_cli.core.exceptions import ConfigError

if TYPE_CHECKING:
    from ptsandbox import Sandbox, SandboxKey
    from ptsandbox.models import SandboxBaseTaskResponse

__all__ = [
    "format_link",
    "get_key_by_name",
    "get_sandbox_key_by_host",
    "validate_key",
]


def get_key_by_name(key_name: str) -> SandboxKey:
    for sandbox_key in settings.sandbox_keys:
        if sandbox_key.name == key_name:
            return sandbox_key
    raise KeyError(f"Key '{key_name}' not found")


def get_sandbox_key_by_host(task_host: str) -> SandboxKey:
    for sandbox_key in settings.sandbox_keys:
        if sandbox_key.host == task_host:
            return sandbox_key

    raise KeyError(f"Key with host '{task_host}' not found")


def validate_key(_: Any, value: Any) -> None:
    try:
        get_key_by_name(value)
    except KeyError:
        available = "', '".join(x.name for x in settings.sandbox_keys)
        raise ConfigError(f'Key "{value}" doesn\'t exist in config. Available keys: "{available}"') from None


@overload
def format_link(
    report: SandboxBaseTaskResponse,
    *,
    sandbox: Sandbox,
    key: SandboxKey | None = None,
) -> str: ...


@overload
def format_link(
    report: SandboxBaseTaskResponse,
    *,
    sandbox: Sandbox | None = None,
    key: SandboxKey,
) -> str: ...


def format_link(
    report: SandboxBaseTaskResponse,
    *,
    sandbox: Sandbox | None = None,
    key: SandboxKey | None = None,
) -> str:
    key = key or (sandbox.api.key if sandbox else None)

    if not key:
        raise ConfigError("Key not provided")

    if not (short_report := report.get_short_report()):
        return "Unknown"

    return f"https://{key.host}/tasks/{short_report.scan_id}"
