from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from sandbox_cli.core.config import get_settings
from sandbox_cli.core.exceptions import ConfigError

if TYPE_CHECKING:
    from ptsandbox import SandboxKey
    from ptsandbox.models import SandboxBaseTaskResponse

    from sandbox_cli.core.config import SandboxConfig

__all__ = [
    "format_link",
    "get_key_by_name",
    "get_sandbox_config",
    "get_sandbox_key_by_host",
    "hostname",
    "validate_key",
]


def get_sandbox_config(key_name: str) -> SandboxConfig:
    """
    The ``[[sandbox]]`` entry named ``key_name``, without resolving its secrets.
    """
    for sandbox in get_settings().sandbox:
        if sandbox.name == key_name:
            return sandbox

    available = '", "'.join(x.name for x in get_settings().sandbox)
    raise ConfigError(f'Key "{key_name}" doesn\'t exist in config. Available keys: "{available}"')


def get_key_by_name(key_name: str) -> SandboxKey:
    """
    API key of the sandbox named ``key_name`` (resolves the secret).
    """
    return get_sandbox_config(key_name).sandbox_key


def hostname(host: str) -> str:
    """
    Lowercase host name without scheme and port (``Sandbox.example.com:8443`` → ``sandbox.example.com``).
    """
    parsed = urlparse(host if "//" in host else f"//{host}")
    return parsed.hostname or host.lower()


def get_sandbox_key_by_host(task_host: str) -> SandboxKey:
    for sandbox in get_settings().sandbox:
        if hostname(sandbox.host) == hostname(task_host):
            return sandbox.sandbox_key

    raise ConfigError(f"Unknown sandbox host: {task_host}")


def validate_key(_: Any, value: Any) -> None:
    """
    cyclopts validator for ``--key``; ``None`` means no key was given.
    """
    if value is not None:
        get_sandbox_config(value)


def format_link(report: SandboxBaseTaskResponse, host: str) -> str:
    """
    Link to the task in the sandbox web UI.
    """
    if not (short_report := report.get_short_report()):
        return "Unknown"
    return f"https://{host}/tasks/{short_report.scan_id}"
