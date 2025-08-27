import sys
import webbrowser
from pathlib import Path
from typing import Any, overload

from ptsandbox import Sandbox, SandboxKey
from ptsandbox.models import SandboxBaseTaskResponse

from sandbox_cli.console import console
from sandbox_cli.internal.config import settings
from sandbox_cli.models.sandbox_arguments import SandboxArguments


def get_key_by_name(key_name: str) -> SandboxKey:
    for sandbox_key in settings.sandbox_keys:
        if sandbox_key.name.get_secret_value() == key_name:
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
        available = "', '".join(x.name.get_secret_value() for x in settings.sandbox_keys)
        console.error(
            f'Key "{value}" doesn\'t exist in config. Available keys: "{available}"'
        )
        sys.exit(1)


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
        console.error("Key not provided")
        sys.exit(1)

    if not (short_report := report.get_short_report()):
        return "Unknown"

    return f"https://{key.host}/tasks/{short_report.scan_id}"


def save_scan_arguments(out_dir: Path, scan_args: SandboxArguments) -> None:
    scan_config_path = out_dir / "scan_config.json"
    scan_config_path.write_text(scan_args.model_dump_json(exclude="debug_options", indent=4), encoding="utf-8")


def open_link(link: str) -> None:
    if settings.browser is not None:
        webbrowser.register("new_default_browser", None, webbrowser.GenericBrowser([settings.browser.path, *settings.browser.args]), preferred=True)
        if not webbrowser.open(link):
            console.error("Can't open link in the specified browser. Please check browser path and args.")
        return

    if not webbrowser.open_new_tab(link):
        console.error("Can't open link in the default browser. Try adding path and args for your browser to the config file.")
