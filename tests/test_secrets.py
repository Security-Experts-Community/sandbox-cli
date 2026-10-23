from __future__ import annotations

import sys
from pathlib import Path

import pydantic
import pytest

from sandbox_cli.core.config import Settings
from sandbox_cli.core.exceptions import ConfigError
from sandbox_cli.core.secrets import is_set, reveal


def _sandbox(**key: object) -> Settings:
    return Settings.model_validate({"sandbox": [{"name": "main", "host": "h", **key}]})


def test_plain_string_keeps_working() -> None:
    settings = _sandbox(key="s3cr3t-key", ssh={"username": "u", "password": "s3cr3t-pass"})
    sandbox = settings.sandbox[0]

    assert reveal(sandbox.key) == "s3cr3t-key"
    assert reveal(sandbox.ssh.password) == "s3cr3t-pass"
    assert sandbox.sandbox_key.key.get_secret_value() == "s3cr3t-key"
    assert "s3cr3t" not in repr(settings)


def test_env_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SB_TEST_KEY", "from-env")
    assert reveal(_sandbox(key={"env": "SB_TEST_KEY"}).sandbox[0].key) == "from-env"


def test_missing_env_is_a_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SB_TEST_MISSING", raising=False)
    sandbox = _sandbox(key={"env": "SB_TEST_MISSING"}).sandbox[0]
    with pytest.raises(ConfigError, match="SB_TEST_MISSING"):
        reveal(sandbox.key)


def test_command_runs_only_when_used(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    command = f"{sys.executable} -c \"open({str(marker)!r}, 'w'); print('from-command')\""
    settings = _sandbox(key={"command": command})

    assert not marker.exists()
    assert is_set(settings.sandbox[0].key)
    assert not marker.exists()

    assert reveal(settings.sandbox[0].key) == "from-command"
    assert marker.exists()


def test_failing_command_is_a_config_error() -> None:
    command = f'{sys.executable} -c "import sys; sys.exit(3)"'
    with pytest.raises(ConfigError, match=r"failed \(3\)"):
        reveal(_sandbox(key={"command": command}).sandbox[0].key)


@pytest.mark.parametrize("key", [{}, {"env": "A", "command": "b"}, {"file": "x"}])
def test_invalid_references_are_rejected(key: dict[str, str]) -> None:
    with pytest.raises(pydantic.ValidationError):
        _sandbox(key=key)


def test_empty_secret_is_not_set() -> None:
    assert not is_set(Settings().docker.token)


def test_key_validation_and_links_do_not_resolve_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from sandbox_cli.core import sandbox as sandbox_module
    from sandbox_cli.core.sandbox import format_link, get_sandbox_config, validate_key

    marker = tmp_path / "ran"
    command = f"{sys.executable} -c \"open({str(marker)!r}, 'w')\""
    settings = _sandbox(key={"command": command})
    monkeypatch.setattr(sandbox_module, "get_settings", lambda: settings)

    validate_key(None, "main")
    report = SimpleNamespace(get_short_report=lambda: SimpleNamespace(scan_id="42"))
    link = format_link(report, get_sandbox_config("main").host)  # type: ignore[arg-type]

    assert link == "https://h/tasks/42"
    assert not marker.exists()
