from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

CONFIG = """
passwords = ["infected"]

[[sandbox]]
name = "main"
key = "token-main"
host = "sandbox.example.com"
max-workers = 4

[[sandbox]]
name = "second"
key = "token-second"
host = "second.example.com"
"""


def pytest_configure(config: pytest.Config) -> None:
    config_home = Path(tempfile.mkdtemp(prefix="sandbox-cli-tests-"))
    (config_home / "sandbox-cli").mkdir()
    (config_home / "sandbox-cli" / "config.toml").write_text(CONFIG, encoding="utf-8")

    os.environ.pop("APPDATA", None)
    os.environ["XDG_CONFIG_HOME"] = str(config_home)
    os.environ["SANDBOX_CLI_TERM_PROGRESS"] = "0"
    os.environ["SANDBOX_CLI_SYNC_OUTPUT"] = "0"
    os.environ["NO_COLOR"] = "1"
    os.environ["COLUMNS"] = "120"
