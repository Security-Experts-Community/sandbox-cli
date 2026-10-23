from __future__ import annotations

import os
import tomllib
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

import pydantic
from pydantic import BaseModel, Field, SecretStr

from sandbox_cli.core.exceptions import ConfigError
from sandbox_cli.core.secrets import Secret, reveal

if TYPE_CHECKING:
    from ptsandbox import SandboxKey

__all__ = [
    "DEFAULT_DURATION",
    "DEFAULT_IMAGE",
    "LINUX_IMAGES",
    "REPORT_NAME",
    "WINDOWS_IMAGES",
    "BrowserConfig",
    "DockerConfig",
    "Platform",
    "SSHConfig",
    "SandboxConfig",
    "Settings",
    "VMImage",
    "configpath",
    "get_settings",
    "images_help",
    "key_help",
    "parse_image",
]


class VMImage(str, Enum):
    """
    Known image ids.

    Some of them are legacy and missing from current sandboxes.
    """

    ALTWORKSTATION_10_X64 = "altworkstation-10-x64"
    ASTRALINUX_SMOLENSK_X64 = "astralinux-smolensk-x64"
    REDOS_8_X64 = "redos-8-x64"
    REDOS_MUROM_X64 = "redos-murom-x64"
    UBUNTU_JAMMY_X64 = "ubuntu-jammy-x64"

    WIN10_1803_X64 = "win10-1803-x64"
    WIN10_22H2_X64 = "win10-22H2-x64"
    WIN11_23H2_X64 = "win11-23H2-x64"
    WIN7_SP1_X64 = "win7-sp1-x64"
    WIN7_SP1_X64_ICS = "win7-sp1-x64-ics"
    WIN81_UPDATE1_X64 = "win8.1-update1-x64"
    WINSERV2016_1198_X64 = "winserv2016-1198-x64"
    WINSERV2019_1879_X64 = "winserv2019-1879-x64"

    LINUX = "linux"
    WINDOWS = "windows"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)


def parse_image(value: str) -> VMImage | str:
    """
    Parse an image id into a ``VMImage`` enum, falling back to the raw string for custom images.
    """
    try:
        return VMImage(value)
    except ValueError:
        return value


def images_help() -> str:
    """
    Build the ``--image`` help text listing all known image ids.
    """
    names = [f"**{img.value}**" for img in VMImage if img not in {VMImage.LINUX, VMImage.WINDOWS}]
    return "Available images: " + ", ".join(names)


def key_help() -> str:
    """
    Build the ``--key`` help text listing all configured sandbox key names.
    """
    names = [x.name for x in get_settings().sandbox]
    if not names:
        return f"The key to access the sandbox (no keys configured in **{configpath}**)"
    return f"The key to access the sandbox **{'**, **'.join(names)}**"


class Platform(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"


class SSHConfig(BaseModel):
    username: str = ""
    password: Secret = SecretStr("")


class DockerConfig(BaseModel):
    username: str = ""
    token: Secret = SecretStr("")
    registry: str = ""
    image_name: str = Field(default="", alias="image-name")
    image_tag: str = Field(default="", alias="image-tag")

    @property
    def path(self) -> str:
        return f"{self.registry}/{self.image_name}"


class SandboxConfig(BaseModel):
    name: str = ""
    key: Secret = SecretStr("")
    host: str = ""
    max_workers: int = Field(default=8, alias="max-workers")
    description: str = ""

    ssh: SSHConfig = SSHConfig()

    @property
    def sandbox_key(self) -> SandboxKey:
        from ptsandbox import SandboxKey

        return SandboxKey(
            name=self.name,
            key=SecretStr(reveal(self.key)),
            host=self.host,
            max_workers=self.max_workers,
            description=self.description,
        )


class BrowserConfig(BaseModel):
    path: Path
    args: list[str]


LINUX_IMAGES: frozenset[VMImage] = frozenset(
    {
        VMImage.ALTWORKSTATION_10_X64,
        VMImage.ASTRALINUX_SMOLENSK_X64,
        VMImage.REDOS_8_X64,
        VMImage.REDOS_MUROM_X64,
        VMImage.UBUNTU_JAMMY_X64,
    }
)

WINDOWS_IMAGES: frozenset[VMImage] = frozenset(
    {
        VMImage.WIN10_1803_X64,
        VMImage.WIN10_22H2_X64,
        VMImage.WIN11_23H2_X64,
        VMImage.WIN7_SP1_X64,
        VMImage.WIN7_SP1_X64_ICS,
        VMImage.WIN81_UPDATE1_X64,
        VMImage.WINSERV2016_1198_X64,
        VMImage.WINSERV2019_1879_X64,
    }
)

REPORT_NAME = "report.json"
DEFAULT_IMAGE = VMImage.WIN10_22H2_X64
DEFAULT_DURATION = 300


class Settings(BaseModel):
    passwords: list[str] = ["infected", "311138", "password", "12345678", "P@ssw0rd!"]
    docker: DockerConfig = DockerConfig()
    sandbox: list[SandboxConfig] = []
    rules_path: Path | None = Field(default=None, alias="rules-path")
    browser: BrowserConfig | None = Field(default=None)

    @property
    def default_key_name(self) -> str:
        """
        Name of the first configured sandbox key, or empty string if none.
        """
        return self.sandbox[0].name if self.sandbox else ""


def _default_config_path() -> Path:
    """
    Resolve the default config path across platforms.
    """
    base = Path(os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "sandbox-cli" / "config.toml"


configpath = _default_config_path()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Load settings from the TOML config file, falling back to defaults.

    Raises ``ConfigError`` for an unreadable or invalid file. The result is cached;
    ``get_settings.cache_clear()`` reloads it.
    """
    if not configpath.exists():
        return Settings()

    try:
        with open(configpath, "rb") as fd:
            raw = tomllib.load(fd)
        settings_obj = Settings.model_validate(raw)
    except (OSError, tomllib.TOMLDecodeError, pydantic.ValidationError) as e:
        raise ConfigError(f"invalid config at {configpath}: {e}") from e

    # post-load normalisation (kept out of the model to avoid mutation side-effects)
    if settings_obj.rules_path:
        settings_obj.rules_path = settings_obj.rules_path.expanduser()
    if settings_obj.browser:
        settings_obj.browser.args.append("%s")

    return settings_obj
