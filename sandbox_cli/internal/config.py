import os
import sys
import tomllib
from enum import Enum
from pathlib import Path
from typing import Any

import pydantic
from ptsandbox import SandboxKey
from pydantic import BaseModel, Field

from sandbox_cli.console import console


class VMImage(str, Enum):
    """
    A list of all known images

    Please note that not all images are supported or available anymore (left as a legacy)
    """

    ALTWORKSTATION_X64 = "altworkstation-10-x64"
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


class Platform(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"


class Settings(BaseModel):
    class Docker(BaseModel):
        username: str = ""
        token: str = ""
        registry: str = ""
        image_name: str = Field(default="", alias="image-name")
        image_tag: str = Field(default="", alias="image-tag")

        @property
        def path(self) -> str:
            return f"{self.registry}/{self.image_name}"

    class Sandbox(BaseModel):
        class SSH(BaseModel):
            username: str = ""
            password: str = ""

        name: str = ""
        key: str = ""
        host: str = ""
        max_workers: int = Field(default=8, alias="max-workers")
        description: str = ""

        ssh: SSH = SSH()

        @property
        def sandbox_key(self) -> SandboxKey:
            return SandboxKey(
                name=self.name,
                key=self.key,
                host=self.host,
                max_workers=self.max_workers,
                description=self.description,
            )

    class Browser(BaseModel):
        path: Path
        args: list[str]

    # default settings (not changable)
    linux_images: set[VMImage] = {
        VMImage.ALTWORKSTATION_X64,
        VMImage.ASTRALINUX_SMOLENSK_X64,
        VMImage.REDOS_8_X64,
        VMImage.REDOS_MUROM_X64,
        VMImage.UBUNTU_JAMMY_X64,
    }

    windows_images: set[VMImage] = {
        VMImage.WIN10_1803_X64,
        VMImage.WIN10_22H2_X64,
        VMImage.WIN11_23H2_X64,
        VMImage.WIN7_SP1_X64,
        VMImage.WIN7_SP1_X64_ICS,
        VMImage.WIN81_UPDATE1_X64,
        VMImage.WINSERV2016_1198_X64,
        VMImage.WINSERV2019_1879_X64,
    }

    rules_archive_name_zip: str = "rules.zip"
    rules_archive_name_gz: str = "rules.tar.gz"

    report_name: str = "report.json"
    default_image: VMImage = VMImage.WIN10_22H2_X64
    default_duration: int = 300

    # post init params
    sandbox_keys: list[SandboxKey] = []

    # configurable parameters
    passwords: list[str] = ["infected", "311138", "password", "12345678", "P@ssw0rd!"]
    docker: Docker = Docker()
    sandbox: list[Sandbox] = []
    rules_path: Path | None = Field(default=None, alias="rules-path")
    browser: Browser | None = Field(default=None)

    def model_post_init(self, __context: Any) -> None:
        self.sandbox_keys = [x.sandbox_key for x in self.sandbox]
        self.rules_path = Path(self.rules_path) if self.rules_path else None
        if self.browser:
            self.browser.args.append("%s")


def load_config(path: Path) -> Settings:
    if not path.exists():
        return Settings()

    with open(path, "rb") as fd:
        raw = tomllib.load(fd)

    try:
        settings = Settings.model_validate(raw)
    except pydantic.ValidationError as e:
        console.print(f"invalid config at {path}: {e}", style="bold red")
        sys.exit(1)

    return settings


configpath = os.path.join(
    os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.environ["HOME"], ".config"),
    "sandbox-cli",
    "config.toml",
)

settings = load_config(Path(configpath))
