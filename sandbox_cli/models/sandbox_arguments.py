from enum import Enum

from ptsandbox.models.api import SandboxOptions, SandboxOptionsAdvanced
from pydantic import BaseModel


class ScanType(str, Enum):
    SCAN = "scan"
    RE_SCAN = "re-scan"
    SCAN_NEW = "scan-new"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)


class SandboxArguments(BaseModel):
    type: ScanType
    sandbox_key_name: str
    sandbox_options: SandboxOptions | SandboxOptionsAdvanced
