"""
The vocabulary of command line parameters.

Every concept is declared here exactly once and commands compose these
declarations: a flag has one name, one alias, one help text and one meaning
across the whole CLI (enforced by ``tests/test_cli_flags.py``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from cyclopts import Parameter, validators

from sandbox_cli.cli._converters import (
    dll_hooks_validator,
    existing,
    image_converter,
    out_dir_converter,
    out_dir_validator,
    rules_path_resolver,
)
from sandbox_cli.core.config import VMImage, get_settings, images_help, key_help
from sandbox_cli.core.sandbox import validate_key
from sandbox_cli.services.downloader import DownloadOptions

__all__ = [
    "DOWNLOAD_OPTIONS",
    "MIN_DURATION",
    "RULES",
    "SANDBOX_OPTIONS",
    "AnalysisDuration",
    "ArtifactFlags",
    "CustomCommand",
    "DllHooksDir",
    "FakeName",
    "Images",
    "IsLocal",
    "JsonOutput",
    "Key",
    "OpenBrowser",
    "OutDir",
    "RulesPath",
    "SyscallHooks",
    "UnpackFlag",
    "UploadTimeout",
    "WaitTimeout",
    "default_key",
    "sandbox_option",
    "sandbox_switch",
    "switch",
]

SANDBOX_OPTIONS = "Sandbox Options"
DOWNLOAD_OPTIONS = "Download Options"

MIN_DURATION = 10


def default_key() -> str:
    """
    Name of the first configured sandbox, the default for ``--key``.
    """
    return get_settings().default_key_name


def switch(
    name: list[str], help: str, group: str | None = None, *, validator: Callable[[Any, Any], None] | None = None
) -> Parameter:
    """
    A flag without a ``--no-...`` counterpart.
    """
    extra: dict[str, Any] = {}
    if group is not None:
        extra["group"] = group
    if validator is not None:
        extra["validator"] = validator
    return Parameter(name=name, help=help, negative="", **extra)


def sandbox_option(
    name: list[str] | str, help: str, *, validator: Callable[[Any, Any], None] | None = None
) -> Parameter:
    if validator is None:
        return Parameter(name=name, help=help, group=SANDBOX_OPTIONS)
    return Parameter(name=name, help=help, group=SANDBOX_OPTIONS, validator=validator)


def sandbox_switch(name: list[str], help: str, *, validator: Callable[[Any, Any], None] | None = None) -> Parameter:
    return switch(name, help, SANDBOX_OPTIONS, validator=validator)


Key = Annotated[
    str,
    Parameter(name=["--key", "-k"], help=key_help(), validator=validate_key, group=SANDBOX_OPTIONS),
]
OutDir = Annotated[
    Path,
    Parameter(
        name=["--out", "-o"],
        help="The path where to save the results",
        converter=out_dir_converter,
        validator=out_dir_validator,
    ),
]
OpenBrowser = Annotated[bool, switch(["--open-browser", "-ob"], "Open analysis link in the default browser")]
UnpackFlag = Annotated[bool, switch(["--unpack", "-U"], "Unpack downloaded logs (see the unpack command)")]
JsonOutput = Annotated[
    bool, switch(["--json", "-J"], "Print results as JSON lines to stdout; messages and progress go to stderr")
]

RULES = Parameter(
    name=["--rules", "-r"],
    help="The path to the folder with the rules, a platform alias (windows, linux) resolved against rules-path, "
    "or an archive with already compiled rules",
    converter=rules_path_resolver,
    validator=existing("any"),
)
"""Use as ``Annotated[Path | None, RULES]`` (optional) or ``Annotated[Path, RULES]`` (required)."""
RulesPath = Annotated[Path | None, RULES]
IsLocal = Annotated[bool, switch(["--local", "-l"], "Compile the rules locally using Docker (unix only)")]

UploadTimeout = Annotated[
    int,
    Parameter(
        name=["--upload-timeout", "-T"],
        help="Upload timeout in seconds (increase if upload big files)",
        validator=validators.Number(gt=0),
    ),
]
WaitTimeout = Annotated[
    int | None,
    Parameter(
        name=["--wait-timeout", "-W"],
        help="How long to wait for the task result in seconds (increase for heavy samples or large traces)",
        validator=validators.Number(gt=0),
    ),
]

Images = Annotated[
    set[VMImage | str] | None,
    Parameter(
        name=["--image", "-i"],
        help=f"The name of the image to scan (*don't mix different platforms*)\n{images_help()}\n\n",
        negative="",
        group=SANDBOX_OPTIONS,
        show_choices=False,
        converter=image_converter,
    ),
]
FakeName = Annotated[
    str | None,
    sandbox_option(
        ["--name", "-n"], "Fake name for the sandbox (if specified more than one file will be applied to all files)"
    ),
]
AnalysisDuration = Annotated[
    int,
    Parameter(
        name=["--timeout", "-t"],
        help="Analysis duration in seconds",
        validator=validators.Number(gte=MIN_DURATION, lt=3600),
        group=SANDBOX_OPTIONS,
    ),
]
SyscallHooks = Annotated[
    Path | None,
    sandbox_option(
        ["--syscall-hooks", "-s"],
        "Path to file with syscall hooks (file with syscall names split by newline)",
        validator=existing("file"),
    ),
]
DllHooksDir = Annotated[
    Path | None,
    sandbox_option(["--dll-hooks-dir", "-dll"], "Path to directory with dll hooks", validator=dll_hooks_validator),
]
CustomCommand = Annotated[
    str | None, sandbox_option("--cmd", "Command line for file execution `rundll32.exe {file},#1`")
]


@Parameter(name="*")
@dataclass(frozen=True, kw_only=True)
class ArtifactFlags:
    """
    Which artifacts of a finished task to download.
    """

    all: Annotated[bool, switch(["--all", "-a"], "Download all artifacts", DOWNLOAD_OPTIONS)] = False
    debug: Annotated[bool, switch(["--debug", "-d"], "Download debug artifacts", DOWNLOAD_OPTIONS)] = False
    artifacts: Annotated[
        bool, switch(["--artifacts", "-A"], "Download artifacts (files and procdumps)", DOWNLOAD_OPTIONS)
    ] = False
    files: Annotated[bool, switch(["--files", "-f"], "Download files", DOWNLOAD_OPTIONS)] = False
    crashdumps: Annotated[
        bool, switch(["--crashdumps", "-C"], "Download crashdumps (may be more than 1GB)", DOWNLOAD_OPTIONS)
    ] = False
    procdumps: Annotated[bool, switch(["--procdumps", "-p"], "Download procdumps", DOWNLOAD_OPTIONS)] = False
    amsi: Annotated[bool, switch(["--amsi", "-am"], "Download amsi-dumps", DOWNLOAD_OPTIONS)] = False
    dex: Annotated[bool, switch(["--dex", "-dx"], "Download dex-dumps", DOWNLOAD_OPTIONS)] = False
    decompress: Annotated[bool, switch(["--decompress", "-D"], "Decompress downloaded procdumps", DOWNLOAD_OPTIONS)] = (
        False
    )

    def to_options(self, **extra: bool) -> DownloadOptions:
        """
        ``DownloadOptions`` for these flags; ``extra`` sets the other categories (logs, video, sample).
        """
        return DownloadOptions(
            all=self.all,
            debug=self.debug,
            artifacts=self.artifacts,
            files=self.files,
            crashdumps=self.crashdumps,
            procdumps=self.procdumps,
            amsi=self.amsi,
            dex=self.dex,
            decompress=self.decompress,
            **extra,
        )
