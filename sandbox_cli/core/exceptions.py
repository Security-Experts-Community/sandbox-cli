from __future__ import annotations

__all__ = [
    "CompilationError",
    "CompilerConnectionError",
    "ConfigError",
    "DownloadError",
    "SandboxCliError",
    "ScanError",
    "UnpackError",
]


class SandboxCliError(Exception):
    """
    Base exception for all sandbox-cli errors.
    """


class ConfigError(SandboxCliError):
    """
    Raised when the configuration is missing or invalid.
    """


class CompilationError(SandboxCliError):
    """
    Raised when rule compilation or testing fails.
    """


class ScanError(SandboxCliError):
    """
    Raised when a scan cannot be prepared or executed.
    """


class DownloadError(SandboxCliError):
    """
    Raised when artifact download fails.
    """


class UnpackError(SandboxCliError):
    """
    Raised when log unpacking fails.
    """


class CompilerConnectionError(SandboxCliError):
    """
    Raised when the compiler backend (docker/ssh) is unavailable.
    """
