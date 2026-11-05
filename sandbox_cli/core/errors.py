"""
Short, user-facing reasons for errors from the sandbox, the network and the CLI itself.
"""

from __future__ import annotations

from collections.abc import Iterator

import aiohttp
from ptsandbox.exceptions import SandboxException, SandboxUploadException, SandboxWaitTimeoutException

from sandbox_cli.core.exceptions import SandboxCliError

__all__ = ["describe_error", "is_unreachable"]


def _causes(error: BaseException) -> Iterator[BaseException]:
    """
    ``error``, the errors it was raised from and the errors of every exception group on the way.
    """
    yield error
    if isinstance(error, BaseExceptionGroup):
        for inner in error.exceptions:
            yield from _causes(inner)
    if error.__cause__ is not None:
        yield from _causes(error.__cause__)


def _connection_error(error: BaseException) -> aiohttp.ClientConnectorError | None:
    return next((e for e in _causes(error) if isinstance(e, aiohttp.ClientConnectorError)), None)


def is_unreachable(error: BaseException) -> bool:
    """
    Whether ``error`` (or what caused it) means the sandbox host can't be connected to.
    """
    return _connection_error(error) is not None


def describe_error(error: BaseException) -> str:
    """
    Turn an exception raised while running a job into a short reason.
    """
    if (connection := _connection_error(error)) is not None:
        return f"connection error • {connection}"
    match error:
        case SandboxUploadException():
            return f"an error occurred when uploading a file to the server • {error}"
        case SandboxWaitTimeoutException():
            return "got timeout while waiting"
        case aiohttp.SocketTimeoutError():
            return "got timeout while downloading results"
        case aiohttp.ClientResponseError() | SandboxException() | SandboxCliError():
            return str(error)
        case aiohttp.ClientError():
            return f"connection error • {error}"
        case _:
            return f"unexpected error • {type(error).__name__}: {error}"
