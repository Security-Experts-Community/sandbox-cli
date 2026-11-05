"""
Short, user-facing reasons for errors from the sandbox, the network and the CLI itself.
"""

from __future__ import annotations

import aiohttp
from ptsandbox.exceptions import SandboxException, SandboxUploadException, SandboxWaitTimeoutException

from sandbox_cli.core.exceptions import SandboxCliError

__all__ = ["describe_error"]


def describe_error(error: BaseException) -> str:
    """
    Turn an exception raised while running a job into a short reason.
    """
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
