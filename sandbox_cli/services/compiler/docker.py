from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, NotRequired, TypedDict

import requests.exceptions
from docker import from_env
from docker.errors import APIError, DockerException, ImageNotFound
from rich.markup import escape

from sandbox_cli.console import console
from sandbox_cli.core.config import settings
from sandbox_cli.core.exceptions import CompilerConnectionError
from sandbox_cli.services.compiler.abc import AbstractCompiler

if TYPE_CHECKING:
    from docker import DockerClient
    from docker.models.containers import Container

__all__ = ["DockerCompiler"]


class _WaitErrorDetails(TypedDict):
    Message: str


class WaitContainerResponse(TypedDict):
    """
    Response of the Docker Container Wait API.

    See https://docs.docker.com/engine/api/v1.42/#tag/Container/operation/ContainerWait
    """

    StatusCode: int
    Error: NotRequired[_WaitErrorDetails]


# Memory limit for the compilation container.
_CONTAINER_MEM_LIMIT = "2g"
# How long to wait for the container to finish before giving up.
_CONTAINER_WAIT_TIMEOUT = 1
# Generic error message when the container wait times out.
_CONTAINER_WAIT_TIMEOUT_ERROR = "container wait timed out"


class DockerCompiler(AbstractCompiler):
    """
    Compile and test rules in a local Docker container.
    """

    def __init__(self) -> None:
        try:
            self._client: DockerClient = from_env()
        except DockerException as e:
            raise CompilerConnectionError(f"Can't connect to docker: {e}") from e

    async def close(self) -> None:
        """
        Close the underlying Docker client.
        """
        self._client.close()

    async def pull_image(self) -> None:
        """
        Pull the builder image from the registry.
        """

        console.warning("Docker image not found, start pulling, be patient")

        # docker SDK calls are synchronous — offload to a thread to avoid blocking the event loop.
        await asyncio.to_thread(
            self._client.api.login,
            username=settings.docker.username,
            password=settings.docker.token,
            registry=settings.docker.registry,
        )

        image = await asyncio.to_thread(
            self._client.images.pull,
            repository=settings.docker.path,
            tag=settings.docker.image_tag,
        )

        console.info(f"Docker image successfully pulled: {image}")

    async def _ensure_image(self) -> None:
        """
        Pull the image if it is not available locally.
        """

        try:
            self._client.images.get(f"{settings.docker.path}:{settings.docker.image_tag}")
        except ImageNotFound:
            await self.pull_image()

    def _run_container(self, command: str, name: str, rules_dir: Path, compiled_rules_dir: Path) -> Container:
        """
        Create and start a detached container (synchronous).
        """

        return self._client.containers.run(
            image=f"{settings.docker.path}:{settings.docker.image_tag}",
            command=command,
            name=name,
            detach=True,
            mem_limit=_CONTAINER_MEM_LIMIT,
            volumes={
                str(rules_dir): {
                    "bind": "/rules",
                    "mode": "ro",
                },
                str(compiled_rules_dir): {
                    "bind": "/compiled-rules",
                    "mode": "rw",
                },
            },
        )

    def _stream_logs(self, container: Container) -> None:
        """
        Follow container logs and print them to the console (synchronous).
        """

        logs = container.logs(stream=True, follow=True)
        for log in logs:
            console.print(escape(log.decode()), end="")

    async def _wait_and_remove(self, container: Container) -> WaitContainerResponse:
        """
        Wait for the container to exit, then force-remove it.
        """
        try:
            exit_data: WaitContainerResponse = await asyncio.to_thread(container.wait, timeout=_CONTAINER_WAIT_TIMEOUT)
        except requests.exceptions.ReadTimeout:
            exit_data = {
                "StatusCode": -1,
                "Error": {
                    "Message": _CONTAINER_WAIT_TIMEOUT_ERROR,
                },
            }

        try:
            await asyncio.to_thread(container.remove, force=True)
        except APIError as e:
            console.error(f"Can't remove docker container: {e} {exit_data}")

        return exit_data

    async def run_docker(self, command: str, name: str, rules_dir: Path, compiled_rules_dir: Path) -> bool:
        """
        Run a command in a container; return ``True`` on success.
        """

        await self._ensure_image()

        # copy taxonomy into rules dir — required by the compiler
        local_taxonomy = rules_dir / "taxonomy"
        shutil.copytree(rules_dir.parent / "taxonomy", local_taxonomy, dirs_exist_ok=True)

        container: Container | None = None
        exit_data: WaitContainerResponse = {"StatusCode": -1}

        try:
            container = await asyncio.to_thread(self._run_container, command, name, rules_dir, compiled_rules_dir)
            await asyncio.to_thread(self._stream_logs, container)
        except Exception as e:
            console.error(f"Exception while running docker: {e}")
        finally:
            if local_taxonomy.is_dir():
                shutil.rmtree(local_taxonomy)
            if container is not None:
                exit_data = await self._wait_and_remove(container)

        return not (exit_data.get("StatusCode") != 0 or exit_data.get("Error"))

    async def compile_rules(self, rules_dir: Path, compiled_rules_dir: Path | None = None) -> bytes | None:
        with tempfile.TemporaryDirectory("sandbox-cli-docker") as tmp_dir:
            if not compiled_rules_dir:
                compiled_rules_dir = Path(tmp_dir)

            rules_dir, compiled_rules_dir = self.normalize_paths(rules_dir, compiled_rules_dir)

            status = await self.run_docker(
                command=(
                    "bash -c 'cp -r /rules /rules.copy && "
                    "package-builder correlation:compile -r /rules.copy -c /compiled-rules'"
                ),
                name="drakvuf-rules-compile",
                rules_dir=rules_dir,
                compiled_rules_dir=compiled_rules_dir,
            )

            if not status:
                return None

            return self.compress_rules(compiled_rules_dir)

    async def test_rules(self, root_rules_dir: Path, container_rules_dir: Path) -> bool:
        # create tmp folder for store compiled rules
        with tempfile.TemporaryDirectory("sandbox-cli-docker") as tmp:
            # ignore result for tests
            await self.compile_rules(root_rules_dir, Path(tmp))

            # run tests
            status = await self.run_docker(
                command=f"package-builder correlation:test -r {Path('/rules') / container_rules_dir} -c /compiled-rules",
                name="drakvuf-rules-test",
                rules_dir=root_rules_dir,
                compiled_rules_dir=Path(tmp),
            )

            return status
