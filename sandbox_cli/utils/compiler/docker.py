import shutil
import sys
import tempfile
from pathlib import Path

import requests.exceptions
from docker import DockerClient, from_env
from docker.errors import APIError, DockerException, ImageNotFound
from docker.models.containers import Container
from rich.markup import escape

from sandbox_cli.console import console
from sandbox_cli.internal.config import settings
from sandbox_cli.utils.compiler.abc import AbstractCompiler


class DockerCompiler(AbstractCompiler):
    client: DockerClient

    def __init__(self) -> None:
        super().__init__()
        try:
            self.client = from_env()
        except DockerException as e:
            console.error(f"Can't connect to docker: {e}")
            sys.exit(1)

    async def pull_image(self) -> None:
        """
        When image not found start pulling from remote
        """

        console.warning("Docker image not found, start pulling, be patient")
        self.client.api.login(
            username=settings.docker.username,
            password=settings.docker.token,
            registry=settings.docker.registry,
        )

        image = self.client.images.pull(repository=settings.docker.path, tag=settings.docker.image_tag)
        console.info(f"Docker image successfully pulled: {image}")

    async def run_docker(self, command: str, name: str, rules_dir: Path, compiled_rules_dir: Path) -> bool:
        """
        Start docker container with given command
        :return True - if command was successfull, False - if some bad stuff happens
        """

        try:
            self.client.images.get(f"{settings.docker.path}:{settings.docker.image_tag}")
        except ImageNotFound:
            await self.pull_image()

        # need copy taxonomy in rules dir otherwise compiler failed
        local_taxonomy = rules_dir / "taxonomy"
        shutil.copytree(rules_dir.parent / "taxonomy", local_taxonomy)

        container: Container | None = None
        exit_data: dict[str, str | int] = {}
        try:
            container = self.client.containers.run(
                image=f"{settings.docker.path}:{settings.docker.image_tag}",
                command=command,
                name=name,
                detach=True,
                mem_limit="2g",
                volumes={
                    str(rules_dir): {"bind": "/rules", "mode": "ro"},
                    str(compiled_rules_dir): {"bind": "/compiled-rules", "mode": "rw"},
                },
            )

            assert container is not None

            logs = container.logs(stream=True, follow=True)
            for log in logs:
                console.print(escape(log.decode()), end="")
        except (KeyboardInterrupt, Exception) as e:  # pylint: disable=broad-exception-caught
            console.error(f"Exception while running docker: {e}")
        finally:
            if local_taxonomy.is_dir():
                shutil.rmtree(local_taxonomy)

            if container:
                try:
                    exit_data = container.wait(timeout=1)  # type: ignore
                except requests.exceptions.ReadTimeout:
                    exit_data = {"Error": "some shit happened", "StatusCode": -1}

                try:
                    container.remove(force=True)
                except APIError as e:
                    console.error(f"Can't remove docker image: {e} {exit_data}")

        if exit_data.get("StatusCode") != 0 or exit_data.get("Error"):
            return False

        return True

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
