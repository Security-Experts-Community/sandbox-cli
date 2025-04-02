import os
import random
import shutil
import string
import sys
from pathlib import Path, PurePosixPath
from typing import Any, cast

from asyncssh import (
    HostKeyNotVerifiable,
    SSHClientConnection,
    SSHClientConnectionOptions,
    SSHClientProcess,
    SSHCompletedProcess,
    SSHReader,
    connect,
)

from sandbox_cli.console import console
from sandbox_cli.internal.config import settings
from sandbox_cli.utils.compiler.abc import AbstractCompiler


class RemoteCompiler(AbstractCompiler):
    host: str
    username: str
    password: str
    client: SSHClientConnection | None = None
    tmp_directory: PurePosixPath

    def __init__(self) -> None:
        super().__init__()
        self.host = settings.sandbox[0].host
        self.username = settings.sandbox[0].ssh.username
        self.password = settings.sandbox[0].ssh.password

    def _generate_random_string(self) -> str:
        return "".join(random.choice(string.ascii_lowercase) for _ in range(8))

    async def _init_ssh_client(self) -> None:
        if not self.client:
            try:
                self.client = await connect(
                    host=self.host,
                    username=self.username,
                    password=self.username,
                    options=SSHClientConnectionOptions(public_key_auth=False),
                )
            except HostKeyNotVerifiable:
                console.error(f"Can't verify ssh-key. Execute 'ssh {self.username}@{self.host}' and type 'yes'")
                sys.exit(1)

    async def _run_command(self, command: str, is_sudo: bool = False) -> SSHCompletedProcess:
        await self._init_ssh_client()
        assert self.client is not None

        if is_sudo:
            command = f"echo {self.password} | sudo -k -S {command}"

        return await self.client.run(command)

    async def _run_stream_command(self, command: str, is_sudo: bool = False) -> SSHClientProcess[Any]:
        await self._init_ssh_client()
        assert self.client is not None

        if is_sudo:
            command = f"echo {self.password} | sudo -k -S {command}"

        async with self.client.create_process(command) as process:
            async for line in cast(SSHReader[bytes], process.stdout):
                print(f"{line.decode() if isinstance(line, bytes) else line}", end="")

        return process

    async def _create_tmp_directory(self) -> None:
        self.tmp_directory = PurePosixPath("/tmp/sandbox-cli") / self._generate_random_string()
        await self._run_command(f"mkdir -p {self.tmp_directory}")

    async def _upload_rules(self, rules_dir: Path) -> None:
        assert self.client is not None

        arcname = shutil.make_archive("rules", "zip", rules_dir)
        async with self.client.start_sftp_client() as ftp:
            await ftp.put(arcname, f"{self.tmp_directory}")
        os.remove(arcname)

        await self._run_command(
            f"""
                mkdir -p {self.tmp_directory / "rules"} &&
                mkdir -p {self.tmp_directory / "compiled-rules"} &&
                unzip -d {self.tmp_directory / "rules"} {self.tmp_directory / "rules.zip"} >/dev/null
            """
        )

    async def _cleanup(self, rules_dir: Path) -> None:
        await self._run_command(f"rm -rf {self.tmp_directory}")
        shutil.rmtree(rules_dir / "taxonomy")

    async def _compile_rules_on_server(self) -> None:
        # generate random container name for avoid collision with several peoples
        result = await self._run_command(
            command=f'ctr run --rm --memory-limit=1000000000 \
            --mount type=bind,src={self.tmp_directory / "compiled-rules"},dst=/compiled-rules,options=rbind:rw \
            --mount type=bind,src={self.tmp_directory / "rules"},dst=/rules,options=rbind:rw \
            "{settings.docker.path}:{settings.docker.image_tag}" {self._generate_random_string()} package-builder correlation:compile -r /rules -c /compiled-rules',
            is_sudo=True,
        )
        if result.exit_status:
            console.log("failed to compile rules", style="bold red")
            console.print(result.stderr)
            sys.exit(1)

    async def _download_compiled_rules(self) -> bytes:
        assert self.client is not None

        await self._run_command(
            f"tar -C {self.tmp_directory / 'compiled-rules'} -czvf {self.tmp_directory / 'compiled-rules.tar.gz'} event_normalization_graph.json event_correlation_graph.json"
        )

        async with self.client.start_sftp_client() as ftp:
            fd = await ftp.open(path=self.tmp_directory / "compiled-rules.tar.gz", pflags_or_mode="rb")
            data: bytes = await fd.read()

        return data

    async def pull_image(self) -> None:
        """Update image on remote server"""

        process = await self._run_command(
            f'ctr image pull --user "{settings.docker.username}:{settings.docker.token}" "{settings.docker.path}:{settings.docker.image_tag}"',
            is_sudo=True,
        )

        if process.exit_status != 0:
            console.error("Failed to update docker image on server")

            if process.stdout:
                value = process.stdout
                console.log(f"{value.decode() if isinstance(value, bytes) else value}")
            if process.stderr:
                value = process.stderr
                console.log(f"{value.decode() if isinstance(value, bytes) else value}")

            sys.exit(1)

        console.info("Docker image successfully updated on server")

    async def compile_rules(self, rules_dir: Path, compiled_rules_dir: Path | None) -> bytes | None:
        """
        Compile rules on remote server
        :params rules_dir path with rules
        """

        rules_dir = rules_dir.expanduser().resolve()
        if not rules_dir.is_dir():
            console.error(f"Invalid rules directory: {rules_dir}")
            sys.exit(1)

        # always take new version of taxonomy
        shutil.copytree(rules_dir.parent / "taxonomy", rules_dir / "taxonomy", dirs_exist_ok=True)

        compiled_rules: bytes | None = None
        try:
            # prepare folder
            await self._create_tmp_directory()

            # upload rules for compilation
            await self._upload_rules(rules_dir)

            await self._compile_rules_on_server()
            compiled_rules = await self._download_compiled_rules()
        finally:
            # cleanup
            await self._cleanup(rules_dir)

        return compiled_rules

    async def test_rules(self, root_rules_dir: Path, container_rules_dir: Path) -> bool:
        # always take new version of taxonomy
        shutil.copytree(root_rules_dir.parent / "taxonomy", root_rules_dir / "taxonomy", dirs_exist_ok=True)

        try:
            # prepare folder
            await self._create_tmp_directory()

            # upload rules for compilation
            await self._upload_rules(root_rules_dir)

            await self._compile_rules_on_server()

            # generate random container name for avoid collision with several peoples
            process = await self._run_stream_command(
                f'ctr run --rm --memory-limit=1000000000 \
                --mount type=bind,src={self.tmp_directory / "compiled-rules"},dst=/compiled-rules,options=rbind:rw \
                --mount type=bind,src={self.tmp_directory / "rules" / container_rules_dir},dst=/rules,options=rbind:rw \
                "{settings.docker.path}:{settings.docker.image_tag}" {self._generate_random_string()} package-builder correlation:test -r /rules -c /compiled-rules',
                is_sudo=True,
            )
        finally:
            # cleanup
            await self._cleanup(root_rules_dir)

        return process.exit_status == 0
