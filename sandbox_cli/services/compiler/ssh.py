from __future__ import annotations

import secrets
import shlex
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, cast

from asyncssh import (
    HostKeyNotVerifiable,
    SSHClientConnectionOptions,
    SSHReader,
    connect,
)

from sandbox_cli.console import console
from sandbox_cli.core.config import settings
from sandbox_cli.core.exceptions import CompilationError, CompilerConnectionError
from sandbox_cli.services.compiler.abc import COMPILED_FILES, AbstractCompiler

if TYPE_CHECKING:
    from asyncssh import SSHClientConnection, SSHClientProcess, SSHCompletedProcess

__all__ = ["RemoteCompiler"]

# Length of the random suffix used for temporary directory names.
_RANDOM_SUFFIX_LENGTH = 8
# Memory limit (in bytes) for the compilation container.
_CONTAINER_MEMORY_LIMIT = 1_000_000_000
# Base directory for temporary rule compilation on the remote host.
_REMOTE_TMP_BASE = "/tmp/sandbox-cli"


class RemoteCompiler(AbstractCompiler):
    """
    Compile and test rules on a remote sandbox host over SSH.

    Use as an async context manager so the SSH connection is always closed::

        async with RemoteCompiler() as compiler:
            data = await compiler.compile_rules(rules_dir, None)
    """

    def __init__(self) -> None:
        sandbox = settings.sandbox[0]
        self._host: str = sandbox.host
        self._username: str = sandbox.ssh.username
        self._password: str = sandbox.ssh.password
        self._client: SSHClientConnection | None = None
        self._tmp_directory: PurePosixPath | None = None

    async def close(self) -> None:
        """
        Close the SSH connection if open.
        """
        if self._client is not None:
            self._client.close()
            self._client = None

    async def _ensure_connected(self) -> SSHClientConnection:
        if self._client is not None:
            return self._client
        try:
            self._client = await connect(
                host=self._host,
                username=self._username,
                password=self._password,
                options=SSHClientConnectionOptions(public_key_auth=False),
            )
        except HostKeyNotVerifiable as e:
            raise CompilerConnectionError(
                f"Can't verify ssh-key. Execute 'ssh {self._username}@{self._host}' and type 'yes'"
            ) from e
        return self._client

    @staticmethod
    def _random_suffix() -> str:
        return secrets.token_hex(_RANDOM_SUFFIX_LENGTH // 2)

    async def _run(self, command: str, *, sudo: bool = False) -> SSHCompletedProcess:
        client = await self._ensure_connected()
        if sudo:
            return await client.run(f"sudo -k -S {command}", input=self._password + "\n")
        return await client.run(command)

    async def _run_stream(self, command: str, *, sudo: bool = False) -> SSHClientProcess[Any]:
        client = await self._ensure_connected()
        if sudo:
            command = f"sudo -k -S {command}"

        async with client.create_process(command) as process:
            if sudo and process.stdin is not None:
                process.stdin.write(self._password + "\n")

            async for line in cast(SSHReader[bytes], process.stdout):
                console.print(line.decode() if isinstance(line, bytes) else line, end="")

        return process

    async def _create_tmp_directory(self) -> None:
        self._tmp_directory = PurePosixPath(_REMOTE_TMP_BASE) / self._random_suffix()
        await self._run(f"mkdir -p {shlex.quote(str(self._tmp_directory))}")

    async def _upload_rules(self, rules_dir: Path) -> None:
        client = await self._ensure_connected()
        if self._tmp_directory is None:
            raise CompilationError("Temporary directory not created")

        tmp_dir = Path(tempfile.mkdtemp(prefix="sandbox-cli-rules-"))
        try:
            arcname = shutil.make_archive(str(tmp_dir / "rules"), "zip", rules_dir)
            async with client.start_sftp_client() as ftp:
                await ftp.put(arcname, f"{self._tmp_directory}")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        rules_remote = shlex.quote(str(self._tmp_directory / "rules"))
        compiled_remote = shlex.quote(str(self._tmp_directory / "compiled-rules"))
        rules_zip_remote = shlex.quote(str(self._tmp_directory / "rules.zip"))
        await self._run(
            f"mkdir -p {rules_remote} && "
            f"mkdir -p {compiled_remote} && "
            f"unzip -d {rules_remote} {rules_zip_remote} >/dev/null"
        )

    async def _cleanup(self, rules_dir: Path) -> None:
        if self._tmp_directory is not None:
            await self._run(f"rm -rf {shlex.quote(str(self._tmp_directory))}")
        shutil.rmtree(rules_dir / "taxonomy", ignore_errors=True)

    async def _compile_on_server(self) -> None:
        if self._tmp_directory is None:
            raise CompilationError("Temporary directory not created")

        container_name = self._random_suffix()
        compiled_remote = shlex.quote(str(self._tmp_directory / "compiled-rules"))
        rules_remote = shlex.quote(str(self._tmp_directory / "rules"))
        image = shlex.quote(f"{settings.docker.path}:{settings.docker.image_tag}")

        result = await self._run(
            command=(
                f"ctr run --rm --memory-limit={_CONTAINER_MEMORY_LIMIT} "
                f"--mount type=bind,src={compiled_remote},dst=/compiled-rules,options=rbind:rw "
                f"--mount type=bind,src={rules_remote},dst=/rules,options=rbind:rw "
                f"{image} {shlex.quote(container_name)} package-builder correlation:compile "
                f"-r /rules -c /compiled-rules"
            ),
            sudo=True,
        )
        if result.exit_status:
            if result.stderr:
                value = result.stderr
                console.print(value.decode() if isinstance(value, bytes) else value)
            raise CompilationError("failed to compile rules on the remote server")

    async def _download_compiled_rules(self) -> bytes:
        client = await self._ensure_connected()
        if self._tmp_directory is None:
            raise CompilationError("Temporary directory not created")

        compiled_remote = shlex.quote(str(self._tmp_directory / "compiled-rules"))
        archive_remote = shlex.quote(str(self._tmp_directory / "compiled-rules.tar.gz"))
        await self._run(f"tar -C {compiled_remote} -czf {archive_remote} " + " ".join(COMPILED_FILES))

        async with client.start_sftp_client() as ftp:
            async with ftp.open(path=self._tmp_directory / "compiled-rules.tar.gz", pflags_or_mode="rb") as fd:
                data: bytes = await fd.read()

        return data

    async def pull_image(self) -> None:
        """
        Update the builder image on the remote server.
        """
        image = shlex.quote(f"{settings.docker.path}:{settings.docker.image_tag}")
        credentials = shlex.quote(f"{settings.docker.username}:{settings.docker.token}")

        process = await self._run(f"ctr image pull --user {credentials} {image}", sudo=True)

        if process.exit_status != 0:
            console.error("Failed to update docker image on server")
            for stream in (process.stdout, process.stderr):
                if stream:
                    console.print(stream.decode() if isinstance(stream, bytes) else stream)
            raise CompilerConnectionError("Failed to update docker image on server")

        console.info("Docker image successfully updated on server")

    async def compile_rules(self, rules_dir: Path, compiled_rules_dir: Path | None) -> bytes | None:
        rules_dir = rules_dir.expanduser().resolve()
        if not rules_dir.is_dir():
            raise CompilationError(f"Invalid rules directory: {rules_dir}")

        # always use the latest version of taxonomy
        shutil.copytree(rules_dir.parent / "taxonomy", rules_dir / "taxonomy", dirs_exist_ok=True)

        try:
            await self._create_tmp_directory()
            await self._upload_rules(rules_dir)
            await self._compile_on_server()
            return await self._download_compiled_rules()
        finally:
            await self._cleanup(rules_dir)

    async def test_rules(self, root_rules_dir: Path, container_rules_dir: Path) -> bool:
        # always use the latest version of taxonomy
        shutil.copytree(root_rules_dir.parent / "taxonomy", root_rules_dir / "taxonomy", dirs_exist_ok=True)

        process: SSHClientProcess[Any] | None = None
        try:
            await self._create_tmp_directory()
            await self._upload_rules(root_rules_dir)
            await self._compile_on_server()

            if self._tmp_directory is None:
                raise CompilationError("Temporary directory not created")

            container_name = self._random_suffix()
            compiled_remote = shlex.quote(str(self._tmp_directory / "compiled-rules"))
            rules_remote = shlex.quote(str(self._tmp_directory / "rules" / container_rules_dir))
            image = shlex.quote(f"{settings.docker.path}:{settings.docker.image_tag}")

            process = await self._run_stream(
                (
                    f"ctr run --rm --memory-limit={_CONTAINER_MEMORY_LIMIT} "
                    f"--mount type=bind,src={compiled_remote},dst=/compiled-rules,options=rbind:rw "
                    f"--mount type=bind,src={rules_remote},dst=/rules,options=rbind:rw "
                    f"{image} {shlex.quote(container_name)} package-builder correlation:test "
                    f"-r /rules -c /compiled-rules"
                ),
                sudo=True,
            )
        finally:
            await self._cleanup(root_rules_dir)

        return process is not None and process.exit_status == 0
