from __future__ import annotations

import io
import tarfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Self

from sandbox_cli.core.exceptions import CompilationError

__all__ = ["COMPILED_FILES", "AbstractCompiler"]

COMPILED_FILES = (
    "event_correlation_graph.json",
    "event_normalization_graph.json",
)


class AbstractCompiler(ABC):
    """
    Compile and test sandbox correlation rules.

    Two implementations exist: ``DockerCompiler`` (local docker) and
    ``RemoteCompiler`` (ssh into a sandbox host). Both share the path
    normalisation and rule-compression logic defined below.

    Use as an async context manager so resources (docker client, ssh
    connection) are always released::

        async with get_compiler(is_local=True) as compiler:
            data = await compiler.compile_rules(rules_dir, None)
    """

    @abstractmethod
    async def pull_image(self) -> None:
        """
        Pull the builder image on the target (docker host or remote).
        """
        ...

    @abstractmethod
    async def compile_rules(self, rules_dir: Path, compiled_rules_dir: Path | None) -> bytes | None:
        """
        Compile rules from ``rules_dir``; return a tar.gz blob or ``None`` on failure.
        """
        ...

    @abstractmethod
    async def test_rules(self, root_rules_dir: Path, container_rules_dir: Path) -> bool:
        """
        Test rules; return ``True`` when all tests pass.
        """
        ...

    async def close(self) -> None:  # noqa: B027 - optional override
        """
        Release resources (docker client, ssh connection). Override in subclasses.
        """
        ...

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    # --- shared helpers ----------------------------------------------------

    @staticmethod
    def normalize_paths(rules_dir: Path, compiled_rules_dir: Path) -> tuple[Path, Path]:
        """
        Validate and resolve ``rules_dir`` / ``compiled_rules_dir``.
        """

        rules_dir = rules_dir.expanduser().resolve()
        if not rules_dir.is_dir():
            raise CompilationError(f"Invalid directory with raw rules: {rules_dir}, {rules_dir.is_dir()}")

        compiled_rules_dir = compiled_rules_dir.expanduser()
        compiled_rules_dir.mkdir(exist_ok=True)
        compiled_rules_dir = compiled_rules_dir.resolve()  # until directory created, we can't resolve it

        return rules_dir, compiled_rules_dir

    @staticmethod
    def compress_rules(compiled_rules: Path) -> bytes:
        """
        Pack the two compiled JSON graphs into a tar.gz blob.
        """

        compiled_rules = compiled_rules.expanduser().resolve()

        buf = io.BytesIO()
        with tarfile.open(mode="w:gz", fileobj=buf) as tar:
            for file_name in COMPILED_FILES:
                tar.add(compiled_rules / file_name, arcname=file_name)

        return buf.getvalue()
