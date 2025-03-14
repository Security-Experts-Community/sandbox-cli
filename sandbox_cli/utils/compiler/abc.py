import io
import sys
import tarfile
from abc import ABC, abstractmethod
from pathlib import Path

from sandbox_cli.console import console


class AbstractCompiler(ABC):
    @abstractmethod
    async def pull_image(self) -> None:
        pass

    @abstractmethod
    async def compile_rules(self, rules_dir: Path, compiled_rules_dir: Path | None) -> bytes | None:
        pass

    @abstractmethod
    async def test_rules(self, root_rules_dir: Path, container_rules_dir: Path) -> bool:
        pass

    def normalize_paths(self, rules_dir: Path, compiled_rules_dir: Path) -> tuple[Path, Path]:
        """
        Check and normalize rules_dir and compiled_rules_dir
        """

        rules_dir = rules_dir.expanduser().resolve()
        if not rules_dir.is_dir():
            console.error(f"Invalid directory with raw rules: {rules_dir}, {rules_dir.is_dir()}")
            sys.exit(1)

        compiled_rules_dir = compiled_rules_dir.expanduser()
        compiled_rules_dir.mkdir(exist_ok=True)
        compiled_rules_dir = compiled_rules_dir.resolve()  # until directory created, we can't resolve it

        return rules_dir, compiled_rules_dir

    def compress_rules(self, compiled_rules: Path) -> bytes:
        compiled_rules = compiled_rules.expanduser().resolve()

        fake_file = io.BytesIO()

        with tarfile.open(mode="w:gz", fileobj=fake_file) as tar:
            for file_name in [
                "event_correlation_graph.json",
                "event_normalization_graph.json",
            ]:  # compiled_rules.glob("*.json")
                tar.add(compiled_rules / file_name, arcname=file_name)

        return fake_file.getvalue()
