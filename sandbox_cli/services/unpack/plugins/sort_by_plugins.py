from sandbox_cli.services.unpack.plugins.abc import BasePlugin


class SortByPlugins(BasePlugin):
    def run(self) -> None:
        base_path = self.trace / "normalized"
        groups = self.group_lines(
            base_path / "events-normalized.log",
            key_fn=lambda data: data.get("plugin"),
        )
        self.write_groups(base_path, groups)
