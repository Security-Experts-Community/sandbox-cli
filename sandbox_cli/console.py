from rich.console import Console


class SandboxConsole(Console):
    INFO = "[turquoise2 bold][INFO][/]"
    WARNING = "[yellow1 bold][WARN][/]"
    ERROR = "[red3 bold][ERROR][/]"
    DONE = "[green3 bold][DONE][/]"

    def done(self, message: str) -> None:
        self.print(f"{self.DONE} {message}")

    def info(self, message: str) -> None:
        self.print(f"{self.INFO} {message}")

    def warning(self, message: str) -> None:
        self.print(f"{self.WARNING} {message}", style="bold")

    def error(self, message: str) -> None:
        self.print(f"{self.ERROR} {message}", style="bold")


console = SandboxConsole(color_system="auto", emoji=True)
