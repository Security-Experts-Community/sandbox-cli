from abc import ABC, abstractmethod
from pathlib import Path


class BasePlugin(ABC):
    """
    Base class for all plugins

    It is necessary to designate a single entry point
    """

    def __init__(self, trace: Path) -> None:
        self.trace = trace

    @abstractmethod
    def run(self) -> None:
        """Invoke plugin"""
        ...
