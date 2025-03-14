import json
from dataclasses import dataclass
from enum import Enum


class DetectionType(str, Enum):
    """
    Enum with sandbox detections levels
    """

    silent = "silent"
    suspicious = "suspicious"
    malware = "malware"


@dataclass(frozen=True)
class Detect:
    """
    Dataclass for sandbox detect, comparable by key (weight ignored)
    """

    name: str
    weight: int | None

    def __key(self) -> tuple[str]:
        return (self.name,)

    def __hash__(self) -> int:
        return hash(self.__key())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Detect):
            return self.__key() == other.__key()
        return NotImplemented


class Detections:
    """
    Class for stroing/parsing detections from correlated-logs
    """

    detections: dict[DetectionType, set[Detect]]

    _real_name: str

    def __init__(self, trace: bytes) -> None:
        """
        trace: UN-gzipped correlated-logs bytes.
        """

        self.detections = {
            DetectionType.silent: set(),
            DetectionType.suspicious: set(),
            DetectionType.malware: set(),
        }

        for line in trace.decode().splitlines(keepends=False):
            event = json.loads(line)
            if event.get("auxiliary.type", None) == "init":
                self._real_name = event.get("object.name")
            detect_type = event.get("detect.type")
            if detect_type in DetectionType.__members__.keys():
                self.detections[DetectionType[detect_type]].add(
                    Detect(
                        name=event.get("detect.name"),
                        weight=event.get("weight", None),
                    )
                )

    def __repr__(self) -> str:
        return repr(self.detections)

    @property
    def silent(self) -> set[Detect]:
        """Only silent detects"""
        return self.detections[DetectionType.silent]

    @property
    def suspicious(self) -> set[Detect]:
        """Only suspicious detects"""
        return self.detections[DetectionType.suspicious]

    @property
    def malware(self) -> set[Detect]:
        """Only malware detects"""
        return self.detections[DetectionType.malware]

    @property
    def real_name(self) -> str:
        """Real sample name, extracted from 'init' auxiliary event"""
        return self._real_name
