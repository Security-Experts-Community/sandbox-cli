from __future__ import annotations

from typing import TYPE_CHECKING

import orjson
from ptsandbox.models import ArtifactType, EngineSubsystem
from ptsandbox.utils import Detections

if TYPE_CHECKING:
    from ptsandbox.models import SandboxBaseTaskResponse

_STATIC_SUBSYSTEMS = {EngineSubsystem.STATIC, EngineSubsystem.AV}


def extract_verdict_from_trace(trace: bytes, suspicious: bool = False) -> list[str]:
    d = Detections(trace)
    malware = {detect.name for detect in d.malware}
    if not suspicious:
        return list(malware)

    return list(malware) + sorted({detect.name for detect in d.suspicious})


def extract_network_from_trace(trace: bytes) -> set[str]:
    # Split on bytes and parse each line directly with orjson (which
    # accepts bytes) to avoid a full trace.decode() string copy.
    return {
        event["s_msg"]
        for line in trace.split(b"\n")
        if line and (event := orjson.loads(line)).get("event.name") == "Auxiliary.ObtainNetworkAlert"
    }


def extract_static(report: SandboxBaseTaskResponse.LongReport) -> list[str]:
    if not report.artifacts:
        return []

    sandbox_result = report.artifacts[0].find_sandbox_result()
    if not sandbox_result:
        return []

    ret: set[str] = set()
    for artifact in report.artifacts:
        if artifact.type == ArtifactType.PROCESS_DUMP or not artifact.engine_results:
            continue
        for result in artifact.engine_results:
            if result.engine_subsystem in _STATIC_SUBSYSTEMS:
                ret |= {f"{result.engine_code_name}: {d.detect}" for d in result.detections}

    return sorted(ret)


def extract_memory(report: SandboxBaseTaskResponse.LongReport) -> set[str]:
    if not report.artifacts:
        return set()

    sandbox_result = report.artifacts[0].find_sandbox_result()
    if not sandbox_result or not sandbox_result.details or not sandbox_result.details.sandbox:
        return set()

    ret: set[str] = set()
    for artifact in sandbox_result.details.sandbox.artifacts or []:
        if artifact.type == ArtifactType.PROCESS_DUMP and (static := artifact.find_static_result()):
            ret |= {d.detect for d in static.detections}

    return ret
