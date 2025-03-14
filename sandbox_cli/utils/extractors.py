import orjson
from ptsandbox.models import ArtifactType, EngineSubsystem, SandboxBaseTaskResponse

from sandbox_cli.models.detections import Detections


def extract_verdict_from_trace(trace: bytes) -> set[str]:
    non_generics: set[str] = set()
    generics: set[str] = set()

    d = Detections(trace)
    for detect in d.malware:
        if detect.name.split(".")[-2] == "Generic":
            generics.add(detect.name)
        else:
            non_generics.add(detect.name)

    return non_generics if len(non_generics) != 0 else generics


def extract_network_from_trace(trace: bytes) -> set[str]:
    detects: set[str] = set()

    for line in trace.decode().splitlines(keepends=False):
        event = orjson.loads(line)
        if event.get("event.name") == "Auxiliary.ObtainNetworkAlert":
            detects.add(event.get("s_msg"))

    return detects


def extract_static(report: SandboxBaseTaskResponse.LongReport) -> list[str]:
    sandbox_result = report.artifacts[0].find_sandbox_result()

    ret: set[str] = set()

    if sandbox_result:
        for artifact in report.artifacts:
            if artifact.type == ArtifactType.PROCESS_DUMP:
                continue

            if artifact.engine_results is None:
                continue

            for artifact_result in artifact.engine_results:
                if artifact_result.engine_subsystem not in {EngineSubsystem.STATIC, EngineSubsystem.AV}:
                    continue

                ret |= {f"{artifact_result.engine_code_name}: {x.detect}" for x in artifact_result.detections}

    return sorted(ret)


def extract_memory(report: SandboxBaseTaskResponse.LongReport) -> set[str]:
    ret: set[str] = set()

    sandbox_result = report.artifacts[0].find_sandbox_result()

    if sandbox_result:
        for artifact in sandbox_result.details.sandbox.artifacts:  # type: ignore
            if artifact.type == ArtifactType.PROCESS_DUMP:
                artifact_result = artifact.find_static_result()
                if artifact_result:
                    ret |= {x.detect for x in artifact_result.detections}

    return ret
