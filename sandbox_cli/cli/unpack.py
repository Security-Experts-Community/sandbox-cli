from pathlib import Path
from typing import Annotated

from cyclopts import Parameter, validators

from sandbox_cli.console import console
from sandbox_cli.services.unpack import unpack_trace


def unpack_logs(
    traces: Annotated[
        list[Path],
        Parameter(
            help="The path to the folder with the raw traces or with the sandbox-logs.zip",
            negative="",
            validator=validators.Path(exists=True),
        ),
    ],
    /,
) -> None:
    """
    Convert sandbox logs into an analysis-friendly format.

    Output file structure:
    * drakvuf-trace
        * drakvuf-trace.log
    * correlated
        * events-correlated.log
        * malware.log
        * <DETECT_NAME>.suspicious.log
        * <DETECT_NAME>.silent.log
    * normalized
        * events-normalized.log
        * <PLUGIN>.log
    * network
        * tcpdump.pcap
    * raw
        * the original compressed logs (input for re-scan)

    Usage examples:
    * Unpack the logs in the current directory:
    _sandbox-cli unpack ._
    * Extract sandbox_logs.zip into the sandbox_logs directory and unpack it:
    _sandbox-cli unpack sandbox_logs.zip_
    * Unpack several archives:
    _sandbox-cli unpack sandbox_logs.zip sandbox_logs_1.zip_
    """

    for trace in traces:
        console.info(f"Unpacking {trace}")
        unpack_trace(trace)
