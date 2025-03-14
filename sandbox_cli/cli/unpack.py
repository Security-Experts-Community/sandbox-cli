from pathlib import Path
from typing import Annotated

from cyclopts import Parameter, validators

from sandbox_cli.console import console
from sandbox_cli.utils.unpack import Unpack


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
        * events-correlated.log.<DETECT_NAME>
    * normalized
        * events-normalized.log
        * events-normalized.log.<DETECT_NAME>
    * network
        * tcpdump.pcap
    * raw
        * drakvuf-trace.log.zst
        * tcpdump.pcap

    Usage examples:
    * Checks for drakvuf-trace.log.gz or drakvuf-trace.log.zst in the current directory:
    _sandbox-cli unpack ._
    * Extracts and processes logs into the sandbox_logs directory:
    _sandbox-cli unpack sandbox_logs.zip_
    * Handles multiple archives simultaneously:
    _sandbox-cli unpack sandbox_logs.zip sandbox_logs_1.zip_
    """

    for trace in traces:
        console.info(f"Unpacking {trace}")
        Unpack(trace=trace).run()
