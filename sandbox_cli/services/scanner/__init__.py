"""
Scanning files and traces in the sandbox.

``execute_scan`` runs a ``ScanKind`` strategy (``kinds/``): the kind says what to
prepare and which jobs to run, ``prepare`` uploads what the jobs need and
``pipeline`` spreads the jobs over the sandboxes and downloads the results.
"""

from sandbox_cli.services.scanner.engine import execute_scan
from sandbox_cli.services.scanner.kinds.advanced import AdvancedScan
from sandbox_cli.services.scanner.kinds.basic import BasicScan
from sandbox_cli.services.scanner.kinds.rescan import Rescan

__all__ = ["AdvancedScan", "BasicScan", "Rescan", "execute_scan"]
