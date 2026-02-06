"""
Network Scanner Package

A comprehensive Python-based network diagnostic tool that scans and identifies
live hosts across a subnet or IP range with professional logging and type hints.
"""

__version__ = "2.0.0"
__author__ = "Hugh Knight"
__email__ = "hugh.knight.oce@gmail.com"
__license__ = "MIT"
__url__ = "https://github.com/HughKnightOCE/NetworkScanner"

from .config import ScanConfig, DEFAULT_PORTS, PORT_RISK_LEVELS
from .network_scanner import NetworkScanner

__all__ = [
    "NetworkScanner",
    "ScanConfig",
    "DEFAULT_PORTS",
    "PORT_RISK_LEVELS",
    "__version__",
    "__author__",
]
