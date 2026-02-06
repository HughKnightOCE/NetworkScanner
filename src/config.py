"""
Configuration management for Network Scanner.

This module handles all configuration settings for the network scanner tool,
allowing for easy customization and environment-based configurations.
"""

from dataclasses import dataclass
from typing import Dict, Set


@dataclass
class ScanConfig:
    """Configuration container for network scanning parameters."""

    # Network scanning parameters
    subnet: str = "auto"  # "auto" will auto-detect local subnet
    timeout: float = 1.0  # Socket timeout in seconds
    max_threads: int = 50  # Maximum concurrent threads for network scanning
    use_arp: bool = True  # Use ARP scanning for local network discovery
    use_ping: bool = True  # Use ICMP ping for host discovery

    # Port scanning parameters
    scan_ports: bool = True  # Whether to scan for open ports
    common_ports: list[int] | None = None  # List of ports to scan
    port_timeout: float = 1.0  # Timeout for port scanning

    # Output parameters
    output_file: str = "scan_results.txt"  # Output file path
    verbose: bool = False  # Enable verbose logging
    log_level: str = "INFO"  # Logging level (DEBUG, INFO, WARNING, ERROR)

    def __post_init__(self) -> None:
        """Initialize default values after dataclass creation."""
        if self.common_ports is None:
            self.common_ports = list(DEFAULT_PORTS.keys())

    @staticmethod
    def from_dict(config_dict: Dict) -> "ScanConfig":
        """Create ScanConfig from dictionary."""
        return ScanConfig(**{k: v for k, v in config_dict.items() if hasattr(ScanConfig, k)})


# Default suspicious ports and their descriptions
DEFAULT_PORTS: Dict[int, str] = {
    4444: "Metasploit",
    23: "Telnet",
    445: "SMB (Server Message Block)",
    1433: "SQL Server",
    3389: "RDP (Remote Desktop Protocol)",
    21: "FTP",
    22: "SSH",
    3306: "MySQL",
    8080: "HTTP Proxy",
    135: "MS RPC",
    139: "NetBIOS",
    80: "HTTP",
    443: "HTTPS",
    5900: "VNC",
    27017: "MongoDB",
    5432: "PostgreSQL",
}

# Risk severity levels
RISK_LEVELS: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

# Port risk assessment
PORT_RISK_LEVELS: Dict[int, str] = {
    23: "CRITICAL",  # Telnet
    445: "HIGH",  # SMB
    1433: "HIGH",  # SQL Server
    3389: "MEDIUM",  # RDP
    21: "HIGH",  # FTP
    3306: "MEDIUM",  # MySQL
    135: "HIGH",  # MS RPC
    139: "HIGH",  # NetBIOS
    27017: "MEDIUM",  # MongoDB
}
