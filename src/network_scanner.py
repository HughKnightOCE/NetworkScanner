"""
Network Scanner - A comprehensive network diagnostic tool.

This module provides functionality to scan networks for active hosts,
detect open ports, and identify potential security risks.

Author: Hugh Knight
License: MIT
"""

import argparse
import logging
import os
import platform
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from config import DEFAULT_PORTS, RISK_LEVELS, PORT_RISK_LEVELS, ScanConfig

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkScanner:
    """
    Main network scanning class with support for ICMP, ARP, and port scanning.
    """

    def __init__(self, config: ScanConfig) -> None:
        """
        Initialize the NetworkScanner with configuration.

        Args:
            config: ScanConfig object containing scan parameters
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.active_hosts: Set[str] = set()
        self.open_ports: Dict[str, List[int]] = {}
        self.risk_findings: List[str] = []

    def get_local_network(self) -> str:
        """
        Automatically determine the local network and subnet mask.

        Returns:
            str: Network address in CIDR notation (e.g., "192.168.1.0/24")

        Raises:
            socket.error: If unable to determine local IP address
        """
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            subnet = f"{local_ip}/24"
            self.logger.info(f"Detected Local IP: {local_ip}, Network: {subnet}")
            return subnet
        except socket.error as e:
            self.logger.error(f"Failed to determine local network: {e}")
            raise

    def ping_host(self, ip: str) -> bool:
        """
        Ping a single host to check if it's alive.

        Args:
            ip: IP address to ping as string

        Returns:
            bool: True if host responds, False otherwise
        """
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", str(ip)]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.logger.debug(f"Ping timeout for {ip}")
            return False
        except Exception as e:
            self.logger.debug(f"Error pinging {ip}: {e}")
            return False

    def scan_network(self) -> Set[str]:
        """
        Scan network to find active hosts using ICMP ping.

        Returns:
            Set[str]: Set of active host IP addresses

        Raises:
            ValueError: If network is invalid
        """
        try:
            if self.config.subnet == "auto":
                network = self.get_local_network()
            else:
                network = self.config.subnet

            net = ip_network(network, strict=False)
            self.logger.info(f"Starting ICMP scan on network: {network}")

            active_hosts: Set[str] = set()

            with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                future_to_ip = {
                    executor.submit(self.ping_host, str(ip)): str(ip)
                    for ip in net.hosts()
                }

                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            active_hosts.add(ip)
                            self.logger.info(f"[+] Active host found: {ip}")
                    except Exception as e:
                        self.logger.debug(f"Error scanning {ip}: {e}")

            self.active_hosts.update(active_hosts)
            self.logger.info(f"ICMP scan complete. Found {len(active_hosts)} active hosts")
            return active_hosts

        except ValueError as e:
            self.logger.error(f"Invalid network specification: {e}")
            raise

    def arp_scan(self) -> Set[str]:
        """
        Perform ARP scan to discover devices on local network.

        Returns:
            Set[str]: Set of discovered IP addresses
        """
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available. Skipping ARP scan.")
            return set()

        try:
            if self.config.subnet == "auto":
                network = self.get_local_network()
            else:
                network = self.config.subnet

            self.logger.info(f"Starting ARP scan on network: {network}")

            arp_request = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp_request

            result = srp(packet, timeout=2, verbose=0)[0]
            devices: Dict[str, str] = {}

            for _, received in result:
                devices[received.psrc] = received.hwsrc
                self.logger.debug(f"Found device - IP: {received.psrc}, MAC: {received.hwsrc}")

            self.logger.info(f"ARP scan complete. Found {len(devices)} devices")
            return set(devices.keys())

        except Exception as e:
            self.logger.error(f"ARP scan failed: {e}")
            return set()

    def scan_ports(self, host: str, ports: Optional[List[int]] = None) -> Tuple[List[int], List[str]]:
        """
        Scan common ports on a given host.

        Args:
            host: Target host IP address
            ports: List of ports to scan (uses config default if None)

        Returns:
            Tuple of (list of open ports, list of risk findings)
        """
        if ports is None:
            ports = self.config.common_ports

        open_ports: List[int] = []
        risk_findings: List[str] = []

        self.logger.info(f"Scanning {len(ports)} ports on {host}")

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.port_timeout)

                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)
                    port_name = DEFAULT_PORTS.get(port, "Unknown")
                    risk_level = PORT_RISK_LEVELS.get(port, "INFO")

                    finding = f"[{risk_level}] Port {port} open on {host} ({port_name})"
                    risk_findings.append(finding)
                    self.logger.warning(finding)

            except socket.timeout:
                self.logger.debug(f"Timeout scanning port {port} on {host}")
            except Exception as e:
                self.logger.debug(f"Error scanning port {port} on {host}: {e}")

        self.open_ports[host] = open_ports
        return open_ports, risk_findings

    def generate_report(self) -> str:
        """
        Generate a comprehensive scan report.

        Returns:
            str: Formatted report
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        report = f"\n{'='*70}\n"
        report += f"Network Scan Report - {timestamp}\n"
        report += f"{'='*70}\n\n"

        report += f"Active Hosts Found: {len(self.active_hosts)}\n"
        if self.active_hosts:
            report += "Hosts:\n"
            for host in sorted(self.active_hosts):
                report += f"  - {host}\n"

        report += f"\nOpen Ports Detected: {sum(len(ports) for ports in self.open_ports.values())}\n"
        if self.open_ports:
            report += "Port Details:\n"
            for host, ports in sorted(self.open_ports.items()):
                if ports:
                    report += f"  {host}: {', '.join(map(str, ports))}\n"

        report += f"\nRisk Findings: {len(self.risk_findings)}\n"
        if self.risk_findings:
            report += "Findings:\n"
            for finding in self.risk_findings:
                report += f"  {finding}\n"
        else:
            report += "No security risks detected.\n"

        report += f"\n{'='*70}\n"
        return report

    def save_report(self, output_file: Optional[str] = None) -> None:
        """
        Save scan report to file.

        Args:
            output_file: Output file path (uses config default if None)
        """
        if output_file is None:
            output_file = self.config.output_file

        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            report = self.generate_report()

            with open(output_path, "a") as f:
                f.write(report)

            self.logger.info(f"Report saved to {output_path}")
            print(f"\n✓ Results written to {output_path}")

        except IOError as e:
            self.logger.error(f"Failed to write report: {e}")
            raise

    def run_scan(self) -> None:
        """
        Execute the full network scan workflow.
        """
        try:
            self.logger.info("Starting network scan...")
            print("\n🔍 Network Scanner Started\n")

            if self.config.use_arp and SCAPY_AVAILABLE:
                discovered = self.arp_scan()
                if not discovered and self.config.use_ping:
                    self.scan_network()
            elif self.config.use_ping:
                self.scan_network()

            if not self.active_hosts:
                self.logger.warning("No active hosts found")
                print("⚠️  No active hosts discovered")
                return

            if self.config.scan_ports:
                self.logger.info(f"Starting port scan on {len(self.active_hosts)} hosts")
                for host in sorted(self.active_hosts):
                    _, findings = self.scan_ports(host)
                    self.risk_findings.extend(findings)

            report = self.generate_report()
            print(report)
            self.save_report()

            self.logger.info("Network scan completed successfully")
            print("✓ Scan completed successfully!\n")

        except KeyboardInterrupt:
            self.logger.info("Scan interrupted by user")
            print("\n\n⚠️  Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise


def setup_logging(log_level: str = "INFO", verbose: bool = False) -> None:
    """
    Configure logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        verbose: Enable verbose output
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("network_scanner.log"),
            logging.StreamHandler(),
        ],
    )

    if not verbose:
        logging.getLogger().setLevel(logging.WARNING)


def main() -> None:
    """Main entry point for the Network Scanner CLI."""
    parser = argparse.ArgumentParser(
        description="🌐 Network Scanner - Detect live hosts and open ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --subnet 192.168.1.0/24          # Scan specific network
  %(prog)s                                   # Auto-detect local network
  %(prog)s --subnet 192.168.1.0/24 --ports 22,80,443  # Scan specific ports
  %(prog)s --verbose                          # Show detailed output
        """,
    )

    parser.add_argument(
        "--subnet",
        type=str,
        default="auto",
        help="Network to scan (CIDR notation) or 'auto' for local network (default: auto)",
    )
    parser.add_argument(
        "--ports",
        type=lambda x: [int(p.strip()) for p in x.split(",")],
        default=None,
        help="Comma-separated list of ports to scan (default: common ports)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="scan_results.txt",
        help="Output file for results (default: scan_results.txt)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Maximum number of concurrent threads (default: 50)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout for host discovery in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--port-timeout",
        type=float,
        default=1.0,
        help="Timeout for port scanning in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--no-arp",
        action="store_true",
        help="Disable ARP scanning",
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Disable ICMP ping scanning",
    )
    parser.add_argument(
        "--no-ports",
        action="store_true",
        help="Disable port scanning",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0",
    )

    args = parser.parse_args()

    setup_logging(args.log_level, args.verbose)
    logger = logging.getLogger(__name__)

    config = ScanConfig(
        subnet=args.subnet,
        max_threads=args.threads,
        timeout=args.timeout,
        port_timeout=args.port_timeout,
        use_arp=not args.no_arp,
        use_ping=not args.no_ping,
        scan_ports=not args.no_ports,
        output_file=args.output,
        verbose=args.verbose,
        log_level=args.log_level,
    )

    if args.ports:
        config.common_ports = args.ports

    logger.info(f"Configuration: {config}")

    try:
        scanner = NetworkScanner(config)
        scanner.run_scan()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan cancelled by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        exit(1)


if __name__ == "__main__":
    main()
