#!/usr/bin/env python3
"""
Example usage of Network Scanner as a library.

This demonstrates how to use the NetworkScanner class programmatically
rather than through the command-line interface.
"""

import sys
from pathlib import Path

# Add src to path for local imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.network_scanner import NetworkScanner
from src.config import ScanConfig


def example_1_basic_scan():
    """Example 1: Basic network scan with default settings."""
    print("=" * 70)
    print("Example 1: Basic Auto-Detection Scan")
    print("=" * 70)
    
    config = ScanConfig(
        subnet="auto",  # Auto-detect local network
        verbose=True,
    )
    
    scanner = NetworkScanner(config)
    scanner.run_scan()


def example_2_specific_subnet():
    """Example 2: Scan a specific subnet."""
    print("\n" + "=" * 70)
    print("Example 2: Scan Specific Subnet")
    print("=" * 70)
    
    config = ScanConfig(
        subnet="192.168.1.0/24",
        max_threads=100,  # Increase threads for faster scanning
        timeout=0.5,  # Reduce timeout for quicker scans
        output_file="results/192_168_1_scan.txt",
    )
    
    scanner = NetworkScanner(config)
    scanner.run_scan()


def example_3_custom_ports():
    """Example 3: Scan with custom port list."""
    print("\n" + "=" * 70)
    print("Example 3: Custom Port Scanning")
    print("=" * 70)
    
    custom_ports = [22, 23, 80, 443, 3389, 5900, 8080]
    
    config = ScanConfig(
        subnet="192.168.1.0/24",
        scan_ports=True,
        common_ports=custom_ports,
        port_timeout=0.5,
        output_file="results/custom_ports_scan.txt",
    )
    
    scanner = NetworkScanner(config)
    scanner.run_scan()


def example_4_icmp_only():
    """Example 4: ICMP ping only (no ARP, no port scanning)."""
    print("\n" + "=" * 70)
    print("Example 4: ICMP Ping Only Scan")
    print("=" * 70)
    
    config = ScanConfig(
        subnet="10.0.0.0/24",
        use_arp=False,  # Disable ARP
        use_ping=True,   # Enable ICMP ping
        scan_ports=False,  # Disable port scanning
        output_file="results/icmp_only_scan.txt",
    )
    
    scanner = NetworkScanner(config)
    scanner.run_scan()


def example_5_arp_only():
    """Example 5: ARP scan only (fastest for local networks)."""
    print("\n" + "=" * 70)
    print("Example 5: ARP Only Scan")
    print("=" * 70)
    
    config = ScanConfig(
        subnet="192.168.1.0/24",
        use_arp=True,     # Enable ARP
        use_ping=False,   # Disable ICMP ping
        scan_ports=False,  # Disable port scanning
        output_file="results/arp_only_scan.txt",
    )
    
    scanner = NetworkScanner(config)
    scanner.run_scan()


def example_6_programmatic_results():
    """Example 6: Scan and process results programmatically."""
    print("\n" + "=" * 70)
    print("Example 6: Programmatic Result Processing")
    print("=" * 70)
    
    config = ScanConfig(
        subnet="192.168.1.0/28",  # Small subnet for quick example
        verbose=False,
    )
    
    scanner = NetworkScanner(config)
    
    # Run the scan
    print("Running scan...")
    scanner.run_scan()
    
    # Process results programmatically
    print(f"\nFound {len(scanner.active_hosts)} active hosts:")
    for host in sorted(scanner.active_hosts):
        print(f"  - {host}")
    
    print(f"\nFound {len(scanner.open_ports)} hosts with open ports:")
    for host, ports in sorted(scanner.open_ports.items()):
        if ports:
            print(f"  {host}: {', '.join(map(str, ports))}")
    
    print(f"\nSecurity Findings ({len(scanner.risk_findings)}):")
    for finding in scanner.risk_findings:
        print(f"  {finding}")


def example_7_debug_logging():
    """Example 7: Detailed debug logging."""
    print("\n" + "=" * 70)
    print("Example 7: Debug Logging")
    print("=" * 70)
    
    config = ScanConfig(
        subnet="192.168.1.0/28",
        verbose=True,
        log_level="DEBUG",  # Maximum verbosity
        output_file="results/debug_scan.txt",
    )
    
    scanner = NetworkScanner(config)
    scanner.run_scan()
    
    print("\nCheck 'network_scanner.log' for detailed debug output")


def example_8_large_network():
    """Example 8: Optimized settings for large networks."""
    print("\n" + "=" * 70)
    print("Example 8: Large Network Scan (Advanced Settings)")
    print("=" * 70)
    
    config = ScanConfig(
        subnet="10.0.0.0/16",  # Large /16 network (65,536 addresses)
        max_threads=250,  # High thread count for parallel scanning
        timeout=0.3,  # Aggressive timeout
        use_arp=False,  # Skip ARP for large networks
        use_ping=True,  # Use ICMP ping
        scan_ports=True,  # Still scan ports on discovered hosts
        port_timeout=0.5,
        output_file="results/large_network_scan.txt",
        verbose=True,
    )
    
    scanner = NetworkScanner(config)
    print("Note: Large networks may take several minutes to scan.")
    scanner.run_scan()


# Main execution
if __name__ == "__main__":
    import logging
    
    # Configure logging for examples
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    print("\n" + "=" * 70)
    print("Network Scanner - Usage Examples")
    print("=" * 70)
    print("\nChoose an example to run:")
    print("  1. Basic auto-detection scan")
    print("  2. Scan specific subnet")
    print("  3. Custom port scanning")
    print("  4. ICMP ping only")
    print("  5. ARP scan only")
    print("  6. Programmatic result processing")
    print("  7. Debug logging")
    print("  8. Large network scan (advanced)")
    
    choice = input("\nEnter your choice (1-8) or 'q' to quit: ").strip()
    
    examples = {
        "1": example_1_basic_scan,
        "2": example_2_specific_subnet,
        "3": example_3_custom_ports,
        "4": example_4_icmp_only,
        "5": example_5_arp_only,
        "6": example_6_programmatic_results,
        "7": example_7_debug_logging,
        "8": example_8_large_network,
    }
    
    if choice in examples:
        try:
            examples[choice]()
            print("\n✓ Example completed successfully!")
        except KeyboardInterrupt:
            print("\n\nExample interrupted by user")
        except Exception as e:
            print(f"\n❌ Error: {e}")
    elif choice.lower() == "q":
        print("Exiting...")
    else:
        print("Invalid choice")
