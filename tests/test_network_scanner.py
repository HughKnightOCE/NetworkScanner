"""
Unit tests for Network Scanner module.

This test suite covers all major functionality of the scanner.
To run tests: pytest tests/
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Mock scapy import if not available
import sys
sys.modules['scapy'] = MagicMock()
sys.modules['scapy.all'] = MagicMock()

from src.config import ScanConfig, DEFAULT_PORTS, PORT_RISK_LEVELS
from src.network_scanner import NetworkScanner, setup_logging


class TestScanConfig:
    """Test suite for ScanConfig configuration class."""

    def test_config_initialization(self):
        """Test basic ScanConfig initialization."""
        config = ScanConfig()
        assert config.subnet == "auto"
        assert config.timeout == 1.0
        assert config.max_threads == 50
        assert config.use_arp is True
        assert config.use_ping is True
        assert config.scan_ports is True

    def test_config_custom_values(self):
        """Test ScanConfig with custom values."""
        config = ScanConfig(
            subnet="192.168.1.0/24",
            timeout=2.0,
            max_threads=100,
            use_arp=False,
        )
        assert config.subnet == "192.168.1.0/24"
        assert config.timeout == 2.0
        assert config.max_threads == 100
        assert config.use_arp is False

    def test_config_default_ports(self):
        """Test that default ports are set correctly."""
        config = ScanConfig()
        assert config.common_ports is not None
        assert len(config.common_ports) > 0
        assert 22 in config.common_ports  # SSH
        assert 80 in config.common_ports  # HTTP

    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        config_dict = {
            "subnet": "10.0.0.0/24",
            "max_threads": 75,
            "use_ping": False,
        }
        config = ScanConfig.from_dict(config_dict)
        assert config.subnet == "10.0.0.0/24"
        assert config.max_threads == 75
        assert config.use_ping is False


class TestNetworkScanner:
    """Test suite for NetworkScanner class."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance for testing."""
        config = ScanConfig(subnet="192.168.1.0/24")
        return NetworkScanner(config)

    def test_scanner_initialization(self, scanner):
        """Test NetworkScanner initialization."""
        assert scanner.config is not None
        assert scanner.logger is not None
        assert scanner.active_hosts == set()
        assert scanner.open_ports == {}
        assert scanner.risk_findings == []

    @patch('socket.gethostname')
    @patch('socket.gethostbyname')
    def test_get_local_network(self, mock_getbyname, mock_hostname, scanner):
        """Test local network detection."""
        mock_hostname.return_value = "test-machine"
        mock_getbyname.return_value = "192.168.1.100"
        
        result = scanner.get_local_network()
        assert "192.168.1" in result
        assert "/24" in result

    @patch('subprocess.run')
    def test_ping_host_success(self, mock_run, scanner):
        """Test successful ping."""
        mock_run.return_value.returncode = 0
        
        result = scanner.ping_host("192.168.1.1")
        assert result is True

    @patch('subprocess.run')
    def test_ping_host_failure(self, mock_run, scanner):
        """Test failed ping."""
        mock_run.return_value.returncode = 1
        
        result = scanner.ping_host("192.168.1.1")
        assert result is False

    def test_scan_ports(self, scanner):
        """Test port scanning method."""
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = MagicMock()
            mock_socket.return_value = mock_sock_instance
            mock_sock_instance.connect_ex.return_value = 0  # Port open
            
            open_ports, findings = scanner.scan_ports("192.168.1.1", [22, 80])
            
            assert len(open_ports) > 0
            assert len(findings) > 0

    def test_generate_report(self, scanner):
        """Test report generation."""
        scanner.active_hosts = {"192.168.1.1", "192.168.1.2"}
        scanner.open_ports = {"192.168.1.1": [22, 80]}
        scanner.risk_findings = ["[HIGH] Port 23 on 192.168.1.1"]
        
        report = scanner.generate_report()
        
        assert "Network Scan Report" in report
        assert "2" in report  # 2 active hosts
        assert "192.168.1.1" in report


class TestConfiguration:
    """Test suite for configuration constants."""

    def test_default_ports_exist(self):
        """Test that default ports dictionary is populated."""
        assert len(DEFAULT_PORTS) > 0
        assert 22 in DEFAULT_PORTS
        assert DEFAULT_PORTS[22] == "SSH"

    def test_port_risk_levels(self):
        """Test port risk level assignments."""
        assert 23 in PORT_RISK_LEVELS  # Telnet
        assert PORT_RISK_LEVELS[23] == "CRITICAL"
        assert PORT_RISK_LEVELS[445] == "HIGH"  # SMB


class TestLogging:
    """Test suite for logging functionality."""

    def test_setup_logging_info(self):
        """Test logging setup with INFO level."""
        setup_logging(log_level="INFO", verbose=False)
        # Should not raise any exceptions

    def test_setup_logging_debug(self):
        """Test logging setup with DEBUG level."""
        setup_logging(log_level="DEBUG", verbose=True)
        # Should not raise any exceptions


# Integration tests
class TestIntegration:
    """Integration tests for complete workflows."""

    @patch('src.network_scanner.NetworkScanner.scan_network')
    @patch('src.network_scanner.NetworkScanner.get_local_network')
    def test_scan_workflow(self, mock_local, mock_scan, capsys):
        """Test complete scan workflow."""
        mock_local.return_value = "192.168.1.0/24"
        mock_scan.return_value = {"192.168.1.1", "192.168.1.2"}
        
        config = ScanConfig(scan_ports=False)
        scanner = NetworkScanner(config)
        
        # Should not raise exceptions
        assert scanner is not None


# Performance benchmarks
@pytest.mark.benchmark
class TestPerformance:
    """Performance benchmarks for scanning operations."""

    @pytest.fixture
    def scanner(self):
        """Create scanner for benchmarks."""
        config = ScanConfig(subnet="192.168.1.0/24")
        return NetworkScanner(config)

    def test_config_initialization_speed(self, benchmark):
        """Benchmark configuration initialization."""
        benchmark(ScanConfig)

    def test_scanner_initialization_speed(self, benchmark):
        """Benchmark scanner initialization."""
        config = ScanConfig()
        benchmark(NetworkScanner, config)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
