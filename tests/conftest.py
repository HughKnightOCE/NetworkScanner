"""
Pytest configuration and fixtures for Network Scanner tests.
"""

import pytest
import logging
from pathlib import Path


@pytest.fixture(scope="session")
def test_data_dir():
    """Provide path to test data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging configuration between tests."""
    logging.shutdown()
    yield
    logging.shutdown()


@pytest.fixture
def mock_network():
    """Fixture providing mock network configuration."""
    return {
        "subnet": "192.168.1.0/24",
        "gateway": "192.168.1.1",
        "dns": "192.168.1.1",
        "hosts": [
            "192.168.1.10",
            "192.168.1.20",
            "192.168.1.30",
        ],
    }


@pytest.fixture
def mock_ports():
    """Fixture providing mock port data."""
    return {
        "192.168.1.10": [22, 80, 443],
        "192.168.1.20": [3389, 5900],
        "192.168.1.30": [80, 443, 8080],
    }


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "benchmark: mark test as a performance benchmark"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
