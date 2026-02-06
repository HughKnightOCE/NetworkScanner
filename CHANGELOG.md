# Changelog

All notable changes to Network Scanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-02-06

### Added
- **Type Safety**: Complete type hints for all functions and methods
- **Professional Logging**: Replace print statements with logging module
- **Configuration Management**: New `config.py` module with `ScanConfig` dataclass
- **Advanced CLI**: Full argparse integration with 15+ options
- **Modern Packaging**: `pyproject.toml` following PEP 517/518 standards
- **Code Quality**: Added `.pylintrc`, Black configuration, MyPy support
- **Risk Assessment**: Port risk levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **Concurrent Performance**: ThreadPoolExecutor with configurable thread pool
- **Package Structure**: Proper Python package with `__init__.py`
- **Development Tools**: `requirements-dev.txt` with linting and testing tools
- **Documentation**: Enhanced README with badges, examples, and troubleshooting

### Changed
- **Architecture**: Refactored from functional to object-oriented design
- **Thread Management**: Upgraded from manual threading to ThreadPoolExecutor
- **Output Format**: Improved report formatting with timestamps and structured data
- **Error Handling**: More robust exception handling and logging
- **Port Scanning**: Enhanced with risk assessment and severity levels

### Improved
- Code readability with proper docstrings (Google style)
- Error messages with contextual information
- Performance with better concurrent threading
- CLI usability with detailed help text and examples
- Configuration flexibility with dataclass-based settings

### Deprecated
- Direct print() output (now uses logging instead)

## [1.0.0] - Original Release

### Features
- ICMP ping-based network scanning
- ARP packet discovery
- TCP port scanning
- Suspicious port detection
- Timestamp-based reporting
- Multithreaded scanning

---

## Version History

### Semantic Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes and improvements

### Upgrade Guide

#### From 1.0.0 to 2.0.0

**Breaking Changes:**
- CLI interface has changed to use argparse instead of interactive prompts
- Import paths have changed (package structure reorganized)
- Output format has been enhanced with structured reporting

**Migration:**
```python
# Old (v1.0.0)
from network_scanner import main
main()

# New (v2.0.0)
from src.network_scanner import NetworkScanner
from src.config import ScanConfig

config = ScanConfig(subnet="192.168.1.0/24")
scanner = NetworkScanner(config)
scanner.run_scan()
```

---

## Future Roadmap

### Planned for 2.1.0
- [ ] IPv6 support
- [ ] Progress bar output (tqdm)
- [ ] Colored terminal output (colorama)
- [ ] JSON export format
- [ ] Unit test suite

### Planned for 2.2.0
- [ ] Async/await implementation
- [ ] Service fingerprinting
- [ ] OS detection
- [ ] Vulnerability scanning

### Planned for 3.0.0
- [ ] Web UI with Flask/Django
- [ ] Database backend support
- [ ] API server mode
- [ ] Scheduled scanning

---

## Support

For help with upgrading or issues, please open an issue on [GitHub](https://github.com/HughKnightOCE/NetworkScanner/issues).
