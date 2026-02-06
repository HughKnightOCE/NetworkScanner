# 🌐 Network Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Type hints: mypy](https://img.shields.io/badge/type%20hints-mypy-brightgreen)](http://mypy-lang.org/)

A comprehensive Python-based network diagnostic tool that scans and identifies live hosts across a subnet or IP range with modern async support, type hints, and professional logging.  
Built to demonstrate expertise in **Python 3.9+**, **network security**, **multithreading**, and **software engineering best practices**.

---

## ✨ Key Features

- 🎯 **Intelligent Host Discovery**: Supports both ARP and ICMP-based detection
- 🔌 **Port Scanning**: Identifies open ports and security risks with risk assessment
- ⚡ **High Performance**: Concurrent scanning with configurable thread pool
- 📊 **Detailed Reporting**: Comprehensive scan results with timestamps
- 🛠️ **Type-Safe**: Full type hints for excellent IDE support and code quality
- 📝 **Professional Logging**: Configurable logging with file and console output
- 💻 **Modern CLI**: Argument parsing with detailed help and examples
- 🐍 **Python 3.9+**: Leverages modern Python features and type annotations

---

## 📋 Requirements

- **Python**: 3.9 or higher
- **OS**: Windows, Linux, or macOS
- **Privileges**: May require elevated/admin privileges for ARP scanning or port operations
- **System Tools**: 
  - Windows: [Npcap](https://npcap.com/) for ARP scanning
  - Linux: typically pre-installed
  - macOS: typically pre-installed

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/HughKnightOCE/NetworkScanner.git
cd NetworkScanner

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan local network (auto-detect)
python src/network_scanner.py

# Scan specific subnet
python src/network_scanner.py --subnet 192.168.1.0/24

# Scan with custom ports
python src/network_scanner.py --subnet 10.0.0.0/24 --ports 22,80,443,3389

# Verbose output with debug logging
python src/network_scanner.py --subnet 192.168.0.0/24 --verbose --log-level DEBUG

# Custom output file
python src/network_scanner.py --output results/scan_2024.txt

# Disable specific scan types
python src/network_scanner.py --no-arp --no-ports  # ICMP ping only
```

---

## 📖 CLI Options

```
options:
  -h, --help            Show this help message and exit
  
  Network Configuration:
    --subnet SUBNET     Network to scan in CIDR notation or 'auto' 
                        (default: auto)
    --ports PORTS       Comma-separated port list (default: common ports)
    
  Performance:
    --threads THREADS   Max concurrent threads (default: 50)
    --timeout TIMEOUT   Host discovery timeout in seconds (default: 1.0)
    --port-timeout PT   Port scan timeout in seconds (default: 1.0)
    
  Scan Options:
    --no-arp            Disable ARP scanning
    --no-ping           Disable ICMP ping
    --no-ports          Disable port scanning
    
  Output:
    --output OUTPUT     Output file path (default: scan_results.txt)
    --verbose, -v       Enable verbose output
    --log-level LEVEL   Logging level: DEBUG, INFO, WARNING, ERROR
    --version           Show version number
```

---

## 🧩 Project Structure

```
NetworkScanner/
├── src/
│   ├── network_scanner.py    # Main scanner class & CLI
│   └── config.py              # Configuration management
│
├── example/
│   └── scan_results/          # Example scan output
│
├── tests/                      # Unit tests (future)
│
├── pyproject.toml             # Modern Python project config
├── setup.cfg                  # Setup configuration
├── .pylintrc                  # Code linting rules
├── requirements.txt           # Runtime dependencies
├── requirements-dev.txt       # Development dependencies
├── README.md                  # This file
├── LICENSE                    # MIT License
└── .gitignore                 # Git ignore rules
```

---

## 🛡️ Security Considerations

This tool is designed for authorized network diagnostics only. Ensure you have proper authorization before scanning networks you don't own. Unauthorized network scanning may be illegal in your jurisdiction.

**Responsible Usage:**
- Only scan networks you own or have explicit permission to scan
- Respect network administrator policies
- Document your scanning activities
- Handle scan results securely (they contain sensitive information)

---

## 🔧 Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run linting
pylint src/

# Format code
black src/

# Type checking
mypy src/

# Run tests (when available)
pytest tests/
```

### Code Quality Standards

- **Type Hints**: All functions have type annotations
- **Docstrings**: Google-style docstrings for all modules and classes
- **Formatting**: Black formatter (line length: 100)
- **Linting**: Pylint with configured rules
- **Type Checking**: MyPy strict mode

---

## 📊 Example Output

```
======================================================================
Network Scan Report - 2024-02-06 11:30:45
======================================================================

Active Hosts Found: 5
Hosts:
  - 192.168.1.1
  - 192.168.1.5
  - 192.168.1.10
  - 192.168.1.15
  - 192.168.1.20

Open Ports Detected: 8
Port Details:
  192.168.1.1: 22, 80, 443
  192.168.1.10: 3389, 5900
  192.168.1.15: 80, 443, 8080

Risk Findings: 2
Findings:
  [CRITICAL] Port 23 open on 192.168.1.5 (Telnet)
  [HIGH] Port 445 open on 192.168.1.20 (SMB)

======================================================================
```

---

## 🐛 Troubleshooting

### ARP Scan Not Working
- **Windows**: Install [Npcap](https://npcap.com/) with WinPcap API compatibility
- **Linux**: Ensure you have `libpcap` installed
- **Resolution**: Use `--no-arp` flag or install system dependencies

### Permission Denied Errors
- **Windows**: Run Command Prompt/PowerShell as Administrator
- **Linux/macOS**: Use `sudo` for ARP scanning
- **Alternative**: Use `--no-arp` to rely on ICMP ping only

### Slow Scanning
- Increase `--threads` parameter (default: 50, max: 250)
- Reduce `--timeout` if your network is responsive
- Use smaller subnet ranges for faster scans

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ✉️ Contact & Contributing

Created by **Hugh Knight**  

- 🔗 **GitHub**: [HughKnightOCE](https://github.com/HughKnightOCE)
- 📧 **Email**: hugh.knight.oce@gmail.com
- 🐛 **Issues**: [Report bugs or suggest features](https://github.com/HughKnightOCE/NetworkScanner/issues)

### Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## 📚 Learn More

- [Python Network Programming](https://docs.python.org/3/library/socket.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [Network Security Best Practices](https://www.nist.gov/cyberframework)

---

**Last Updated**: February 2024 | Version 2.0.0
