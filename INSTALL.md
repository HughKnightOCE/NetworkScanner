# Installation & Deployment Guide

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements

- **Python**: 3.9 or higher
- **RAM**: 512 MB
- **Disk Space**: 100 MB
- **Network**: Connection to networks you wish to scan

### Supported Operating Systems

| OS | Version | Status |
|----|---------|--------|
| Windows | 10, 11 | ✅ Fully Supported |
| Linux | Ubuntu 18.04+ | ✅ Fully Supported |
| macOS | 10.14+ | ✅ Fully Supported |

### Additional Tools

**Windows:**
- [Npcap](https://npcap.com/) - Required for ARP scanning (WinPcap compatible mode)

**Linux:**
- `libpcap-dev` - Usually pre-installed
- `python3-dev` - For compilation if needed

**macOS:**
- `libpcap` - Usually pre-installed

---

## Installation Methods

### Method 1: pip (Recommended)

```bash
# Install from PyPI (when published)
pip install network-scanner

# Verify installation
network-scanner --version
```

### Method 2: From Source (Development)

```bash
# Clone repository
git clone https://github.com/HughKnightOCE/NetworkScanner.git
cd NetworkScanner

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install in development mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Method 3: Docker (Coming Soon)

```dockerfile
# Dockerfile will be provided in future release
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "-m", "src.network_scanner"]
```

### Method 4: Pre-built Executable

```bash
# Windows executable (when available)
# Download NetworkScanner-2.0.0-windows.exe from releases

# Extract and run
.\NetworkScanner-2.0.0-windows.exe --subnet 192.168.1.0/24
```

---

## Configuration

### Environment Setup

```bash
# Create configuration directory (optional)
mkdir ~/.network-scanner
cp .network-scanner.conf ~/.network-scanner/

# Set environment variable (optional)
export NETWORK_SCANNER_CONFIG=~/.network-scanner/.network-scanner.conf
```

### Python venv Setup (Recommended)

```bash
# Create isolated environment
python -m venv ~/.venv/network-scanner

# Activate environment
# On Windows:
call %USERPROFILE%\.venv\network-scanner\Scripts\activate.bat
# On Linux/macOS:
source ~/.venv/network-scanner/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Docker Compose Setup

```yaml
version: '3.8'
services:
  scanner:
    build: .
    volumes:
      - ./results:/app/results
    network_mode: "host"
    command: --subnet 192.168.1.0/24 --output /app/results/scan.txt
```

---

## Deployment

### Single Machine

```bash
# One-time scan
python -m src.network_scanner --subnet 192.168.1.0/24

# Save results
python -m src.network_scanner --subnet 192.168.1.0/24 \
    --output results/scan_$(date +%Y%m%d).txt
```

### Scheduled Scanning (Linux/macOS)

```bash
# Edit crontab
crontab -e

# Add scheduled scan (daily at 2 AM)
0 2 * * * /usr/bin/python3 ~/NetworkScanner/src/network_scanner.py \
    --subnet 192.168.1.0/24 \
    --output ~/NetworkScanner/results/scan_$(date +\%Y\%m\%d).txt

# View scheduled jobs
crontab -l
```

### Scheduled Scanning (Windows)

```powershell
# Create Task Scheduler job
$taskName = "NetworkScanner"
$scriptPath = "C:\Users\YourUser\NetworkScanner\scan.ps1"

# Schedule to run daily at 2 AM
schtasks /create /tn $taskName /tr "powershell -ExecutionPolicy Bypass -File $scriptPath" /sc daily /st 02:00

# View scheduled tasks
schtasks /query /tn $taskName /v
```

### Cloud Deployment

#### AWS EC2

```bash
#!/bin/bash
# User data script for EC2 instance

sudo apt-get update
sudo apt-get install -y python3-pip libpcap-dev

git clone https://github.com/HughKnightOCE/NetworkScanner.git
cd NetworkScanner

pip3 install -r requirements.txt

# Run scan
python3 -m src.network_scanner --subnet 172.31.0.0/16 \
    --output s3://your-bucket/scans/$(date +%Y%m%d).txt
```

#### Docker Container

```bash
# Build image
docker build -t network-scanner .

# Run container
docker run --rm \
    --net=host \
    -v $(pwd)/results:/app/results \
    network-scanner \
    --subnet 192.168.1.0/24 \
    --output /app/results/scan.txt

# Push to registry
docker tag network-scanner your-registry/network-scanner:latest
docker push your-registry/network-scanner:latest
```

---

## Troubleshooting

### Installation Issues

#### "pip: command not found"
```bash
# Use python module
python -m pip install -r requirements.txt

# Or upgrade pip
python -m pip install --upgrade pip
```

#### "No module named 'scapy'"
```bash
# Install missing dependency
pip install scapy>=2.5.0

# Verify installation
python -c "import scapy; print(scapy.__version__)"
```

#### "Permission denied" on Linux/macOS
```bash
# Run with sudo for ARP scanning
sudo python src/network_scanner.py

# Or use ICMP ping only (no sudo needed)
python src/network_scanner.py --no-arp
```

### Runtime Issues

#### "Npcap not installed" (Windows)
```powershell
# Download and install Npcap
# https://npcap.com/

# Or use ping-only mode
python src/network_scanner.py --no-arp
```

#### "Timeout or slow scanning"
```bash
# Reduce timeout
python src/network_scanner.py --timeout 0.5

# Increase threads
python src/network_scanner.py --threads 200

# Use smaller subnet
python src/network_scanner.py --subnet 192.168.1.0/25
```

#### "Address already in use"
```bash
# Kill existing processes
# On Linux/macOS:
killall python3

# On Windows:
taskkill /IM python.exe /F
```

### Permission Issues

#### "Operation not permitted"
```bash
# Run with elevated privileges
# Windows: Run as Administrator
runas /user:Administrator "python src/network_scanner.py"

# Linux/macOS: Use sudo
sudo python3 src/network_scanner.py
```

---

## Post-Installation

### Verify Installation

```bash
# Check version
network-scanner --version
# or
python -m src.network_scanner --version

# Check help
network-scanner --help
# or
python -m src.network_scanner --help

# Test with small subnet
python -m src.network_scanner --subnet 127.0.0.1/32
```

### Install Development Tools

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Check code quality
pylint src/
black --check src/
mypy src/
```

### Update Configuration

```bash
# Check current version
pip show network-scanner

# Update to latest
pip install --upgrade network-scanner

# View changelog
cat CHANGELOG.md
```

---

## Getting Help

- 📖 [Documentation](README.md)
- 🐛 [Report Issues](https://github.com/HughKnightOCE/NetworkScanner/issues)
- 💬 [Discussions](https://github.com/HughKnightOCE/NetworkScanner/discussions)
- 📧 [Contact](mailto:hugh.knight.oce@gmail.com)
