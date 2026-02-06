# Network Scanner - Development Quick Start

## 30-Second Setup

```bash
# Clone and setup
git clone https://github.com/HughKnightOCE/NetworkScanner.git
cd NetworkScanner
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Check code quality
make check

# Start hacking!
```

## Project Structure

```
NetworkScanner/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── network_scanner.py   # Main scanner class (600 lines)
│   └── config.py             # Configuration & constants (100 lines)
├── tests/
│   ├── __init__.py           # Test package
│   ├── conftest.py           # Pytest fixtures and config
│   └── test_network_scanner.py # Comprehensive test suite
├── example/
│   ├── usage_examples.py     # 8 practical examples
│   └── scan_results/         # Results directory
├── .github/workflows/
│   └── ci-cd.yml             # GitHub Actions pipeline
├── pyproject.toml            # Modern Python packaging
├── setup.cfg                 # Project metadata
├── .pylintrc                 # Linting rules
├── requirements.txt          # Runtime dependencies
├── requirements-dev.txt      # Development dependencies
├── README.md                 # User documentation
├── INSTALL.md                # Installation guide
├── CONTRIBUTING.md           # Contribution guidelines
├── SECURITY.md               # Security policy
├── CHANGELOG.md              # Version history
├── LICENSE                   # MIT License
├── Makefile                  # Development commands
└── .gitignore                # Git ignore patterns
```

## Development Commands

```bash
# Format code
black src/ tests/

# Check linting
pylint src/

# Type checking
mypy src/

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test
pytest tests/test_network_scanner.py::TestNetworkScanner::test_scanner_initialization -v

# All checks at once
make check

# Clean build artifacts
make clean
```

## Code Quality Standards

- **Type Hints**: Required on all functions
- **Docstrings**: Google style, required for classes/modules
- **Line Length**: 100 characters (enforced by Black)
- **Test Coverage**: Aim for >80%
- **Linting**: Zero warnings from Pylint

## Git Workflow

```bash
# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and commit
git add .
git commit -m "feat: Add amazing feature"

# Push and create PR
git push origin feature/amazing-feature
```

## Common Tasks

### Adding a New Feature

1. Create feature branch: `git checkout -b feature/my-feature`
2. Add code with type hints and docstrings
3. Add tests in `tests/`
4. Run `make check` to ensure quality
5. Commit with descriptive message
6. Push and create pull request

### Running Scanner Locally

```bash
# Auto-detect local network
python src/network_scanner.py

# Scan specific subnet
python src/network_scanner.py --subnet 192.168.1.0/24

# Debug mode
python src/network_scanner.py --verbose --log-level DEBUG

# Custom configuration
python src/network_scanner.py --subnet 10.0.0.0/24 --threads 100 --ports 22,80,443
```

### Running Tests

```bash
# All tests
pytest tests/

# Verbose output
pytest tests/ -v

# With coverage
pytest tests/ --cov=src

# Specific test file
pytest tests/test_network_scanner.py

# Specific test class
pytest tests/test_network_scanner.py::TestNetworkScanner

# Specific test method
pytest tests/test_network_scanner.py::TestNetworkScanner::test_ping_host_success

# Stop on first failure
pytest tests/ -x

# Show print statements
pytest tests/ -s
```

## Important Files to Know

| File | Purpose |
|------|---------|
| `src/network_scanner.py` | Main `NetworkScanner` class - core logic |
| `src/config.py` | `ScanConfig` dataclass & constants |
| `tests/test_network_scanner.py` | Unit and integration tests |
| `pyproject.toml` | Package metadata and tool configs |
| `.pylintrc` | Linting rules and exclusions |

## Key Classes & Methods

### NetworkScanner Class
```python
class NetworkScanner:
    def __init__(self, config: ScanConfig)
    def get_local_network(self) -> str
    def ping_host(self, ip: str) -> bool
    def scan_network(self) -> Set[str]
    def arp_scan(self) -> Set[str]
    def scan_ports(self, host: str) -> Tuple[List[int], List[str]]
    def generate_report(self) -> str
    def save_report(self, output_file: Optional[str] = None)
    def run_scan(self) -> None
```

### ScanConfig Dataclass
```python
@dataclass
class ScanConfig:
    subnet: str = "auto"
    timeout: float = 1.0
    max_threads: int = 50
    use_arp: bool = True
    use_ping: bool = True
    scan_ports: bool = True
    output_file: str = "scan_results.txt"
    # ... more fields
```

## Testing Checklist

Before submitting a PR:

- [ ] Code follows style guide (black, pylint)
- [ ] Type hints are present and correct
- [ ] Docstrings are clear and complete
- [ ] All tests pass: `pytest tests/ -v`
- [ ] Code coverage maintained: `pytest --cov=src`
- [ ] Type checking passes: `mypy src/`
- [ ] No linting warnings: `pylint src/`
- [ ] Commit message is descriptive

## Release Process

1. Update version in `pyproject.toml` and `src/__init__.py`
2. Update `CHANGELOG.md` with new features
3. Create git tag: `git tag v2.0.0`
4. Push tag: `git push origin v2.0.0`
5. GitHub Actions will automatically build and test
6. Download distributions from Actions artifacts

## Troubleshooting

**Q: Import errors when running tests?**
```bash
# Add src to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
pytest tests/
```

**Q: Changes not reflected?**
```bash
# Clear Python cache
find . -type d -name __pycache__ -exec rm -rf {} +
find . -type d -name .pytest_cache -exec rm -rf {} +
```

**Q: Need to reinstall in dev mode?**
```bash
pip install -e .
```

## Resources

- [Python Style Guide (PEP 8)](https://pep8.org/)
- [Type Hints Documentation](https://docs.python.org/3/library/typing.html)
- [Pytest Documentation](https://docs.pytest.org/)
- [Black Formatter](https://github.com/psf/black)
- [Pylint Documentation](https://pylint.readthedocs.io/)

## Getting Help

- Check existing [issues](https://github.com/HughKnightOCE/NetworkScanner/issues)
- Read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
- Ask in [GitHub Discussions](https://github.com/HughKnightOCE/NetworkScanner/discussions)

---

**Happy coding! 🚀**
