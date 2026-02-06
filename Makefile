# Network Scanner - Makefile

.PHONY: help install install-dev test lint format check-types clean build docs

help:
	@echo "Network Scanner - Available Commands"
	@echo "====================================="
	@echo ""
	@echo "Setup:"
	@echo "  make install          - Install runtime dependencies"
	@echo "  make install-dev      - Install development dependencies"
	@echo "  make install-all      - Install all dependencies"
	@echo ""
	@echo "Development:"
	@echo "  make check            - Run all checks (lint, types, tests)"
	@echo "  make lint             - Run pylint code analysis"
	@echo "  make format           - Format code with black"
	@echo "  make check-types      - Check type hints with mypy"
	@echo "  make test             - Run unit tests"
	@echo "  make test-coverage    - Run tests with coverage report"
	@echo ""
	@echo "Project:"
	@echo "  make clean            - Remove build artifacts and cache"
	@echo "  make build            - Build distribution packages"
	@echo "  make docs             - Generate documentation (if available)"
	@echo ""
	@echo "Execution:"
	@echo "  make run              - Run scanner with default settings"
	@echo "  make run-help         - Show scanner help"
	@echo ""

install:
	python -m pip install --upgrade pip
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

install-all: install install-dev

check: lint check-types test
	@echo "✓ All checks passed!"

lint:
	@echo "Running pylint..."
	pylint src/ --rcfile=.pylintrc

format:
	@echo "Formatting code with black..."
	black src/ tests/ example/
	@echo "✓ Code formatted"

check-types:
	@echo "Checking type hints with mypy..."
	mypy src/ --config-file=pyproject.toml

test:
	@echo "Running tests..."
	pytest tests/ -v

test-coverage:
	@echo "Running tests with coverage..."
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing
	@echo "✓ Coverage report generated (check htmlcov/index.html)"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .mypy_cache/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo "✓ Clean complete"

build: clean
	@echo "Building distribution packages..."
	python -m build

docs:
	@echo "Building documentation..."
	@echo "Note: Sphinx documentation coming in future release"

run:
	python -m src.network_scanner

run-help:
	python -m src.network_scanner --help

.DEFAULT_GOAL := help
