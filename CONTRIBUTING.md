# Contributing to Network Scanner

First off, thank you for considering contributing to Network Scanner! It's people like you that make this tool such a great resource.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps which reproduce the problem**
- **Provide specific examples to demonstrate the steps**
- **Describe the behavior you observed after following the steps**
- **Explain which behavior you expected to see instead and why**
- **Include screenshots and animated GIFs if possible**
- **Include your OS version and Python version**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title**
- **Provide a step-by-step description of the suggested enhancement**
- **Provide specific examples to demonstrate the steps**
- **Describe the current behavior and the expected behavior**
- **Include screenshots and animated GIFs if possible**
- **Explain why this enhancement would be useful**

### Pull Requests

- Follow the Python/PEP 8 style guide
- Include appropriate test cases
- Update documentation as needed
- End all files with a newline

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/NetworkScanner.git
cd NetworkScanner

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Create a new branch for your feature
git checkout -b feature/amazing-feature
```

## Code Quality Standards

Before submitting a pull request, ensure your code passes:

```bash
# Format code
black src/

# Check types
mypy src/

# Lint code
pylint src/

# Run tests
pytest tests/
```

## Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

Example:
```
feat: Add IPv6 subnet support

- Implement IPv6 network detection
- Support CIDR notation for IPv6
- Add tests for IPv6 scanning

Closes #123
```

## Attribution

This Contributing guideline is adapted from the [Atom Contributing Guide](https://github.com/atom/atom/blob/master/CONTRIBUTING.md).

---

Thank you for contributing! 🎉
