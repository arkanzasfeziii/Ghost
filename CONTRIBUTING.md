# Contributing to Ghost

Thank you for your interest in contributing to Ghost. This document provides
guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check existing [Issues](https://github.com/arkanzasfeziii/Ghost/issues) to
   avoid duplicates.
2. Open a new issue using the **Bug Report** template.
3. Include steps to reproduce, expected behavior, and actual behavior.

### Suggesting Features

1. Open a new issue using the **Feature Request** template.
2. Describe the use case and expected behavior.

### Submitting Changes

1. Fork the repository.
2. Create a feature branch from `master`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
3. Make your changes following the coding standards below.
4. Run linting and tests:
   ```bash
   make lint
   make test
   ```
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add new encoder variant
   fix: handle edge case in XOR encoding
   docs: update AMSI bypass documentation
   refactor: extract shellcode format converter
   test: add unit tests for AVEvasionModule
   ```
6. Push to your fork and open a Pull Request.

## Coding Standards

- **Python 3.10+** required.
- Follow [PEP 8](https://peps.python.org/pep-0008/) style guide.
- Use type hints for all function signatures.
- Keep functions under 50 lines where possible.
- Use `snake_case` for functions and variables, `PascalCase` for classes.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/arkanzasfeziii/Ghost.git
cd Ghost

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Legal

All contributions must comply with the project's ethical use policy. Ghost is
designed exclusively for authorized penetration testing and red team
engagements. Do not submit code intended for malicious use.
