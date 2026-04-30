# Contributing to SecureScan

Thank you for your interest in contributing to SecureScan! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We're all here to improve application security together.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - SecureScan version
   - Python version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

### Suggesting Features

1. Check existing feature requests
2. Describe the use case
3. Explain how it benefits users
4. Consider implementation complexity

### Adding Security Rules

We welcome new security detection rules! To add a rule:

#### SAST Rules

1. Add to `securescan/scanners/sast_scanner.py`:

```python
SASTRule(
    rule_id="SAST0XX",           # Unique ID
    title="Rule Title",          # Short description
    description="...",           # Detailed explanation
    pattern=r'...',              # Regex pattern
    severity="critical|high|medium|low",
    cwe_id="CWE-XXX",           # CWE reference
    languages=["python", ...],   # Applicable languages
    remediation="...",           # How to fix
    fix_example="...",           # Code example
    references=["..."]           # URLs for more info
)
```

2. Test the rule against known vulnerable code
3. Verify no false positives on common patterns
4. Add test cases

#### Secrets Patterns

1. Add to `securescan/scanners/secrets_scanner.py`:

```python
SecretPattern(
    pattern_id="SEC0XX",
    name="Service Name Token",
    pattern=re.compile(r'...'),
    severity="critical|high|medium",
    description="...",
    false_positive_patterns=["test", "example"]
)
```

2. Test against real token formats (use revoked/test tokens)
3. Add false positive patterns to reduce noise

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest`
5. Run linting: `flake8 securescan/`
6. Format code: `black securescan/`
7. Commit with clear messages
8. Push and create a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/securescan.git
cd securescan

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8 securescan/
black --check securescan/
mypy securescan/
```

## Testing

- Write tests for new features
- Maintain or improve code coverage
- Test edge cases and error handling
- Include both positive and negative test cases

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=securescan --cov-report=html

# Run specific test file
pytest tests/test_sast_scanner.py
```

## Pull Request Guidelines

1. **Title**: Clear, concise description of changes
2. **Description**: Explain what and why
3. **Tests**: Include relevant tests
4. **Documentation**: Update docs if needed
5. **Breaking Changes**: Clearly note any breaking changes

## Release Process

1. Update version in `__init__.py`, `setup.py`, `pyproject.toml`
2. Update CHANGELOG.md
3. Create release PR
4. After merge, tag the release
5. GitHub Actions will publish to PyPI

## Questions?

Open an issue with the "question" label or reach out to maintainers.

Thank you for contributing! 🛡️
