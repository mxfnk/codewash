# Contributing to codewash

Thank you for your interest in contributing! We welcome pull requests, bug reports, and feature suggestions.

## Code of Conduct

Please be respectful and constructive in all interactions.

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/your-username/codewash.git
cd codewash
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install in Development Mode

```bash
pip install -e ".[dev]"
```

### 4. Verify Tests Pass

```bash
pytest
```

## Development Workflow

### Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### Make Changes

- Write clean, readable code
- Follow PEP 8 guidelines
- Add tests for new functionality
- Update docs if needed

### Run Quality Checks

```bash
# Run tests
pytest -v

# Type checking
mypy src/

# Linting
ruff check src/
ruff format src/
```

### Commit Your Changes

Write clear, descriptive commit messages:

```
Add support for custom regex patterns in config

- Add CustomPattern dataclass to models.py
- Extend CodewashConfig to load additional_patterns from YAML
- Add tests for pattern compilation and validation
```

### Push and Create a Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a PR on GitHub with a clear description of your changes.

## Types of Contributions

### Bug Reports

Please include:
- A clear description of the bug
- Steps to reproduce it
- Expected behavior vs. actual behavior
- Your OS and Python version
- Any relevant log output

### Feature Requests

Describe:
- What problem does it solve?
- Who would benefit?
- Any alternative approaches you considered

### Pattern Improvements

We're always looking to improve pattern detection. If you have:
- New regex patterns that catch sensitive data better
- Improvements to existing patterns
- Allowlist additions

Please submit a PR with tests demonstrating the improvement.

## Testing

### Adding Tests

Tests go in the `tests/` directory, organized by module:
- `test_scanner.py` — File discovery tests
- `test_detector.py` — Pattern detection tests
- `test_replacer.py` — Anonymization and restoration tests
- `test_config.py` — Configuration loading tests

Example test:

```python
def test_detects_my_pattern(self):
    assert Category.CUSTOM in categories("my_pattern: some_value")
```

### Test Coverage

Aim for high coverage, especially for:
- New detection patterns
- Edge cases (empty files, binary files, symlinks, etc.)
- Error conditions

Run coverage report:

```bash
pytest --cov=src/codewash tests/
```

## Documentation

- Update `README.md` for user-facing changes
- Update `docs/patterns.md` for new detection categories
- Add docstrings to public functions and classes
- Keep the architecture clear and maintainable

## Code Style

- Use type hints throughout (`from __future__ import annotations`)
- Use dataclasses for data structures
- Write descriptive variable names
- Keep functions focused and testable

Example:

```python
from dataclasses import dataclass

@dataclass
class Finding:
    """A single sensitive finding in a file."""
    category: Category
    line: int
    column: int
    matched_text: str
```

## Before Submitting a PR

- [ ] Tests pass (`pytest`)
- [ ] Code is formatted (`ruff format src/`)
- [ ] Linting passes (`ruff check src/`)
- [ ] Type checking passes (`mypy src/`)
- [ ] Commit messages are clear and descriptive
- [ ] PR description explains the "why" and "what"

## Questions?

- Open an issue for discussion
- Ask in PR comments
- Reach out on GitHub Discussions (if available)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for making codewash better!
