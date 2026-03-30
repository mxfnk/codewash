.PHONY: help install install-dev lint format type-check test coverage clean build publish

help:
	@echo "codewash development tasks"
	@echo ""
	@echo "Available targets:"
	@echo "  install       Install codewash in production mode"
	@echo "  install-dev   Install codewash with development dependencies"
	@echo "  lint          Run ruff linter"
	@echo "  format        Format code with ruff"
	@echo "  type-check    Run mypy type checking"
	@echo "  test          Run pytest tests"
	@echo "  coverage      Run tests with coverage report"
	@echo "  clean         Remove build artifacts and cache"
	@echo "  build         Build distribution packages"
	@echo "  publish       Publish to PyPI (requires credentials)"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

type-check:
	mypy src/

test:
	pytest -v

coverage:
	pytest tests/ -v --cov=src/codewash --cov-report=term-missing --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

clean:
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache

build: clean
	python -m pip install --upgrade build
	python -m build

publish: build
	python -m pip install --upgrade twine
	python -m twine upload dist/*
