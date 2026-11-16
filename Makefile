PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help venv install dev test lint format format-check bandit check docs build clean

help:
	@echo "Targets:"
	@echo "  venv          create $(VENV) and install the project with dev extras"
	@echo "  install       install the project into the active environment"
	@echo "  dev           install with dev extras into the active environment"
	@echo "  test          run the test suite"
	@echo "  lint          run ruff check"
	@echo "  format        apply ruff formatting"
	@echo "  format-check  verify formatting without writing"
	@echo "  bandit        run the security linter over src"
	@echo "  check         lint, format check, bandit, and tests"
	@echo "  docs          regenerate docs/RULES.md from the rule pack"
	@echo "  build         build sdist and wheel"
	@echo "  clean         remove caches and build artifacts"

venv:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e ".[dev]"

install:
	$(PYTHON) -m pip install .

dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

format-check:
	$(PYTHON) -m ruff format --check .

bandit:
	$(PYTHON) -m bandit -r src

check: lint format-check bandit test

docs:
	$(PYTHON) scripts/generate_rule_docs.py

build:
	$(PYTHON) -m build

clean:
	rm -rf build dist .pytest_cache .ruff_cache .coverage htmlcov
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.egg-info' -type d -prune -exec rm -rf {} +
