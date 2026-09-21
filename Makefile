.PHONY: help setup test lint format audit check run clean

PYTHON ?= python3
VENV ?= .venv
BIN = $(VENV)/bin

help:
	@echo "Lineage Developer Targets:"
	@echo "  setup   - Create virtual environment and install dev dependencies"
	@echo "  test    - Run pytest test suite"
	@echo "  lint    - Run ruff and black checks"
	@echo "  format  - Auto-format code with ruff and black"
	@echo "  audit   - Scan dependencies for known vulnerabilities"
	@echo "  check   - Run lint, format check, audit, and tests"
	@echo "  run     - Run the lineage detector (requires root)"
	@echo "  clean   - Remove build and test caches"

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip setuptools
	$(BIN)/pip install -r requirements-dev.txt

test:
	$(BIN)/pytest tests/ -v

lint:
	$(BIN)/ruff check lineage/ tests/
	$(BIN)/black --check lineage/ tests/

format:
	$(BIN)/ruff check lineage/ tests/ --fix
	$(BIN)/black lineage/ tests/

audit:
	$(BIN)/pip-audit -r requirements-dev.txt

check: lint test audit

run:
	sudo $(PYTHON) -m lineage.detector

clean:
	rm -rf .pytest_cache .ruff_cache __pycache__ lineage/__pycache__ tests/__pycache__
