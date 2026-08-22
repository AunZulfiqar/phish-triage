.PHONY: help install test lint cov samples docs demo clean

help:
	@echo "install  - editable install with dev extras"
	@echo "test     - run the test suite"
	@echo "cov      - run tests with a coverage report"
	@echo "lint     - ruff"
	@echo "samples  - regenerate the synthetic sample corpus"
	@echo "docs     - regenerate docs/indicators.md and docs/demo-output.txt"
	@echo "demo     - analyse the sample corpus"

install:
	pip install -e ".[dev]"

test:
	pytest

cov:
	pytest --cov=phishtriage --cov-report=term-missing

lint:
	ruff check .

samples:
	python samples/generate.py

docs:
	python tools/gendocs.py

demo:
	python -m phishtriage analyze samples/ --format summary --fail-on never
