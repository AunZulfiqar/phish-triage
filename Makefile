.PHONY: help install test lint cov samples docs shots web demo clean

help:
	@echo "install  - editable install with dev extras"
	@echo "test     - run the test suite"
	@echo "cov      - run tests with a coverage report"
	@echo "lint     - ruff"
	@echo "samples  - regenerate the synthetic sample corpus"
	@echo "docs     - regenerate docs/indicators.md and docs/demo-output.txt"
	@echo "shots    - regenerate the README screenshots (needs Chrome)"
	@echo "web      - run the web UI on :8000"
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

shots:
	python tools/screenshots.py

web:
	python -m webapp --port 8000

demo:
	python -m phishtriage analyze samples/ --format summary --fail-on never
