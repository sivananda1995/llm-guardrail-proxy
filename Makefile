# Every target regenerates something this repository claims. Nothing post-processes a number.
#
# PYTHONPATH is set per-target rather than expected from the environment, because `attacks/` is
# deliberately outside the installed package and a target that only works after the reader exports a
# variable is a target that fails for the reader.
.PHONY: help install lint test test-fast verify demo report leak base-rate bypass redos latency \
        experiments receipts shots video all clean

export PYTHONPATH := src:.

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t -s "$$(printf '\t')"

install: ## install with the dev extras
	pip install -e ".[dev]"

lint: ## ruff
	ruff check .

# `python -m pytest` rather than `pytest`: a uv-installed pytest earlier on PATH shadows the one in
# this environment and cannot see pytest-cov, which fails with a confusing unrecognised-argument error.
test: ## the whole suite, with coverage
	python -m pytest --cov=guardrail --cov-report=term --cov-report=xml

test-fast: ## the suite without coverage instrumentation
	python -m pytest

demo: ## the whole CLI tour, in the order the arguments build
	bash tools/run_demo.sh

report: ## the JSON, markdown and HTML report from one payload
	python -m guardrail.cli report --out docs/report

leak: ## what streaming costs and what buffering costs
	python experiments/stream_vs_buffer.py

base-rate: ## precision at prevalence, and how large a corpus a block would need
	python experiments/base_rate.py

bypass: ## which normalisation step each evasion depends on, and the oracle
	python experiments/bypass_matrix.py

redos: ## switching the guardrail off with twenty-four characters
	python experiments/redos_fail_open.py

latency: ## the two currencies the guardrail spends: milliseconds and characters
	python experiments/latency_budget.py

experiments: leak base-rate bypass redos latency ## all five

receipts: ## re-measure every published number and fail if a document quotes a stale one
	python tools/collect_metrics.py
	python tools/check_numbers.py

shots: ## regenerate the README screenshots from real output
	python tools/capture_screenshots.py

video: ## record the demo video and GIF from real command output
	python tools/record_demo.py

verify: lint test receipts ## lint, the full suite, and every number re-measured

all: experiments report demo shots video receipts ## everything, in order

clean:
	rm -rf reports .pytest_cache .ruff_cache .coverage coverage.xml htmlcov docs/report
