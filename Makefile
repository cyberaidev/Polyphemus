# Polyphemus — bedrock-secure-rag-reference
#
# The `setup`, `demo`, and `test` targets run FULLY OFFLINE in mock mode and
# require NO AWS credentials. IaC targets are reference-only.

VENV        ?= .venv
PY          := $(VENV)/bin/python
PIP         := $(VENV)/bin/pip
export POLYPHEMUS_MODE ?= mock

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

$(VENV)/bin/activate: requirements.txt requirements-dev.txt
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt -r requirements-dev.txt
	touch $(VENV)/bin/activate

.PHONY: setup
setup: $(VENV)/bin/activate ## Create venv and install runtime + dev deps

.PHONY: seed
seed: setup ## Seed the (mock) vector store from data/documents
	POLYPHEMUS_MODE=mock $(PY) scripts/seed_store.py

.PHONY: demo
demo: setup ## Run all 4 security scenarios offline (mock mode)
	POLYPHEMUS_MODE=mock $(PY) scripts/run_demo.py

.PHONY: test
test: setup ## Run the test suite offline (mock mode)
	POLYPHEMUS_MODE=mock $(PY) -m pytest -q

.PHONY: coverage
coverage: setup ## Run tests with coverage
	POLYPHEMUS_MODE=mock $(PY) -m pytest --cov=polyphemus --cov-report=term-missing

.PHONY: lint
lint: setup ## ruff + black --check
	$(VENV)/bin/ruff check src scripts tests api
	$(VENV)/bin/black --check src scripts tests api

.PHONY: format
format: setup ## Auto-format with black + ruff --fix
	$(VENV)/bin/black src scripts tests api
	$(VENV)/bin/ruff check --fix src scripts tests api

.PHONY: typecheck
typecheck: setup ## mypy static type checking
	$(VENV)/bin/mypy src

.PHONY: render-diagram
render-diagram: setup ## Regenerate docs/architecture.svg (pure Python, no network)
	$(PY) scripts/render_architecture.py

.PHONY: tf-init
tf-init: ## (reference only) terraform init
	cd iac/terraform && terraform init

.PHONY: tf-plan
tf-plan: ## (reference only) terraform plan
	cd iac/terraform && terraform plan

.PHONY: cdk-synth
cdk-synth: ## (reference only) cdk synth
	cd iac/cdk && cdk synth

.PHONY: clean
clean: ## Remove caches, venv, and runtime audit logs
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache audit
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
