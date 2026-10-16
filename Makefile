.DEFAULT_GOAL := help

.PHONY: help sync lint format typecheck test-unit test-integration check run hooks

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

sync: ## Install dependencies (frozen lockfile)
	uv sync --frozen

lint: ## ruff check + format check
	uv run ruff check .
	uv run ruff format --check .

format: ## Auto-format
	uv run ruff check --fix .
	uv run ruff format .

typecheck: ## mypy (strict)
	uv run mypy

test-unit: ## Fast layer: no Docker, no network
	uv run pytest tests/unit -q

test-integration: ## Needs Docker
	uv run pytest tests/integration -q -m integration

check: lint typecheck test-unit ## Everything the pre-push hook runs

run: ## Dev server on the first free port from 8000
	uv run python scripts/run_dev.py

hooks: ## Install the pre-push hook
	ln -sf ../../scripts/git-hooks/pre-push .git/hooks/pre-push
