.DEFAULT_GOAL := help

.PHONY: help sync lint format typecheck test-unit test-integration test-docker db-up db-down check frontend-check demo run hooks

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

test-integration: ## Postgres tests (run `make db-up` first); skips without DATABASE_URL_TEST
	DATABASE_URL_TEST=$${DATABASE_URL_TEST:-postgresql+psycopg://postgres:postgres@localhost:5432/postgres} uv run pytest tests/integration -q -m integration

test-docker: ## Real image builds (slow; needs Docker, buildx and network)
	uv run pytest tests/integration -q -m docker

db-up: ## Start a throwaway local Postgres 17 on :5432 (needs Docker)
	docker run -d --rm --name dabao-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17

db-down: ## Stop the local Postgres
	docker stop dabao-pg

check: lint typecheck test-unit ## Everything the pre-push hook runs

frontend-check: ## Frontend: svelte-check, vitest, build (needs Node 22)
	cd frontend && npm ci && npm run check && npm test && npm run build

demo: ## Seed fake demo data into ./dabao.db and start the API
	uv run python scripts/seed_demo.py
	$(MAKE) run

run: ## Dev server on the first free port from 8000
	uv run python scripts/run_dev.py

hooks: ## Install the pre-push hook
	ln -sf ../../scripts/git-hooks/pre-push .git/hooks/pre-push
