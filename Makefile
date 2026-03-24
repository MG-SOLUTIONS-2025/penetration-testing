.PHONY: deploy up down migrate revision shell test lint format pull-scanners logs

# deploy: free port 3102, build images, run migrations, start all services
deploy:
	@echo "Stopping any container occupying port 3102..."
	-docker ps --filter publish=3102 --format '{{.Names}}' | xargs -r docker stop
	docker compose build
	docker compose up -d

# up: start services (assumes images are built and port 3102 is free)
up:
	docker compose up -d

# down: stop and remove containers (data volumes preserved)
down:
	docker compose down

# logs: tail all service logs
logs:
	docker compose logs -f

# build: rebuild all Docker images without starting services
build:
	docker compose build

# migrate: apply pending database migrations (local dev, not in Docker)
migrate:
	uv run alembic upgrade head

# revision: generate a new Alembic migration. Usage: make revision msg="add foo table"
revision:
	uv run alembic revision --autogenerate -m "$(msg)"

# shell: open a bash shell inside the running API container
shell:
	docker compose exec api bash

# test: run the full pytest suite
test:
	uv run pytest tests/ -v

# lint: check code style with ruff
lint:
	uv run ruff check .

# format: auto-format code with ruff
format:
	uv run ruff format .

# pull-scanners: pre-pull Docker images for the scanning tools
pull-scanners:
	docker pull instrumentisto/nmap
	docker pull projectdiscovery/subfinder
	docker pull projectdiscovery/nuclei

# dev: run the API locally with hot-reload (requires local postgres + redis)
dev:
	uv run uvicorn src.api.app:app --reload --port 8000

# worker: run a local Celery worker (requires local postgres + redis)
worker:
	uv run celery -A src.worker.celery_app worker --loglevel=info -Q scans,celery
