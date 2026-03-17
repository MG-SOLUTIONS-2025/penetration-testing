.PHONY: up down migrate revision shell test lint format pull-scanners

up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

migrate:
	uv run alembic upgrade head

revision:
	uv run alembic revision --autogenerate -m "$(msg)"

shell:
	docker compose exec api bash

test:
	uv run pytest tests/ -v

lint:
	uv run ruff check .

format:
	uv run ruff format .

pull-scanners:
	docker pull instrumentisto/nmap
	docker pull projectdiscovery/subfinder
	docker pull projectdiscovery/nuclei

dev:
	uv run uvicorn src.api.app:app --reload --port 8000

worker:
	uv run celery -A src.worker.celery_app worker --loglevel=info -Q scans,celery
