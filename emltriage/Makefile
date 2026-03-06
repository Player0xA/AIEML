.PHONY: help install install-ai test lint format clean docker-build docker-run

help:
	@echo "emltriage Makefile"
	@echo "=================="
	@echo ""
	@echo "Development:"
	@echo "  make install       Install base package with venv"
	@echo "  make install-ai    Install with AI support"
	@echo "  make install-dev   Install with dev dependencies"
	@echo "  make test          Run tests"
	@echo "  make lint          Run linter (ruff)"
	@echo "  make format        Format code (ruff)"
	@echo "  make typecheck     Run type checker (mypy)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-run    Run with Docker Compose"
	@echo "  make docker-stop   Stop Docker containers"
	@echo ""
	@echo "Clean:"
	@echo "  make clean         Remove build artifacts"
	@echo "  make clean-all     Remove venv and all artifacts"

# Virtual environment
venv:
	python3 -m venv venv

install: venv
	. venv/bin/activate && pip install --upgrade pip
	. venv/bin/activate && pip install -r requirements.txt
	. venv/bin/activate && pip install -e .
	@echo "✅ Installation complete!"
	@echo "Activate with: source venv/bin/activate"

install-ai: venv
	. venv/bin/activate && pip install --upgrade pip
	. venv/bin/activate && pip install -r requirements.txt
	. venv/bin/activate && pip install -r requirements-ai.txt
	. venv/bin/activate && pip install -e .
	@echo "✅ Installation with AI support complete!"

install-dev: venv
	. venv/bin/activate && pip install --upgrade pip
	. venv/bin/activate && pip install -r requirements.txt
	. venv/bin/activate && pip install -r requirements-ai.txt
	. venv/bin/activate && pip install -e ".[dev]"
	@echo "✅ Development installation complete!"

test:
	. venv/bin/activate && python -m pytest tests/ -v

lint:
	. venv/bin/activate && ruff check emltriage/

format:
	. venv/bin/activate && ruff format emltriage/

typecheck:
	. venv/bin/activate && mypy emltriage/

# Docker
docker-build:
	docker build -t emltriage:latest .

docker-run:
	mkdir -p data output watchlists
	docker-compose up -d
	@echo "🐳 Containers started!"
	@echo "Check logs: docker-compose logs -f"

docker-stop:
	docker-compose down
	@echo "🛑 Containers stopped"

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name ".DS_Store" -delete
	rm -f .cti_cache.db

clean-all: clean
	rm -rf venv/
	rm -rf data/
	rm -rf output/
	@echo "🧹 All cleaned!"
