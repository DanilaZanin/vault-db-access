# make up        one command from a clean clone: .env (random secrets), build, start, setup, portal
# make test      unit tests, then integration tests if the stack is running (skipped with a loud banner otherwise)
# make check     fresh stack with test hooks, unit + integration; FAILS if the stack is unreachable
# make lint      ruff check + format check (+ hadolint when installed)
# make audit     pip-audit on the locked runtime dependencies
# make images    build the two images locally (vdba-app:local, vdba-vault:local)
# make up-release  run the published signed images from GHCR instead of building (VDBA_VERSION=v0.1.0)
# make down      destroy the stack, its volumes and ./secrets (demo reset)
COMPOSE ?= docker compose
SETUP_ARGS ?=
export VDBA_HOST_UID ?= $(shell id -u)

.PHONY: env up up-release setup test unit lint audit images smoke-multiarch check down logs

env:
	@touch .env && chmod 600 .env
	@grep -v '^#' .env.example | grep '=' | while IFS= read -r line; do \
	  key=$${line%%=*}; \
	  grep -q "^$$key=" .env || { case "$$line" in \
	    *=changeme) echo "$${line%=changeme}=$$(openssl rand -hex 24)" >> .env;; \
	    *) echo "$$line" >> .env;; esac; echo "added $$key to .env"; }; \
	done

up: env
	@mkdir -p secrets/approle && chmod 700 secrets
	$(COMPOSE) up -d --build --wait postgres clickhouse vault
	VDBA_SETUP_ARGS="$(SETUP_ARGS)" $(COMPOSE) --profile setup run --rm --build setup
	$(COMPOSE) up -d --build --wait middleware
	@echo "portal: http://127.0.0.1:8000  (admin user/password: see VDBA_ADMIN_* in .env)"

up-release: env
	@mkdir -p secrets/approle && chmod 700 secrets
	$(COMPOSE) -f docker-compose.yml -f compose.release.yml pull
	$(COMPOSE) -f docker-compose.yml -f compose.release.yml up -d --wait postgres clickhouse vault
	VDBA_SETUP_ARGS="$(SETUP_ARGS)" $(COMPOSE) -f docker-compose.yml -f compose.release.yml --profile setup run --rm setup
	$(COMPOSE) -f docker-compose.yml -f compose.release.yml up -d --wait middleware
	@echo "portal: http://127.0.0.1:8000  (admin user/password: see VDBA_ADMIN_* in .env)"

setup:
	VDBA_SETUP_ARGS="$(SETUP_ARGS)" $(COMPOSE) --profile setup run --rm setup

unit:
	uv run pytest tests/unit -q

lint:
	uv run ruff check . && uv run ruff format --check .
	@if command -v hadolint >/dev/null; then hadolint --config .hadolint.yaml middleware/Dockerfile vault/Dockerfile; fi

audit:
	uv export --frozen --no-dev --no-emit-project --no-hashes > .requirements-audit.txt
	uv run pip-audit -r .requirements-audit.txt --no-deps --disable-pip; rc=$$?; rm -f .requirements-audit.txt; exit $$rc

images:
	$(COMPOSE) build vault
	$(COMPOSE) build preflight

# Release-path smoke test without a registry: cross-build both images for another architecture.
smoke-multiarch:
	@for arch in arm64 amd64; do \
	  docker buildx build --platform linux/$$arch -t vdba-vault:$$arch --load ./vault && \
	  docker buildx build --platform linux/$$arch --build-context vaultimg=docker-image://vdba-vault:$$arch \
	    -f middleware/Dockerfile -t vdba-app:$$arch --load . || exit 1; \
	done
	@docker image ls --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -E '^vdba-(vault|app):(arm64|amd64)'

test: unit
	@curl -sf http://127.0.0.1:8000/healthz >/dev/null || { echo; echo "!!! No running stack: integration tests will be SKIPPED. That is NOT a security check; use 'make check'. !!!"; echo; }
	uv run pytest tests/integration -q

check: down
	VDBA_TEST_HOOKS=1 VDBA_RECONCILE_INTERVAL=5 VDBA_SESSION_RECHECK_SECONDS=5 $(MAKE) up
	uv run pytest tests/unit -q
	VDBA_REQUIRE_STACK=1 uv run pytest tests/integration -q

down:
	$(COMPOSE) --profile setup down -v --remove-orphans
	@docker run --rm --user root -v "$$PWD/secrets:/s" --entrypoint sh vdba-app:local -c 'chmod -R u+rwx /s; rm -rf /s/* /s/.[!.]*' 2>/dev/null || rm -rf secrets/* 2>/dev/null || true

logs:
	$(COMPOSE) logs -f --tail=100
