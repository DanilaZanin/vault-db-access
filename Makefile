# make env    generate .env with random secrets (never overwrites an existing one)
# make up     build + start the stack, run one-off setup (init/unseal Vault, provision, revoke root)
# make test   unit tests, then integration tests if the stack is running (skipped cleanly otherwise)
# make check  fresh stack with test hooks, run everything, leave the stack up
# make down   destroy the stack, its volumes and ./secrets (demo reset)
COMPOSE ?= docker compose
SETUP_ARGS ?=

.PHONY: env up setup test unit lint check down logs

env:
	@test -f .env && echo ".env exists, leaving it alone" || { \
	  while IFS= read -r line; do \
	    case "$$line" in \
	      *=changeme) echo "$${line%=changeme}=$$(openssl rand -hex 24)";; \
	      *) echo "$$line";; \
	    esac; \
	  done < .env.example > .env; chmod 600 .env; echo "wrote .env"; }

up: env
	@mkdir -p secrets/approle && chmod 700 secrets
	$(COMPOSE) up -d --build --wait postgres clickhouse vault
	VDBA_SETUP_ARGS="$(SETUP_ARGS)" $(COMPOSE) --profile setup run --rm --build setup
	$(COMPOSE) up -d --build --wait middleware
	@echo "portal: http://127.0.0.1:8000  (admin user/password: see VDBA_ADMIN_* in .env)"

setup:
	VDBA_SETUP_ARGS="$(SETUP_ARGS)" $(COMPOSE) --profile setup run --rm setup

unit:
	uv run pytest tests/unit -q

lint:
	uv run ruff check . && uv run ruff format --check .

test: unit
	uv run pytest tests/integration -q

check: down
	VDBA_TEST_HOOKS=1 VDBA_RECONCILE_INTERVAL=5 $(MAKE) up
	$(MAKE) test

down:
	$(COMPOSE) --profile setup down -v --remove-orphans
	@docker run --rm --user root -v "$$PWD/secrets:/s" --entrypoint sh vdba-app:local -c 'chmod -R u+rwx /s; rm -rf /s/* /s/.[!.]*' || rm -rf secrets/*

logs:
	$(COMPOSE) logs -f --tail=100
