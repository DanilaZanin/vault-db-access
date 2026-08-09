import json

from . import config


def _load() -> dict:
    with open(config.VAULT_SECRETS_PATH) as f:
        return json.load(f)


def postgres_introspect_password() -> str:
    return _load()["postgres_introspect_password"]


def clickhouse_introspect_password() -> str:
    return _load()["clickhouse_introspect_password"]
