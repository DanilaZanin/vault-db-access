import hashlib
import time

import hvac

from . import config

PASSWORD_POLICY_HCL = """
length = 12
rule "charset" {
  charset = "abcdefghijklmnopqrstuvwxyz"
  min-chars = 3
}
rule "charset" {
  charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  min-chars = 3
}
rule "charset" {
  charset = "0123456789"
  min-chars = 3
}
rule "charset" {
  charset = "!@#%^&*-_="
  min-chars = 2
}
"""

# random-N is alphanumeric only, so the generated login never contains special characters.
USERNAME_TEMPLATE = '{{ printf "v%s" (random 15) | lowercase | truncate 20 }}'


def client(token: str | None = None) -> hvac.Client:
    return hvac.Client(url=config.VAULT_ADDR, token=token)


def wait_for_vault(timeout: int = 60) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            client().sys.is_initialized()
            return
        except Exception as exc:  # noqa: BLE001 - retry loop, any connection error is transient
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"vault did not become reachable in time: {last_error}")


def ensure_database_engine(c: hvac.Client) -> None:
    mounts = c.sys.list_mounted_secrets_engines()["data"]
    if "database/" not in mounts:
        c.sys.enable_secrets_engine(backend_type="database", path="database")


def ensure_password_policy(c: hvac.Client) -> None:
    c.write(f"sys/policies/password/{config.PASSWORD_POLICY_NAME}", policy=PASSWORD_POLICY_HCL)


def ensure_clickhouse_plugin(c: hvac.Client) -> None:
    with open(config.VAULT_PLUGIN_PATH, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    c.write(
        "sys/plugins/catalog/database/clickhouse-database-plugin",
        sha256=digest,
        command="clickhouse-database-plugin",
    )


def ensure_postgres_connection(c: hvac.Client, username: str, password: str) -> None:
    # Note: Vault's schedule-based root rotation (`rotation_period`/`rotation_schedule`)
    # is Enterprise-only in Vault 2.0 ("rotation manager capabilities not supported in
    # Vault Community Edition") -- confirmed while building this, not used here. Manual
    # rotation via `database/rotate-root/<name>` (see main.py) is unaffected and used instead.
    c.write(
        f"database/config/{config.POSTGRES_CONNECTION_NAME}",
        plugin_name="postgresql-database-plugin",
        allowed_roles="*",
        connection_url=(
            f"postgresql://{{{{username}}}}:{{{{password}}}}@"
            f"{config.POSTGRES_HOST}:{config.POSTGRES_PORT}/{config.POSTGRES_DB}?sslmode=disable"
        ),
        username=username,
        password=password,
        username_template=USERNAME_TEMPLATE,
    )


def ensure_clickhouse_connection(c: hvac.Client, username: str, password: str) -> None:
    c.write(
        f"database/config/{config.CLICKHOUSE_CONNECTION_NAME}",
        plugin_name="clickhouse-database-plugin",
        allowed_roles="*",
        connection_url=(
            f"clickhouse://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}"
            f"?username={{{{username}}}}&password={{{{password}}}}&dial_timeout=10s"
        ),
        username=username,
        password=password,
        username_template=USERNAME_TEMPLATE,
    )
