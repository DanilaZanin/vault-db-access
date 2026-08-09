"""One-time setup for the Vault DB access system.

Run once per Vault deployment (not on every container start):

    docker compose run --rm middleware python -m app.first_time_setup \\
        --init --persist-secrets \\
        --admin-user ivanov --admin-password 'change-me'

In a real production Vault that an operator already initialized/unsealed
themselves (recommended: multiple key shares, no single point of compromise),
omit --init and pass a temporary privileged token instead:

    VAULT_ROOT_TOKEN=hvs.xxx docker compose run --rm middleware python -m app.first_time_setup \\
        --admin-user ivanov --admin-password 'change-me'

Either way this script only needs to run once; it is idempotent if re-run.
"""

import argparse
import json
import os
import secrets
import string

import clickhouse_connect
import hvac
import psycopg2

from . import bootstrap, config

ADMIN_POLICY_HCL = """
path "database/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "database/creds/*" {
  capabilities = ["read"]
}
path "database/config/*" {
  capabilities = ["create", "read", "update", "list"]
}
path "database/rotate-root/*" {
  capabilities = ["update"]
}
path "sys/policies/acl/read-grant-*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "auth/token/create/grant-token-issuer" {
  capabilities = ["create", "update"]
}
path "sys/leases/revoke-prefix/database/creds/*" {
  capabilities = ["update", "sudo"]
}
"""


def _gen_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _init_and_unseal(persist_secrets: bool) -> str:
    c = bootstrap.client()
    shares = int(os.environ.get("VAULT_INIT_SHARES", "1"))
    threshold = int(os.environ.get("VAULT_INIT_THRESHOLD", "1"))

    if c.sys.is_initialized():
        raise SystemExit(
            "vault is already initialized; supply VAULT_ROOT_TOKEN and omit --init instead"
        )

    result = c.sys.initialize(secret_shares=shares, secret_threshold=threshold)
    root_token = result["root_token"]
    keys = result["keys"]

    print("Vault initialized. Store these securely -- they are shown only once:")
    print(f"  root_token: {root_token}")
    for i, key in enumerate(keys):
        print(f"  unseal_key[{i}]: {key}")

    unseal_client = bootstrap.client()
    for key in keys[:threshold]:
        status = unseal_client.sys.submit_unseal_key(key)
        if not status["sealed"]:
            break

    if persist_secrets:
        with open(config.VAULT_SECRETS_PATH, "w") as f:
            json.dump({"root_token": root_token, "unseal_key": keys[0]}, f)
        os.chmod(config.VAULT_SECRETS_PATH, 0o600)
        print(f"(dev mode) also persisted root token + first unseal key to {config.VAULT_SECRETS_PATH}")

    return root_token


def _ensure_grant_token_role(c: hvac.Client) -> None:
    # Vault refuses to mint a child token with a policy the creator doesn't itself hold,
    # unless the creator uses a token role that explicitly allows it. The admin's own
    # token never holds a per-grant "read-grant-*" policy, so token-mode grants need this.
    c.write(
        "auth/token/roles/grant-token-issuer",
        allowed_policies_glob=["read-grant-*"],
        orphan=True,
        renewable=False,
    )


def _ensure_userpass_admin(c: hvac.Client, username: str, password: str) -> None:
    mounts = c.sys.list_auth_methods()["data"]
    if "userpass/" not in mounts:
        c.sys.enable_auth_method("userpass", path="userpass")

    c.write(f"sys/policies/acl/{config.ADMIN_POLICY_NAME}", policy=ADMIN_POLICY_HCL)
    c.write(f"auth/userpass/users/{username}", password=password, token_policies=[config.ADMIN_POLICY_NAME])


def _ensure_postgres_introspect_account(admin_password: str) -> str:
    introspect_password = _gen_password()
    conn = psycopg2.connect(
        host=config.POSTGRES_HOST,
        port=config.POSTGRES_PORT,
        user=config.POSTGRES_SUPERUSER,
        password=admin_password,
        dbname=config.POSTGRES_DB,
    )
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (config.POSTGRES_INTROSPECT_USER,))
            if cur.fetchone():
                cur.execute(
                    f'ALTER ROLE "{config.POSTGRES_INTROSPECT_USER}" WITH PASSWORD %s',
                    (introspect_password,),
                )
            else:
                cur.execute(
                    f'CREATE ROLE "{config.POSTGRES_INTROSPECT_USER}" WITH LOGIN PASSWORD %s',
                    (introspect_password,),
                )
    finally:
        conn.close()
    return introspect_password


def _ensure_clickhouse_introspect_account(admin_password: str) -> str:
    introspect_password = _gen_password()
    ch = clickhouse_connect.get_client(
        host=config.CLICKHOUSE_HOST,
        port=config.CLICKHOUSE_HTTP_PORT,
        username=config.CLICKHOUSE_ADMIN_USER,
        password=admin_password,
    )
    ch.command(f"CREATE USER IF NOT EXISTS {config.CLICKHOUSE_INTROSPECT_USER} IDENTIFIED BY '{introspect_password}'")
    ch.command(f"ALTER USER {config.CLICKHOUSE_INTROSPECT_USER} IDENTIFIED BY '{introspect_password}'")
    # SHOW TABLES (not SELECT) is enough to list table names without granting read access to data.
    ch.command(f"GRANT SHOW TABLES ON {config.CLICKHOUSE_DB}.* TO {config.CLICKHOUSE_INTROSPECT_USER}")
    return introspect_password


def _persist_introspect_passwords(pg_password: str | None, ch_password: str | None) -> None:
    data = {}
    if os.path.exists(config.VAULT_SECRETS_PATH):
        with open(config.VAULT_SECRETS_PATH) as f:
            data = json.load(f)
    if pg_password:
        data["postgres_introspect_password"] = pg_password
    if ch_password:
        data["clickhouse_introspect_password"] = ch_password
    with open(config.VAULT_SECRETS_PATH, "w") as f:
        json.dump(data, f)
    os.chmod(config.VAULT_SECRETS_PATH, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description="One-time Vault DB access system setup")
    parser.add_argument("--init", action="store_true", help="initialize and unseal a fresh Vault")
    parser.add_argument(
        "--persist-secrets", action="store_true", help="dev only: store root token/unseal key on disk"
    )
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--admin-password", required=True)
    args = parser.parse_args()

    bootstrap.wait_for_vault()

    if args.init:
        root_token = _init_and_unseal(args.persist_secrets)
    else:
        root_token = os.environ.get("VAULT_ROOT_TOKEN")
        if not root_token:
            raise SystemExit("VAULT_ROOT_TOKEN must be set when not using --init")

    c = bootstrap.client(token=root_token)
    bootstrap.ensure_database_engine(c)
    bootstrap.ensure_password_policy(c)
    bootstrap.ensure_clickhouse_plugin(c)

    pg_introspect_password = None
    ch_introspect_password = None

    if config.POSTGRES_SUPERUSER_PASSWORD:
        bootstrap.ensure_postgres_connection(c, config.POSTGRES_SUPERUSER, config.POSTGRES_SUPERUSER_PASSWORD)
        pg_introspect_password = _ensure_postgres_introspect_account(config.POSTGRES_SUPERUSER_PASSWORD)
    else:
        print("POSTGRES_SUPERUSER_PASSWORD not set; skipping Postgres connection (configure it later in Connection Settings)")

    if config.CLICKHOUSE_ADMIN_PASSWORD:
        bootstrap.ensure_clickhouse_connection(c, config.CLICKHOUSE_ADMIN_USER, config.CLICKHOUSE_ADMIN_PASSWORD)
        ch_introspect_password = _ensure_clickhouse_introspect_account(config.CLICKHOUSE_ADMIN_PASSWORD)
    else:
        print("CLICKHOUSE_VAULTADMIN_PASSWORD not set; skipping ClickHouse connection (configure it later in Connection Settings)")

    if pg_introspect_password or ch_introspect_password:
        _persist_introspect_passwords(pg_introspect_password, ch_introspect_password)

    _ensure_grant_token_role(c)
    _ensure_userpass_admin(c, args.admin_user, args.admin_password)

    print(f"Setup complete. Admin user {args.admin_user!r} can now log into the middleware UI.")


if __name__ == "__main__":
    main()
