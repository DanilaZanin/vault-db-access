"""Full-stack integration tests. Run against the live docker-compose stack:

    docker run --rm --network vault-db-access_vault-db-access \
        -v $(pwd):/work -w /work python:3.12-slim \
        bash -c "pip install -q -r middleware/requirements.txt pytest requests && pytest tests/test_integration.py -v"
"""

import os
import time

import clickhouse_connect
import psycopg2
import pytest
import requests

MIDDLEWARE_URL = os.environ.get("MIDDLEWARE_URL", "http://vdba-middleware:8000")
ADMIN_USER = os.environ.get("VAULT_ADMIN_USER", "ivanov")
ADMIN_PASSWORD = os.environ["VAULT_ADMIN_PASSWORD"]

SESSION = requests.Session()
_login_resp = SESSION.post(
    f"{MIDDLEWARE_URL}/login", data={"username": ADMIN_USER, "password": ADMIN_PASSWORD}, timeout=30
)
assert _login_resp.status_code == 200, f"login failed: {_login_resp.status_code} {_login_resp.text}"

POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "vdba-postgres")
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))
POSTGRES_DB = "appdb"

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "vdba-clickhouse")
CLICKHOUSE_HTTP_PORT = int(os.environ.get("CLICKHOUSE_HTTP_PORT", "8123"))
CLICKHOUSE_DB = "appdb"

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vdba-vault:8200")


def create_grant(**payload) -> dict:
    payload.setdefault("requested_for", "pytest")
    resp = SESSION.post(f"{MIDDLEWARE_URL}/api/grants", json=payload, timeout=30)
    assert resp.status_code == 200, resp.text
    return resp.json()


def revoke_grant(role_name: str) -> None:
    resp = SESSION.post(f"{MIDDLEWARE_URL}/grants/{role_name}/revoke", timeout=30)
    assert resp.status_code == 200, resp.text


def pg_connect(username: str, password: str):
    return psycopg2.connect(
        host=POSTGRES_HOST, port=POSTGRES_PORT, user=username, password=password, dbname=POSTGRES_DB
    )


def ch_connect(username: str, password: str):
    return clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_HTTP_PORT, username=username, password=password, database=CLICKHOUSE_DB
    )


@pytest.fixture
def cleanup():
    role_names = []
    yield role_names
    for role_name in role_names:
        try:
            revoke_grant(role_name)
        except AssertionError:
            pass


def test_postgres_table_scoped_select_only(cleanup):
    grant = create_grant(
        db_type="postgres",
        scope="tables",
        tables=["customers"],
        commands=["SELECT"],
        allow_create=False,
        credential_type="password",
        ttl_seconds=120,
    )
    cleanup.append(grant["role_name"])

    conn = pg_connect(grant["username"], grant["password"])
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM customers")
            assert len(cur.fetchall()) == 2

        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM orders")
        conn.rollback()

        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("INSERT INTO customers (name, email) VALUES ('x', 'x@example.com')")
        conn.rollback()
    finally:
        conn.close()


def test_postgres_whole_db_select_insert(cleanup):
    grant = create_grant(
        db_type="postgres",
        scope="database",
        tables=[],
        commands=["SELECT", "INSERT"],
        allow_create=False,
        credential_type="password",
        ttl_seconds=120,
    )
    cleanup.append(grant["role_name"])

    conn = pg_connect(grant["username"], grant["password"])
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM orders")
            assert cur.fetchall()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO products (name, price) VALUES ('Thingamajig', 5.00)")
        conn.commit()

        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("DELETE FROM products WHERE name = 'Thingamajig'")
        conn.rollback()
    finally:
        conn.close()


def test_postgres_user_can_create_and_drop_own_table(cleanup):
    grant = create_grant(
        db_type="postgres",
        scope="database",
        tables=[],
        commands=["SELECT"],
        allow_create=True,
        credential_type="password",
        ttl_seconds=120,
    )
    cleanup.append(grant["role_name"])

    conn = pg_connect(grant["username"], grant["password"])
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE scratch (id INT)")
            cur.execute("INSERT INTO scratch VALUES (1)")
            cur.execute("DROP TABLE scratch")
        conn.commit()
    finally:
        conn.close()


def test_postgres_token_mode_end_to_end(cleanup):
    grant = create_grant(
        db_type="postgres",
        scope="tables",
        tables=["products"],
        commands=["SELECT"],
        allow_create=False,
        credential_type="token",
        ttl_seconds=120,
    )
    cleanup.append(grant["role_name"])
    assert grant["vault_token"]

    resp = requests.get(
        f"{VAULT_ADDR}/v1/database/creds/{grant['role_name']}",
        headers={"X-Vault-Token": grant["vault_token"]},
        timeout=30,
    )
    assert resp.status_code == 200, resp.text
    creds = resp.json()["data"]

    conn = pg_connect(creds["username"], creds["password"])
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM products")
            assert cur.fetchall()
    finally:
        conn.close()

    # the scoped token must not be able to read anything else in vault
    resp = requests.get(
        f"{VAULT_ADDR}/v1/sys/mounts", headers={"X-Vault-Token": grant["vault_token"]}, timeout=30
    )
    assert resp.status_code in (403, 400)


def test_postgres_ttl_expiry_revokes_access(cleanup):
    grant = create_grant(
        db_type="postgres",
        scope="tables",
        tables=["customers"],
        commands=["SELECT"],
        allow_create=False,
        credential_type="password",
        ttl_seconds=5,
    )
    cleanup.append(grant["role_name"])

    conn = pg_connect(grant["username"], grant["password"])
    conn.close()

    time.sleep(25)

    with pytest.raises(psycopg2.OperationalError):
        pg_connect(grant["username"], grant["password"])


def test_clickhouse_table_scoped_select_only(cleanup):
    grant = create_grant(
        db_type="clickhouse",
        scope="tables",
        tables=["customers"],
        commands=["SELECT"],
        allow_create=False,
        credential_type="password",
        ttl_seconds=120,
    )
    cleanup.append(grant["role_name"])

    client = ch_connect(grant["username"], grant["password"])
    result = client.query("SELECT * FROM customers")
    assert result.result_rows

    with pytest.raises(Exception):
        client.query("SELECT * FROM orders")


def test_clickhouse_whole_db_select_insert(cleanup):
    grant = create_grant(
        db_type="clickhouse",
        scope="database",
        tables=[],
        commands=["SELECT", "INSERT"],
        allow_create=False,
        credential_type="password",
        ttl_seconds=120,
    )
    cleanup.append(grant["role_name"])

    client = ch_connect(grant["username"], grant["password"])
    result = client.query("SELECT * FROM orders")
    assert result.result_rows
    client.command("INSERT INTO products VALUES (99, 'Extra', 1.23)")
