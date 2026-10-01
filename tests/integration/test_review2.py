"""Regression tests for the second review round (Sol review 2 / Opus final audit)."""

import re
import socket
import subprocess
import threading
import time
import uuid

import hvac
import pytest
import requests
from conftest import (
    BASE,
    ENV,
    ROOT,
    VAULT,
    Portal,
    all_tokens,
    ch_connect,
    dc,
    eventually,
    pg_connect,
    pg_role_exists,
)

VALID = {
    "db_type": "postgres",
    "scope": "tables",
    "tables": ["customers"],
    "commands": ["SELECT"],
    "ttl_seconds": 120,
    "requested_for": "pytest",
}


def vault_client_for_root(token: str) -> hvac.Client:
    return hvac.Client(url=VAULT, token=token)


def cleanup_as_manager(account: str) -> None:
    """Call the cleanup function exactly as Vault would: as vault_manager (privileges it granted can only be
    revoked by it, so running it as the superuser would leave them behind)."""
    su = pg_connect("postgres", ENV["POSTGRES_ADMIN_PASSWORD"])
    su.execute("SET ROLE vault_manager")
    su.execute("SELECT vdba.cleanup_role(%s)", (account,))
    su.close()


def sql_in_middleware(code: str) -> str:
    return dc("exec", "-T", "middleware", "python", "-c", code).stdout


# O2 / N4 ----------------------------------------------------------------------------------------
def test_service_relogin_revokes_the_previous_token(root_token, tmp_path, monkeypatch):
    from app import config, vault_client

    role_id = dc("exec", "-T", "middleware", "cat", "/run/vdba/approle/role_id").stdout.strip()
    secret_id = dc("exec", "-T", "middleware", "cat", "/run/vdba/approle/secret_id").stdout.strip()
    (tmp_path / "role_id").write_text(role_id)
    (tmp_path / "secret_id").write_text(secret_id)
    monkeypatch.setattr(config, "APPROLE_DIR", str(tmp_path))
    monkeypatch.setattr(config, "VAULT_ADDR", VAULT)

    def service_tokens():
        return [t for t in all_tokens(root_token) if t.get("path") == "auth/approle/login"]

    before = len(service_tokens())
    svc = vault_client.Service()
    svc.client()
    for _ in range(5):
        svc._login()  # noqa: SLF001
    after = service_tokens()
    assert len(after) == before + 1, f"{len(after) - before} new service tokens alive; old ones were not revoked"
    svc._client.auth.token.revoke_self()  # noqa: SLF001


# N1 ---------------------------------------------------------------------------------------------
def test_setup_refuses_a_postgres_manager_with_dangerous_memberships(root_token):
    from app import setup

    root = vault_client_for_root(root_token)
    su = pg_connect("postgres", ENV["POSTGRES_ADMIN_PASSWORD"])
    setup.validate_connection(root, "postgres")  # baseline passes
    for grant, undo in (
        ("GRANT pg_execute_server_program TO vault_manager", "REVOKE pg_execute_server_program FROM vault_manager"),
        ("GRANT pg_read_server_files TO vault_manager", "REVOKE pg_read_server_files FROM vault_manager"),
        ("CREATE ROLE evil_group; GRANT evil_group TO vault_manager", "DROP OWNED BY evil_group; DROP ROLE evil_group"),
    ):
        for stmt in grant.split("; "):
            su.execute(stmt)
        try:
            with pytest.raises(SystemExit, match="probe"):
                setup.validate_connection(root, "postgres")
        finally:
            if "evil_group" in undo:
                su.execute("REVOKE evil_group FROM vault_manager")
            for stmt in undo.split("; "):
                if not stmt.startswith("REVOKE evil_group"):
                    su.execute(stmt)
    setup.validate_connection(root, "postgres")  # and healthy again


def test_setup_refuses_a_clickhouse_manager_with_extra_grants_or_roles(root_token):
    from app import setup

    root = vault_client_for_root(root_token)
    ad = ch_connect("bootstrap_admin", ENV["CLICKHOUSE_ADMIN_PASSWORD"])
    setup.validate_connection(root, "clickhouse")
    ad.command("GRANT ALTER ROLE ON *.* TO vault_manager")  # not on ACCESS MANAGEMENT's old deny-list, still unsafe
    try:
        with pytest.raises(SystemExit, match="probe"):
            setup.validate_connection(root, "clickhouse")
    finally:
        ad.command("REVOKE ALTER ROLE ON *.* FROM vault_manager")
    ad.command("CREATE ROLE IF NOT EXISTS r_evil")
    ad.command("GRANT r_evil TO vault_manager")
    try:
        with pytest.raises(SystemExit, match="probe"):
            setup.validate_connection(root, "clickhouse")
    finally:
        ad.command("REVOKE r_evil FROM vault_manager")
        ad.command("DROP ROLE r_evil")
    setup.validate_connection(root, "clickhouse")


# N2 ---------------------------------------------------------------------------------------------
def test_setup_refuses_a_connector_with_a_foreign_username_template(root_token):
    from app import setup

    root = vault_client_for_root(root_token)
    root.write(
        "database/config/tpl-test",
        plugin_name="postgresql-database-plugin",
        allowed_roles="vdba_*",
        connection_url="postgresql://{{username}}:{{password}}@postgres:5432/appdb?sslmode=disable",
        username="vault_manager",
        password="not-the-real-password",
        verify_connection=False,
        username_template="{{ random 8 }}",
    )
    try:
        with pytest.raises(SystemExit, match="username_template"):
            setup.validate_connection(root, "tpl-test", kind="postgres")
    finally:
        root.delete("database/config/tpl-test")


# Sol 3 ------------------------------------------------------------------------------------------
def test_setup_without_root_still_rechecks_connectors_and_warns():
    r = dc("--profile", "setup", "run", "--rm", "setup")
    out = r.stdout + r.stderr
    assert "already provisioned" in out
    assert "connector 'postgres' re-checked" in out and "connector 'clickhouse' re-checked" in out
    assert "probe was NOT re-run" in out  # loud warning: no root, so the privilege probe could not run


# Sol 8 ------------------------------------------------------------------------------------------
def test_cleanup_function_is_idempotent_and_guarded():
    cleanup_as_manager("vdba_0000000000_aaaaaa")  # role does not exist: no error
    cleanup_as_manager("vdba_0000000000_aaaaaa")
    with pytest.raises(Exception, match="refusing"):
        cleanup_as_manager("postgres")  # the function only ever touches our accounts
    assert pg_role_exists("postgres")


def test_revoke_after_the_role_was_already_dropped_is_clean(admin):
    g = admin.issue("postgres", ttl=300)
    conn = pg_connect(g["username"], g["password"])
    cleanup_as_manager(g["username"])  # DB side done, Vault lease still outstanding
    assert not pg_role_exists(g["username"])
    with pytest.raises(Exception):  # noqa: B017, PT011
        conn.execute("SELECT 1")
    r = admin.revoke(g["grant_id"])  # Vault now runs the revocation on a missing role: must not error
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    assert admin.revoke(g["grant_id"]).status_code == 200  # twice


def test_vault_expiry_after_the_role_was_already_dropped_is_clean(admin, root_token):
    g = admin.issue("postgres", ttl=15)
    lease = sql_in_middleware(
        f"import sqlite3;print(sqlite3.connect('/data/vdba.sqlite3').execute(\"select lease_id from grants where id='{g['grant_id']}'\").fetchone()[0])"
    ).strip()
    cleanup_as_manager(g["username"])
    dc("stop", "middleware")  # nothing but Vault itself may clean up the lease
    try:
        time.sleep(30)
        r = requests.put(
            f"{VAULT}/v1/sys/leases/lookup", headers={"X-Vault-Token": root_token}, json={"lease_id": lease}, timeout=10
        )
        assert r.status_code in (400, 404), f"lease still present after expiry: {r.text}"
    finally:
        dc("start", "middleware", timeout=180)
    eventually(lambda: requests.get(f"{BASE}/healthz", timeout=2).ok, timeout=60)


# Sol 16 (ClickHouse) ------------------------------------------------------------------------------
def test_clickhouse_running_query_stops_after_revoke(admin):
    ad = ch_connect("bootstrap_admin", ENV["CLICKHOUSE_ADMIN_PASSWORD"])
    ad.command("CREATE TABLE IF NOT EXISTS appdb.bigtest (n UInt64) ENGINE = MergeTree ORDER BY n")
    ad.command("INSERT INTO appdb.bigtest SELECT number FROM numbers(3000000)")
    try:
        g = admin.issue("clickhouse", tables=["bigtest"], commands=["SELECT"], ttl=300)
        user = g["username"]
        c = ch_connect(user, g["password"])
        result = {}

        def run():
            try:
                c.query(
                    "SELECT count() FROM bigtest a CROSS JOIN bigtest b WHERE a.n < 30000 AND (a.n + b.n) % 7 = 1",
                    settings={"max_execution_time": 120},
                )
                result["ended"] = "completed"
            except Exception as exc:  # noqa: BLE001
                result["ended"] = type(exc).__name__

        def running():
            return (
                ad.query("SELECT count() FROM system.processes WHERE user = %(u)s", parameters={"u": user}).result_rows[
                    0
                ][0]
                > 0
            )

        t = threading.Thread(target=run)
        t.start()
        eventually(running, timeout=20, interval=0.5)
        t0 = time.time()
        assert admin.revoke(g["grant_id"]).status_code == 200
        eventually(lambda: not running(), timeout=10, interval=0.5)
        t.join(timeout=20)
        assert result.get("ended") not in (None, "completed"), result
        assert time.time() - t0 < 25
    finally:
        ad.command("DROP TABLE IF EXISTS appdb.bigtest")


# real backend failures never reach the client ----------------------------------------------------
LEAKS = [
    "psycopg",
    "traceback",
    "errno",
    "5432",
    "introspect",
    "refused",
    "timed out",
    "operationalerror",
    "hvac",
    "urllib3",
    "requests.",
]


@pytest.mark.parametrize("service", ["postgres", "vault"])
def test_real_backend_failures_do_not_leak_details(admin, service):
    dc("pause", service)
    try:
        r = admin.post("/api/grants", json=VALID)
        assert r.status_code in (502, 503), (r.status_code, r.text)
        text = r.text.lower()
        assert not [needle for needle in LEAKS if needle in text], r.text
        page = admin.get("/")  # the UI page degrades without leaking either
        assert not [needle for needle in LEAKS if needle in page.text.lower()]
    finally:
        dc("unpause", service)
    eventually(lambda: admin.get("/api/grants").status_code == 200, timeout=60, interval=1)


# 413 on JSON endpoints ---------------------------------------------------------------------------
def test_oversized_chunked_json_body_is_413_not_400(admin):
    cookie = admin.s.cookies.get("vdba_sid")
    big = b"x" * 100_000
    req = (
        b"POST /api/grants HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\nOrigin: " + BASE.encode() + b"\r\nX-CSRF-Token: " + admin.csrf.encode()
        + b"\r\nCookie: vdba_sid=" + cookie.encode() + b"\r\n\r\n"
    )  # fmt: skip
    with socket.create_connection(("127.0.0.1", 8000), timeout=10) as s:
        s.sendall(req)
        s.sendall(b"%x\r\n" % len(big) + big + b"\r\n0\r\n\r\n")
        resp = s.recv(4096)
    assert resp.startswith(b"HTTP/1.1 413"), resp[:60]


_ = (re, subprocess, uuid, Portal, ROOT)
