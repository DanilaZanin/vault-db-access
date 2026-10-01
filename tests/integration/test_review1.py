"""Regression tests for the phase-1 review findings (Sol review 1 / Opus re-audit). Each test fails on the
code as it was at commit dc3665d."""

import json
import socket
import threading
import time
import uuid

import pytest
import requests
from conftest import (
    BASE,
    ENV,
    VAULT,
    Portal,
    ch_introspect,
    dc,
    eventually,
    pg_connect,
    pg_role_exists,
)

STRONG = "Zx9-" + uuid.uuid4().hex


def vault(token: str, method: str, path: str, body=None) -> requests.Response:
    return requests.request(method, f"{VAULT}/v1/{path}", headers={"X-Vault-Token": token}, json=body or {}, timeout=15)


def sql_in_middleware(code: str) -> str:
    return dc("exec", "-T", "middleware", "python", "-c", code).stdout


# 1 ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("how", ["user_deleted", "policy_removed"])
def test_session_ends_when_admin_rights_are_removed(root_token, stack, how):
    recheck = stack["recheck"]
    if recheck > 60:
        pytest.skip("stack not started with a short VDBA_SESSION_RECHECK_SECONDS (make check does)")
    name = f"tmpadmin-{uuid.uuid4().hex[:8]}"
    path = f"auth/userpass/users/{name}"
    assert (
        vault(root_token, "PUT", path, {"password": STRONG, "token_policies": ["db-access-admin"]}).status_code == 204
    )
    try:
        p = Portal(name, STRONG)
        assert p.get("/api/session").status_code == 200
        if how == "user_deleted":
            assert vault(root_token, "DELETE", path).status_code == 204
        else:
            assert (
                vault(root_token, "PUT", path, {"password": STRONG, "token_policies": ["default"]}).status_code == 204
            )
        time.sleep(recheck + 2)  # the session's Vault token still lists db-access-admin; only the user changed
        assert p.get("/api/session").status_code == 401
        assert p.post("/api/grants", json={}).status_code == 401
    finally:
        vault(root_token, "DELETE", path)


# 2 ---------------------------------------------------------------------------------------------
def _raw(request: bytes, chunks: list[bytes] | None = None) -> bytes:
    with socket.create_connection(("127.0.0.1", 8000), timeout=10) as s:
        s.sendall(request)
        for c in chunks or []:
            s.sendall(c)
        s.settimeout(10)
        return s.recv(4096)


def test_body_limit_cannot_be_bypassed_with_chunked_encoding():
    head = (
        b"POST /login HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nOrigin: " + BASE.encode() + b"\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
    )
    # chunked only, 100 KB: refused by the byte counter, not by any header
    big = b"x" * 100_000
    resp = _raw(
        head + b"Transfer-Encoding: chunked\r\n\r\n",
        [b"%x\r\n" % len(big), big, b"\r\n0\r\n\r\n"],
    )
    assert resp.startswith(b"HTTP/1.1 413"), resp[:80]
    # chunked + a tiny Content-Length (the smuggling shape): refused outright
    resp = _raw(head + b"Transfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n", [b"5\r\nhello\r\n0\r\n\r\n"])
    assert resp.split(b"\r\n")[0].split()[1] in (b"400", b"413"), resp[:80]
    # plain oversized Content-Length still 413
    r = requests.post(f"{BASE}/login", data="x" * 70_000, headers={"Origin": BASE}, timeout=10)
    assert r.status_code == 413
    # and a normal small request is unaffected
    assert requests.get(f"{BASE}/login", timeout=10).status_code == 200


# 10 (origin) ------------------------------------------------------------------------------------
def test_state_changing_request_without_origin_or_fetch_metadata_is_rejected(admin):
    body = {
        "db_type": "postgres",
        "scope": "tables",
        "tables": ["customers"],
        "commands": ["SELECT"],
        "ttl_seconds": 60,
    }
    h = {"X-CSRF-Token": admin.csrf}
    url = f"{BASE}/api/grants"
    for extra in ({}, {"Origin": ""}):
        r = admin.s.post(url, json=body | {"requested_for": "x"}, headers=h | extra, timeout=10)
        assert r.status_code == 403, extra
    r = admin.s.post(url, json=body | {"requested_for": "x"}, headers=h | {"Sec-Fetch-Site": "same-origin"}, timeout=60)
    assert r.status_code == 200  # a browser (Sec-Fetch-Site) is fine
    admin.revoke(r.json()["grant_id"])


# 3 ---------------------------------------------------------------------------------------------
def test_setup_refuses_a_superuser_or_wrong_account_connector(root_token):
    import hvac
    from app import setup

    root = hvac.Client(url=VAULT, token=root_token)
    # (a) a pre-existing connector that uses the postgres superuser
    root.write(
        "database/config/su-test",
        plugin_name="postgresql-database-plugin",
        allowed_roles="vdba_*",
        connection_url="postgresql://{{username}}:{{password}}@postgres:5432/appdb?sslmode=disable",
        username="postgres",
        password=ENV["POSTGRES_ADMIN_PASSWORD"],
    )
    try:
        with pytest.raises(SystemExit, match="not 'vault_manager'"):
            setup.validate_connection(root, "su-test")
    finally:
        root.delete("database/config/su-test")
    # (b) the right account name but with superuser rights (probe runs AS that account, inside the DB)
    setup.validate_connection(root, "postgres")  # healthy now
    su = pg_connect("postgres", ENV["POSTGRES_ADMIN_PASSWORD"])
    su.execute("ALTER ROLE vault_manager SUPERUSER")
    try:
        with pytest.raises(SystemExit, match="least-privilege probe"):
            setup.validate_connection(root, "postgres")
    finally:
        su.execute("ALTER ROLE vault_manager NOSUPERUSER")
    setup.validate_connection(root, "postgres")
    setup.validate_connection(root, "clickhouse")
    role = vault(root_token, "GET", "auth/token/roles/vdba-grant").json()["data"]
    assert role["orphan"] is True and role["allowed_policies"] == ["vdba-creds-reader"]
    assert role["token_explicit_max_ttl"] > 0  # token role TTL is bounded


# 4 ---------------------------------------------------------------------------------------------
def test_postgres_termination_is_confirmed_by_pg_stat_activity(admin):
    g = admin.issue("postgres", ttl=300)
    user = g["username"]
    conn = pg_connect(user, g["password"])
    started = threading.Event()
    result = {}

    def long_query():
        started.set()
        try:
            conn.execute("SELECT pg_sleep(60)")
            result["ended"] = "completed"
        except Exception as exc:  # noqa: BLE001
            result["ended"] = type(exc).__name__

    t = threading.Thread(target=long_query)
    t.start()
    started.wait()
    superuser = pg_connect("postgres", ENV["POSTGRES_ADMIN_PASSWORD"])
    eventually(
        lambda: superuser.execute("SELECT count(*) FROM pg_stat_activity WHERE usename = %s", (user,)).fetchone()[0] > 0
    )
    assert admin.revoke(g["grant_id"]).status_code == 200
    t.join(timeout=15)
    assert result.get("ended") not in (None, "completed"), result  # the running query was killed, not waited out
    assert superuser.execute("SELECT count(*) FROM pg_stat_activity WHERE usename = %s", (user,)).fetchone()[0] == 0
    assert not pg_role_exists(user)


# 5 (unit-level race lives in tests/unit/test_reconcile.py) ----------------------------------------


# 6 ---------------------------------------------------------------------------------------------
def test_old_revoking_row_is_retried_even_behind_a_thousand_newer_rows(admin, hooks):
    g = admin.issue("postgres", ttl=3600)
    user = g["username"]
    assert pg_role_exists(user)
    sql_in_middleware(
        "import sqlite3,time,json\n"
        "c=sqlite3.connect('/data/vdba.sqlite3', timeout=30)\n"
        f"c.execute(\"UPDATE grants SET status='revoking', created_at=?, updated_at=? WHERE id='{g['grant_id']}'\","
        "(time.time()-864000,)*2)\n"
        "now=time.time()\n"
        "rows=[('vdba_%010x'%(0xf000000000+i),'postgres','tables','[]','[]','x','bulk',60,'revoked',now+i/1000,None,None,None,None,None,now) for i in range(1100)]\n"
        "c.executemany('INSERT INTO grants VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',rows)\n"
        "c.commit()\n"
    )
    eventually(lambda: not pg_role_exists(user), timeout=60, interval=2)
    row = {x["grant_id"]: x for x in admin.get("/api/grants").json()}
    assert row.get(g["grant_id"], {}).get("status", "revoked") == "revoked" or g["grant_id"] not in row
    sql_in_middleware(
        "import sqlite3\nc=sqlite3.connect('/data/vdba.sqlite3');c.execute(\"DELETE FROM grants WHERE issued_by='bulk'\");c.commit()"
    )


# 7 ---------------------------------------------------------------------------------------------
def test_partial_clickhouse_account_is_removed_when_a_later_grant_fails(admin, hooks):
    dc("exec", "-T", "middleware", "sh", "-c", "echo bad_statement > /data/fault-point")
    before = {x["grant_id"] for x in admin.get("/api/grants").json()}
    r = admin.post("/api/grants", json={
        "db_type": "clickhouse", "scope": "tables", "tables": ["customers"], "commands": ["SELECT"],
        "ttl_seconds": 300, "requested_for": "partial",
    })  # fmt: skip
    assert r.status_code == 502
    assert "Syntax error" not in r.text and "Code:" not in r.text  # backend error text never reaches the client
    rows = [x for x in admin.get("/api/grants").json() if x["grant_id"] not in before]
    assert len(rows) == 1
    gid = rows[0]["grant_id"]
    # proof the account really was created before the failure: the server log has the backend error
    logs = dc("logs", "middleware", "--tail", "400").stdout + dc("logs", "middleware", "--tail", "400").stderr
    assert "Syntax error" in logs  # the backend rejected the statement that followed CREATE USER
    eventually(
        lambda: (
            admin.get("/api/grants").json()
            and {x["grant_id"]: x["status"] for x in admin.get("/api/grants").json()}[gid] == "failed"
        ),
        timeout=60,
    )
    leftovers = (
        ch_introspect()
        .query("SELECT name FROM system.users WHERE startsWith(name, %(p)s)", parameters={"p": gid + "_"})
        .result_rows
    )
    assert leftovers == []


# 8 / 10 ------------------------------------------------------------------------------------------
def test_lost_token_create_response_does_not_leave_a_live_token(root_token, hooks, admin):
    before = {x["grant_id"] for x in admin.get("/api/grants").json()}
    dc("exec", "-T", "middleware", "sh", "-c", "echo after_token_create > /data/fault-point")
    with pytest.raises(requests.exceptions.ConnectionError):
        admin.post("/api/grants", json={
            "db_type": "postgres", "scope": "tables", "tables": ["customers"], "commands": ["SELECT"],
            "ttl_seconds": 600, "requested_for": "lost-token",
        })  # fmt: skip
    eventually(lambda: requests.get(f"{BASE}/healthz", timeout=2).ok, timeout=90, interval=1)

    def failed():
        rows = [x for x in admin.get("/api/grants").json() if x["grant_id"] not in before]
        return rows and rows[0]["status"] == "failed" and rows[0]["grant_id"]

    gid = eventually(failed, timeout=90, interval=2)
    # independent check with root: no live token carries this grant's name
    accessors = vault(root_token, "LIST", "auth/token/accessors").json()["data"]["keys"]
    names = []
    for a in accessors:
        r = vault(root_token, "POST", "auth/token/lookup-accessor", {"accessor": a})
        if r.status_code == 200:
            names.append(r.json()["data"].get("display_name"))
    assert not any(gid in (n or "") for n in names), "the orphaned grant token is still alive"


# 9 ---------------------------------------------------------------------------------------------
def test_sqlite_files_and_session_ids_are_private(admin):
    out = dc("exec", "-T", "middleware", "sh", "-c", "stat -c '%a %n' /data /data/vdba.sqlite3*").stdout
    modes = dict(line.split(" ", 1)[::-1] for line in out.strip().splitlines())
    assert modes["/data"] == "700", out
    for path, mode in modes.items():
        if path.startswith("/data/vdba.sqlite3"):
            assert mode == "600", out
    sid = admin.s.cookies.get("vdba_sid")
    rows = sql_in_middleware(
        "import sqlite3\nprint([r[0] for r in sqlite3.connect('/data/vdba.sqlite3').execute('select sid from sessions')])"
    )
    assert sid not in rows  # only a hash of the id is stored
    assert all(len(x) == 64 for x in json.loads(rows.replace("'", '"')))


# 11 --------------------------------------------------------------------------------------------
def test_one_database_down_does_not_hide_the_other_catalog(admin):
    dc("stop", "clickhouse")
    try:
        r = admin.get("/")
        assert r.status_code == 200
        assert 'name="tables" value="customers"' in r.text  # Postgres tables still listed
        assert "Could not list clickhouse tables" in r.text
    finally:
        dc("start", "clickhouse")
    eventually(lambda: "healthy" in dc("ps", "clickhouse").stdout, timeout=90, interval=2)


def test_errors_never_leak_backend_text(admin):
    r = admin.post(
        "/api/grants",
        json={
            "db_type": "postgres",
            "scope": "tables",
            "tables": ["nope"],
            "commands": ["SELECT"],
            "ttl_seconds": 60,
            "requested_for": "x",
        },
    )
    assert r.status_code == 400
    assert "Traceback" not in r.text and "vault" not in r.text.lower() and "Code:" not in r.text
