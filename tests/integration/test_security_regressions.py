"""One regression test per audit finding: each proves the original exploit no longer works.
Numbers refer to S11 in .ai/plan.md."""

import calendar
import json
import re
import subprocess
import time

import pytest
import requests
from conftest import (
    BASE,
    ENV,
    ROOT,
    VAULT,
    Portal,
    can_login,
    ch_connect,
    ch_user_exists,
    dc,
    eventually,
    pg_connect,
    pg_introspect,
    pg_role_exists,
    vault_login_admin,
    vault_login_approle,
)

DBS = ["postgres", "clickhouse"]
DENIED = "permission denied|must be owner"


def exists(db: str, name: str) -> bool:
    return pg_role_exists(name) if db == "postgres" else ch_user_exists(name)


def vault(token: str, method: str, path: str, body=None) -> requests.Response:
    return requests.request(method, f"{VAULT}/v1/{path}", headers={"X-Vault-Token": token}, json=body or {}, timeout=10)


# 1 ---------------------------------------------------------------------------------------------
def test_01_admin_token_cannot_touch_policies_roles_or_connections():
    token = vault_login_admin()
    evil_policy = {"policy": 'path "*" { capabilities = ["create","read","update","delete","list","sudo"] }'}
    assert vault(token, "PUT", "sys/policies/acl/read-grant-evil", evil_policy).status_code == 403
    assert vault(token, "PUT", "sys/policies/acl/db-access-admin", evil_policy).status_code == 403
    role = {
        "db_name": "postgres",
        "creation_statements": ["ALTER ROLE postgres SUPERUSER"],
        "default_ttl": "1m",
    }
    assert vault(token, "PUT", "database/roles/vdba_evil", role).status_code == 403
    cfg = {
        "plugin_name": "postgresql-database-plugin",
        "connection_url": "postgresql://x:y@169.254.169.254/",
        "verify_connection": False,
    }
    assert vault(token, "PUT", "database/config/ssrf", cfg).status_code == 403
    assert (
        vault(token, "PUT", "auth/token/roles/grant-token-issuer", {"allowed_policies_glob": ["*"]}).status_code == 403
    )
    assert vault(token, "POST", "auth/token/create", {"policies": ["root"]}).status_code == 403


# 2 ---------------------------------------------------------------------------------------------
def test_02_service_identity_is_narrow():
    token = vault_login_approle()
    any_policy = {"policy": 'path "*" { capabilities = ["sudo"] }'}
    assert vault(token, "PUT", "sys/policies/acl/vdba-grant-evil", any_policy).status_code == 403
    assert vault(token, "PUT", "sys/policies/acl/vdba-service", any_policy).status_code == 403
    assert vault(token, "POST", "auth/token/create", {"policies": ["vdba-service"]}).status_code == 403
    assert vault(token, "POST", "auth/token/create-orphan", {"policies": ["vdba-service"]}).status_code == 403
    # the one token role it may use only mints the fixed reader policy
    r = vault(token, "POST", "auth/token/create/vdba-grant", {"policies": ["vdba-service"]})
    assert r.status_code in (400, 403), r.text
    r = vault(token, "POST", "auth/token/create/vdba-grant", {"policies": ["root"]})
    assert r.status_code in (400, 403), r.text
    assert vault(token, "PUT", "database/config/postgres", {"connection_url": "postgresql://evil"}).status_code == 403
    assert vault(token, "GET", "database/creds/vdba_anything").status_code == 403
    assert vault(token, "PUT", "sys/leases/revoke-prefix/database/creds/vdba_x").status_code == 403
    assert vault(token, "PUT", "sys/audit/evil", {"type": "file"}).status_code == 403


def test_02b_middleware_has_no_root_secrets():
    cid = dc("ps", "-q", "middleware").stdout.strip()
    mounts = json.loads(
        subprocess.run(
            ["docker", "inspect", cid, "--format", "{{json .Mounts}}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )  # noqa: S603, S607
    dests = {m["Destination"] for m in mounts}
    assert dests == {"/data", "/run/vdba/approle"}, dests
    approle = next(m for m in mounts if m["Destination"] == "/run/vdba/approle")
    assert approle["RW"] is False
    out = dc("exec", "-T", "middleware", "sh", "-c", "env; ls /secrets /vault-secrets 2>&1 || true").stdout
    assert "hvs." not in out and "vault-keys" not in out
    assert not (ROOT / "secrets" / "root-token").exists()
    assert "root_token" not in (ROOT / "secrets" / "vault-keys.json").read_text()


def test_02c_root_token_revoked_and_audit_device_on():
    keys = json.loads((ROOT / "secrets" / "vault-keys.json").read_text())
    assert (ROOT / "secrets" / "vault-keys.json").stat().st_mode & 0o077 == 0
    assert "keys" in keys
    out = dc("exec", "-T", "vault", "sh", "-c", "ls -l /vault/logs/audit.log").stdout
    assert "audit.log" in out


def test_02d_ports_are_loopback_only():
    out = dc("ps", "--format", "json").stdout
    pubs = []
    for line in out.splitlines():
        svc = json.loads(line)
        pubs += [p for p in svc.get("Publishers") or [] if p.get("PublishedPort")]
    assert pubs
    assert all(p["URL"] in ("127.0.0.1", "::1") for p in pubs), pubs


# 3 ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("db", DBS)
def test_03_no_password_is_ever_exposed_or_stored(admin, grants, db):
    r = admin.post(
        "/api/grants",
        json={
            "db_type": db,
            "scope": "tables",
            "tables": ["customers"],
            "commands": ["SELECT"],
            "ttl_seconds": 120,
            "requested_for": "pytest",
        },
    )
    assert r.status_code == 200
    assert "no-store" in r.headers["Cache-Control"]
    g = r.json()
    grants.append(g["grant_id"])
    password = g["password"]
    assert len(password) >= 20
    listing = admin.get("/api/grants")
    assert password not in listing.text and "password" not in listing.text
    assert password not in admin.get("/").text
    assert password not in admin.get(f"/api/grants?x={g['grant_id']}").text
    # nothing in the SQLite file (or its WAL) either
    code = (
        "import sys;p=sys.argv[1].encode();import glob\n"
        "print(any(p in open(f,'rb').read() for f in glob.glob('/data/vdba.sqlite3*')))"
    )
    assert dc("exec", "-T", "middleware", "python", "-c", code, password).stdout.strip() == "False"


# 4 ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("db", DBS)
def test_04_revoke_kills_the_account_within_five_seconds(admin, db):
    g = admin.issue(db, commands=["SELECT", "INSERT", "UPDATE", "DELETE"] if db == "postgres" else ["SELECT", "INSERT"])
    assert can_login(db, g["username"], g["password"])
    assert exists(db, g["username"])
    t0 = time.time()
    assert admin.revoke(g["grant_id"]).status_code == 200
    assert not can_login(db, g["username"], g["password"])
    assert not exists(db, g["username"])
    assert time.time() - t0 < 5
    listing = {x["grant_id"]: x for x in admin.get("/api/grants").json()}
    assert listing[g["grant_id"]]["status"] == "revoked"
    assert admin.revoke(g["grant_id"]).status_code == 200  # idempotent


def test_04b_open_postgres_session_is_terminated_on_revoke(admin):
    g = admin.issue("postgres")
    conn = pg_connect(g["username"], g["password"])
    assert conn.execute("SELECT count(*) FROM customers").fetchone()[0] == 2
    admin.revoke(g["grant_id"])
    with pytest.raises(Exception):  # noqa: B017, PT011 - connection was terminated
        conn.execute("SELECT 1").fetchone()


# 5 ---------------------------------------------------------------------------------------------
def test_05_logout_of_the_issuing_admin_does_not_revoke_grants(grants):
    a = Portal()
    g = a.issue("postgres")
    grants.append(g["grant_id"])
    r = a.post("/logout", allow_redirects=False)
    assert r.status_code == 303
    assert a.get("/api/session").status_code == 401  # session really is gone
    time.sleep(2)
    assert can_login("postgres", g["username"], g["password"])
    c = pg_connect(g["username"], g["password"])
    assert c.execute("SELECT count(*) FROM customers").fetchone()[0] == 2
    b = Portal()
    assert {x["grant_id"]: x["status"] for x in b.get("/api/grants").json()}[g["grant_id"]] == "active"
    assert b.revoke(g["grant_id"]).status_code == 200


# 6 ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("ttl", [0, -5, "abc", 999999999, 5, True, 1.5, None])
def test_06_ttl_is_validated(admin, ttl):
    r = admin.post(
        "/api/grants",
        json={
            "db_type": "postgres",
            "scope": "tables",
            "tables": ["customers"],
            "commands": ["SELECT"],
            "ttl_seconds": ttl,
            "requested_for": "pytest",
        },
    )
    assert r.status_code == 400, (ttl, r.status_code, r.text)


def test_06b_removed_and_unknown_fields_are_rejected(admin):
    base = {
        "db_type": "postgres",
        "scope": "tables",
        "tables": ["customers"],
        "commands": ["SELECT"],
        "ttl_seconds": 60,
        "requested_for": "pytest",
    }
    for extra in ({"allow_create": True}, {"allow_create": "false"}, {"credential_type": "token"}):
        assert admin.post("/api/grants", json=base | extra).status_code == 400
    assert admin.post("/api/grants", json=base | {"commands": ["DROP TABLE"]}).status_code == 400
    assert admin.post("/api/grants", json=base | {"tables": ["nope"]}).status_code == 400
    assert admin.post("/api/grants", json=base | {"tables": ["customers\n"]}).status_code == 400


def test_06c_expires_at_follows_the_vault_lease(admin, grants):
    g = admin.issue("postgres", ttl=90)
    grants.append(g["grant_id"])
    expires = calendar.timegm(time.strptime(g["expires_at"], "%Y-%m-%dT%H:%M:%SZ"))
    created = calendar.timegm(time.strptime(g["created_at"], "%Y-%m-%dT%H:%M:%SZ"))
    assert 88 <= expires - created <= 93
    # independent source: the VALID UNTIL Vault put on the database role from the same lease
    with pg_introspect() as c:
        valid_until = c.execute(
            "SELECT extract(epoch FROM rolvaliduntil) FROM pg_roles WHERE rolname = %s", (g["username"],)
        ).fetchone()[0]
    # Vault passes expiration = lease expiry + a 5 s safety margin to the database
    assert 0 <= float(valid_until) - expires <= 8


# 7 ---------------------------------------------------------------------------------------------
def test_07_csrf(admin):
    body = {
        "db_type": "postgres",
        "scope": "tables",
        "tables": ["customers"],
        "commands": ["SELECT"],
        "ttl_seconds": 60,
        "requested_for": "pytest",
    }
    url = f"{BASE}/api/grants"
    # no token / wrong token
    assert admin.s.post(url, json=body, timeout=10).status_code == 403
    assert admin.s.post(url, json=body, headers={"X-CSRF-Token": "nope"}, timeout=10).status_code == 403
    # right token, wrong / hostile origin
    good = {"X-CSRF-Token": admin.csrf}
    assert admin.s.post(url, json=body, headers=good | {"Origin": "http://evil.example"}, timeout=10).status_code == 403
    assert admin.s.post(url, json=body, headers=good | {"Origin": "null"}, timeout=10).status_code == 403
    assert admin.s.post(url, json=body, headers=good | {"Sec-Fetch-Site": "cross-site"}, timeout=10).status_code == 403
    # revoke, rotate, form post, logout are all protected too
    assert admin.s.post(f"{BASE}/api/grants/vdba_0123456789/revoke", json={}, timeout=10).status_code == 403
    assert admin.s.post(f"{BASE}/settings/postgres/rotate", timeout=10, allow_redirects=False).status_code == 403
    form = {
        "db_type": "postgres",
        "scope": "tables",
        "tables": "customers",
        "commands": "SELECT",
        "ttl_seconds": "60",
        "requested_for": "x",
    }
    assert admin.s.post(f"{BASE}/grants", data=form, timeout=10).status_code == 403
    assert admin.s.post(f"{BASE}/logout", timeout=10, allow_redirects=False).status_code == 403
    assert admin.get("/api/session").status_code == 200  # the failed logout did not log us out
    # login CSRF
    r = requests.post(
        f"{BASE}/login",
        data={"username": ENV["VDBA_ADMIN_USER"], "password": ENV["VDBA_ADMIN_PASSWORD"]},
        timeout=10,
        allow_redirects=False,
    )
    assert r.status_code == 403
    r = requests.post(
        f"{BASE}/login",
        data={"csrf_token": "x", "username": ENV["VDBA_ADMIN_USER"], "password": ENV["VDBA_ADMIN_PASSWORD"]},
        timeout=10,
        allow_redirects=False,
    )
    assert r.status_code == 403
    s = requests.Session()
    page = s.get(f"{BASE}/login", timeout=10).text
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    r = s.post(
        f"{BASE}/login",
        data={"csrf_token": tok, "username": ENV["VDBA_ADMIN_USER"], "password": ENV["VDBA_ADMIN_PASSWORD"]},
        headers={"Origin": "http://evil.example"},
        timeout=10,
        allow_redirects=False,
    )
    assert r.status_code == 403
    # same-origin form post with the token still works
    ok = admin.s.post(f"{BASE}/grants", data=form | {"csrf_token": admin.csrf}, headers={"Origin": BASE}, timeout=60)
    assert ok.status_code == 200 and "shown once" in ok.text
    assert "no-store" in ok.headers["Cache-Control"]


def test_07b_session_and_cookie_hygiene(admin):
    s = requests.Session()
    tok = re.search(r'name="csrf_token" value="([^"]+)"', s.get(f"{BASE}/login", timeout=10).text).group(1)
    r = s.post(
        f"{BASE}/login",
        data={"csrf_token": tok, "username": ENV["VDBA_ADMIN_USER"], "password": ENV["VDBA_ADMIN_PASSWORD"]},
        timeout=10,
        allow_redirects=False,
    )
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie
    sid = s.cookies.get("vdba_sid")
    assert sid and not sid.startswith("hvs.") and "." not in sid  # opaque id, no Vault token / signed blob
    # a second login rotates the id
    s2 = requests.Session()
    tok2 = re.search(r'name="csrf_token" value="([^"]+)"', s2.get(f"{BASE}/login", timeout=10).text).group(1)
    s2.cookies.set("vdba_sid", sid, domain="127.0.0.1", path="/")
    s2.post(
        f"{BASE}/login",
        data={"csrf_token": tok2, "username": ENV["VDBA_ADMIN_USER"], "password": ENV["VDBA_ADMIN_PASSWORD"]},
        timeout=10,
        allow_redirects=False,
    )
    assert s2.cookies.get("vdba_sid", domain="127.0.0.1") != sid
    assert requests.get(f"{BASE}/api/grants", cookies={"vdba_sid": sid}, timeout=10).status_code == 401
    # unauthenticated access
    assert requests.get(f"{BASE}/api/grants", timeout=10).status_code == 401
    assert requests.get(f"{BASE}/", timeout=10, allow_redirects=False).status_code == 303
    # wrong password / non-admin vault user
    s3 = requests.Session()
    tok3 = re.search(r'name="csrf_token" value="([^"]+)"', s3.get(f"{BASE}/login", timeout=10).text).group(1)
    assert (
        s3.post(
            f"{BASE}/login",
            data={"csrf_token": tok3, "username": ENV["VDBA_ADMIN_USER"], "password": "wrong"},
            timeout=10,
        ).status_code
        == 401
    )


def test_07c_oversized_and_chunked_bodies_are_refused():
    r = requests.post(
        f"{BASE}/login",
        data="x" * 70_000,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    assert r.status_code == 413
    r = requests.post(f"{BASE}/login", data=iter([b"a=b"]), timeout=10)  # chunked, no Content-Length
    assert r.status_code == 411


# 8 ---------------------------------------------------------------------------------------------
def test_08_postgres_grant_is_limited_to_listed_tables_and_sequences(admin, grants):
    ro = admin.issue("postgres", tables=["customers"], commands=["SELECT"])
    rw = admin.issue("postgres", tables=["customers"], commands=["SELECT", "INSERT"])
    grants += [ro["grant_id"], rw["grant_id"]]

    c = pg_connect(ro["username"], ro["password"])
    assert c.execute("SELECT count(*) FROM customers").fetchone()[0] == 2
    for sql in (
        "SELECT * FROM orders",
        "SELECT * FROM products",
        "SELECT nextval('orders_id_seq')",
        "SELECT nextval('customers_id_seq')",  # SELECT alone must not allow advancing sequences
        "SELECT last_value FROM orders_id_seq",
        "INSERT INTO customers (name, email) VALUES ('x', 'x@example.com')",
        "DELETE FROM customers",
        "CREATE TABLE scratch (id int)",
        "CREATE SCHEMA evil",
        "DROP TABLE customers",
    ):
        with pytest.raises(Exception, match=DENIED):
            c.execute(sql)

    w = pg_connect(rw["username"], rw["password"])
    w.execute("INSERT INTO customers (name, email) VALUES ('pytest', 'pytest@example.com')")  # uses customers_id_seq
    for sql in (
        "SELECT nextval('orders_id_seq')",
        "SELECT nextval('products_id_seq')",
        "INSERT INTO orders (quantity) VALUES (1)",
        "SELECT * FROM orders",
    ):
        with pytest.raises(Exception, match=DENIED):
            w.execute(sql)
    with pytest.raises(Exception, match=DENIED):
        w.execute("DELETE FROM customers")
    # tidy: remove the row we inserted using a throwaway full-write grant
    d = admin.issue("postgres", tables=["customers"], commands=["SELECT", "DELETE"])
    grants.append(d["grant_id"])
    pg_connect(d["username"], d["password"]).execute("DELETE FROM customers WHERE email = 'pytest@example.com'")


def test_08b_postgres_all_commands_and_whole_database(admin, grants):
    g = admin.issue("postgres", tables=[], commands=["SELECT", "INSERT", "UPDATE", "DELETE"], scope="database")
    grants.append(g["grant_id"])
    c = pg_connect(g["username"], g["password"])
    for t in ("customers", "orders", "products"):
        assert c.execute(f"SELECT count(*) FROM {t}").fetchone()[0] >= 1  # noqa: S608
    c.execute("INSERT INTO products (name, price) VALUES ('Probe', 1.00)")
    c.execute("UPDATE products SET price = 2.00 WHERE name = 'Probe'")
    c.execute("DELETE FROM products WHERE name = 'Probe'")
    with pytest.raises(Exception, match=DENIED):
        c.execute("CREATE TABLE scratch (id int)")
    assert admin.revoke(g["grant_id"]).status_code == 200  # DROP OWNED works for every privilege type


def test_08c_clickhouse_grant_is_limited_and_cannot_drop(admin, grants):
    g = admin.issue("clickhouse", tables=["customers"], commands=["SELECT"])
    grants.append(g["grant_id"])
    c = ch_connect(g["username"], g["password"])
    assert c.query("SELECT count() FROM customers").result_rows[0][0] == 2
    for sql in (
        "SELECT * FROM orders",
        "INSERT INTO customers VALUES (9, 'x', 'x@example.com')",
        "DROP TABLE customers",
        "CREATE TABLE scratch (id UInt8) ENGINE = Memory",
        "CREATE USER evil",
        "GRANT SELECT ON appdb.orders TO " + g["username"],
    ):
        with pytest.raises(Exception, match=r"(?i)not enough privileges|access_denied|code: 497"):
            c.command(sql)


# 9 ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("point", ["after_role_create", "after_creds_read"])
def test_09_interrupted_issue_is_cleaned_by_the_reconciler(hooks, admin, point):
    with pg_introspect() as c:
        before = {r[0] for r in c.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 'vdba\\_%'").fetchall()}
    dc("exec", "-T", "middleware", "sh", "-c", f"echo {point} > /data/fault-point")
    with pytest.raises(requests.exceptions.ConnectionError):
        admin.post(
            "/api/grants",
            json={
                "db_type": "postgres",
                "scope": "tables",
                "tables": ["customers"],
                "commands": ["SELECT"],
                "ttl_seconds": 300,
                "requested_for": "pytest",
            },
        )

    def restarted():
        return requests.get(f"{BASE}/healthz", timeout=2).status_code == 200

    eventually(restarted, timeout=90, interval=1)

    def cleaned():
        rows = admin.get("/api/grants").json()
        stuck = [g for g in rows if g["status"] in ("issuing", "revoking")]
        failed = [g for g in rows if g["status"] == "failed" and g["requested_for"] == "pytest"]
        return not stuck and failed

    eventually(cleaned, timeout=90, interval=2)
    with pg_introspect() as c:
        after = {r[0] for r in c.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 'vdba\\_%'").fetchall()}
    assert after <= before, f"leftover accounts: {after - before}"


# 10 --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("db", DBS)
def test_10_expiry_works_without_the_web_app(admin, db):
    g = admin.issue(db, ttl=20)
    assert can_login(db, g["username"], g["password"])
    dc("stop", "middleware")
    try:
        time.sleep(32)
        assert not can_login(db, g["username"], g["password"])
        assert eventually(lambda: not exists(db, g["username"]), timeout=20)
    finally:
        dc("up", "-d", "--wait", "middleware", timeout=180)
    eventually(lambda: requests.get(f"{BASE}/healthz", timeout=2).ok, timeout=60)
    again = Portal()  # sessions survive a restart (SQLite), but be independent of that
    eventually(
        lambda: (
            {x["grant_id"]: x["status"] for x in again.get("/api/grants").json()}[g["grant_id"]]
            in ("expired", "revoked")
        ),
        timeout=60,
        interval=2,
    )


# 11 --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("db", DBS)
def test_11_manager_password_comes_from_env_and_rotation_works(admin, grants, db):
    if db == "clickhouse":
        mgr = ENV["CLICKHOUSE_MANAGER_PASSWORD"]
        c = ch_connect("vault_manager", mgr)
        assert c.query("SELECT currentUser()").result_rows[0][0] == "vault_manager"
        grants_text = "\n".join(r[0] for r in ch_connect("vault_manager", mgr).query("SHOW GRANTS").result_rows)
        assert "ACCESS MANAGEMENT" not in grants_text and "ALL ON *.*" not in grants_text
    else:
        mgr = ENV["PG_MANAGER_PASSWORD"]
        c = pg_connect("vault_manager", mgr)
        row = c.execute(
            "SELECT rolsuper, rolcreatedb, rolreplication, rolbypassrls, rolcreaterole "
            "FROM pg_roles WHERE rolname = 'vault_manager'"
        ).fetchone()
        assert row == (False, False, False, False, True)
        with pytest.raises(Exception, match=DENIED + "|must be superuser"):
            c.execute("CREATE ROLE sneaky SUPERUSER")
        with pytest.raises(Exception, match=DENIED):
            c.execute("CREATE TABLE t (id int)")
    r = admin.post(f"/settings/{db}/rotate")
    assert r.status_code == 200, r.text
    assert not can_login_manager(db, mgr)  # the .env value is dead: only Vault knows the new one
    g = admin.issue(db, ttl=60)  # issuing still works through Vault's rotated credential
    grants.append(g["grant_id"])
    assert can_login(db, g["username"], g["password"])
    assert admin.revoke(g["grant_id"]).status_code == 200


def can_login_manager(db: str, password: str) -> bool:
    return can_login(db, "vault_manager", password)


# 12 --------------------------------------------------------------------------------------------
def test_12_stack_refuses_to_start_with_changeme(tmp_path):
    env_file = tmp_path / "bad.env"
    env_file.write_text((ROOT / ".env.example").read_text())  # every secret is still "changeme"
    base = ["docker", "compose", "-p", "vdbapf", "--env-file", str(env_file)]
    try:
        r = subprocess.run(
            [*base, "up", "-d", "--no-build", "postgres", "clickhouse", "vault", "middleware"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
        )  # noqa: S603
        assert r.returncode != 0
        assert "preflight" in (r.stdout + r.stderr)
        ps = subprocess.run(
            [*base, "ps", "--status", "running", "-q"], cwd=ROOT, capture_output=True, text=True, timeout=30
        )  # noqa: S603
        assert ps.stdout.strip() == "", "a service started despite placeholder secrets"
        logs = subprocess.run([*base, "logs", "preflight"], cwd=ROOT, capture_output=True, text=True, timeout=30)  # noqa: S603
        assert "changeme" in logs.stdout + logs.stderr
        # and the same for an empty value
        env_file.write_text("POSTGRES_ADMIN_PASSWORD=\n")
        r = subprocess.run(
            [*base, "up", "-d", "--no-build", "postgres"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
        )  # noqa: S603
        assert r.returncode != 0
    finally:
        subprocess.run([*base, "down", "-v", "--remove-orphans"], cwd=ROOT, capture_output=True, timeout=120)  # noqa: S603
