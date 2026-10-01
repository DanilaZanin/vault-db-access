"""Integration tests run against the REAL compose stack (`make up`, ideally with
VDBA_TEST_HOOKS=1 VDBA_RECONCILE_INTERVAL=5 as `make check` does). If the stack is not running
every test here is skipped, so `make test` stays green on a bare checkout."""

import os
import re
import subprocess
import time
from pathlib import Path

import clickhouse_connect
import psycopg
import pytest
import requests

ROOT = Path(__file__).resolve().parents[2]
BASE = "http://127.0.0.1:8000"
VAULT = "http://127.0.0.1:8200"
PG = {"host": "127.0.0.1", "port": 5432, "dbname": "appdb", "connect_timeout": 5}
CH = {"host": "127.0.0.1", "port": 8123, "database": "appdb"}


def load_env() -> dict[str, str]:
    env = {}
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


ENV = load_env()
# `make check` sets this: the security gate must FAIL, never silently skip, when the stack is unreachable.
REQUIRE_STACK = os.environ.get("VDBA_REQUIRE_STACK") == "1"
_skipped_for_stack = False


def dc(*args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        ["docker", "compose", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,  # noqa: S607
    )


def eventually(fn, timeout: float = 30, interval: float = 0.5):
    """Poll until fn() returns something truthy; returns it. Raises AssertionError on timeout."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = fn()
            if last:
                return last
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(interval)
    raise AssertionError(f"condition not met within {timeout}s (last: {last!r})")


class Portal:
    """A logged-in browser-like client of the portal (cookie jar + CSRF handling)."""

    def __init__(self, username: str | None = None, password: str | None = None):
        self.s = requests.Session()
        self.username = username or ENV["VDBA_ADMIN_USER"]
        self.password = password or ENV["VDBA_ADMIN_PASSWORD"]
        self.csrf = ""
        self.login()

    def login(self) -> None:
        page = self.s.get(f"{BASE}/login", timeout=10)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        r = self.s.post(
            f"{BASE}/login",
            data={"csrf_token": token, "username": self.username, "password": self.password},
            headers={"Origin": BASE},
            allow_redirects=False,
            timeout=30,
        )
        assert r.status_code == 303, r.text
        self.csrf = self.s.get(f"{BASE}/api/session", timeout=10).json()["csrf_token"]

    def post(self, path: str, json=None, headers=None, **kw) -> requests.Response:
        h = {"X-CSRF-Token": self.csrf, "Origin": BASE, **(headers or {})}
        return self.s.post(f"{BASE}{path}", json=json if json is not None else {}, headers=h, timeout=60, **kw)

    def get(self, path: str, **kw) -> requests.Response:
        return self.s.get(f"{BASE}{path}", timeout=30, **kw)

    def issue(self, db_type="postgres", tables=("customers",), commands=("SELECT",), ttl=120, **over):
        body = {
            "db_type": db_type,
            "scope": "tables",
            "tables": list(tables),
            "commands": list(commands),
            "ttl_seconds": ttl,
            "requested_for": "pytest",
        } | over
        r = self.post("/api/grants", json=body)
        assert r.status_code == 200, r.text
        return r.json()

    def revoke(self, grant_id: str) -> requests.Response:
        return self.post(f"/api/grants/{grant_id}/revoke")


@pytest.fixture(scope="session", autouse=True)
def stack():
    global _skipped_for_stack
    try:
        h = requests.get(f"{BASE}/healthz", timeout=3).json()
    except Exception:  # noqa: BLE001
        if REQUIRE_STACK:
            pytest.fail(
                "compose stack is NOT reachable but VDBA_REQUIRE_STACK=1: the security gate cannot pass", pytrace=False
            )
        _skipped_for_stack = True
        pytest.skip("compose stack is not running (make up)")
    if not ENV:
        pytest.fail(".env not found", pytrace=False) if REQUIRE_STACK else pytest.skip(".env not found")
    return h


def pytest_terminal_summary(terminalreporter):
    if _skipped_for_stack:
        terminalreporter.write_sep(
            "!", "INTEGRATION TESTS WERE SKIPPED: no running stack. This is NOT a security check."
        )
        terminalreporter.write_line("Run `make check` (fresh stack, fails if the stack is unreachable).")


@pytest.fixture(scope="session")
def hooks(stack):
    if not stack.get("test_hooks"):
        if REQUIRE_STACK:
            pytest.fail("stack started without VDBA_TEST_HOOKS=1 but VDBA_REQUIRE_STACK=1", pytrace=False)
        pytest.skip("stack started without VDBA_TEST_HOOKS=1")


@pytest.fixture(scope="session")
def root_token(stack):
    """A privileged non-root token minted by setup ONLY on test stacks (VDBA_TEST_HOOKS=1; Vault 2.x has no
    unauthenticated generate-root). The real root token stays revoked (see test_02c)."""
    f = ROOT / "secrets" / "test-admin-token"
    if not f.exists():
        if REQUIRE_STACK:
            pytest.fail(
                "secrets/test-admin-token missing: start the stack with VDBA_TEST_HOOKS=1 (make check)", pytrace=False
            )
        pytest.skip("no test-admin token (stack not started with VDBA_TEST_HOOKS=1)")
    return f.read_text().strip()


@pytest.fixture(scope="session")
def admin(stack) -> Portal:
    return Portal()


@pytest.fixture
def grants(admin):
    """Collects grant ids to revoke at teardown."""
    ids: list[str] = []
    yield ids
    for gid in ids:
        try:
            admin.revoke(gid)
        except Exception:  # noqa: BLE001, S110
            pass


# ---- direct database access (as the host, over 127.0.0.1) -----------------------------------------


def pg_connect(user: str, password: str) -> psycopg.Connection:
    return psycopg.connect(user=user, password=password, autocommit=True, **PG)


def ch_connect(user: str, password: str):
    return clickhouse_connect.get_client(username=user, password=password, **CH)


def pg_introspect() -> psycopg.Connection:
    return pg_connect("vault_introspect", ENV["PG_INTROSPECT_PASSWORD"])


def ch_introspect():
    return ch_connect("vault_introspect", ENV["CLICKHOUSE_INTROSPECT_PASSWORD"])


def pg_role_exists(name: str) -> bool:
    with pg_introspect() as c:
        return c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)).fetchone() is not None


def ch_user_exists(name: str) -> bool:
    return bool(
        ch_introspect().query("SELECT 1 FROM system.users WHERE name = %(n)s", parameters={"n": name}).result_rows
    )


def can_login(db_type: str, user: str, password: str) -> bool:
    try:
        if db_type == "postgres":
            pg_connect(user, password).close()
        else:
            ch_connect(user, password).query("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        return False


def vault_login_approle() -> str:
    """Token of the middleware's own AppRole identity (secret read from inside the container)."""
    role_id = dc("exec", "-T", "middleware", "cat", "/run/vdba/approle/role_id").stdout.strip()
    secret_id = dc("exec", "-T", "middleware", "cat", "/run/vdba/approle/secret_id").stdout.strip()
    r = requests.post(f"{VAULT}/v1/auth/approle/login", json={"role_id": role_id, "secret_id": secret_id}, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()["auth"]["client_token"]


def vault_login_admin() -> str:
    r = requests.post(
        f"{VAULT}/v1/auth/userpass/login/{ENV['VDBA_ADMIN_USER']}",
        json={"password": ENV["VDBA_ADMIN_PASSWORD"]},
        timeout=10,
    )
    assert r.status_code == 200, r.text
    return r.json()["auth"]["client_token"]
