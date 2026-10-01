"""Runtime configuration. Everything comes from the environment; no secrets live here."""

import os
from urllib.parse import urlsplit


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vault:8200")
VAULT_TIMEOUT = 10
APPROLE_DIR = os.environ.get("VDBA_APPROLE_DIR", "/run/vdba/approle")
DB_PATH = os.environ.get("VDBA_DB_PATH", "/data/vdba.sqlite3")

POSTGRES_HOST = os.environ.get("VDBA_POSTGRES_HOST", "postgres")
POSTGRES_PORT = _int("VDBA_POSTGRES_PORT", 5432)
POSTGRES_DB = "appdb"
CLICKHOUSE_HOST = os.environ.get("VDBA_CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_HTTP_PORT = _int("VDBA_CLICKHOUSE_HTTP_PORT", 8123)
CLICKHOUSE_NATIVE_PORT = _int("VDBA_CLICKHOUSE_NATIVE_PORT", 9000)
CLICKHOUSE_DB = "appdb"
DB_TIMEOUT = 8
# Transport to Postgres. The demo runs plain on the internal docker network and needs VDBA_ALLOW_INSECURE=1.
PG_SSLMODE = os.environ.get("VDBA_PG_SSLMODE", "")

# Names of the objects created by `app.setup`.
CONNECTION_NAMES = {"postgres": "postgres", "clickhouse": "clickhouse"}
PASSWORD_POLICY_NAME = "vdba-password"
ADMIN_POLICY_NAME = "db-access-admin"
SERVICE_POLICY_NAME = "vdba-service"
CREDS_READER_POLICY_NAME = "vdba-creds-reader"
TOKEN_ROLE_NAME = "vdba-grant"
APPROLE_NAME = "vdba-service"
ROLE_PREFIX = "vdba_"  # Vault role names and DB usernames start with this

TTL_MIN = _int("VDBA_TTL_MIN_SECONDS", 10)
TTL_MAX = _int("VDBA_TTL_MAX_SECONDS", 86400)
TOKEN_GRACE_SECONDS = 120  # grant token outlives the lease by this much
HELPER_TTL_SECONDS = 60  # lifetime of the one-shot "run these statements as the manager" roles/tokens

ALLOWED_POSTGRES_COMMANDS = ["SELECT", "INSERT", "UPDATE", "DELETE"]
ALLOWED_CLICKHOUSE_COMMANDS = ["SELECT", "INSERT", "ALTER UPDATE", "ALTER DELETE"]

SESSION_ABSOLUTE_SECONDS = 8 * 3600
SESSION_IDLE_SECONDS = 30 * 60
SESSION_RECHECK_SECONDS = _int("VDBA_SESSION_RECHECK_SECONDS", 5 * 60)
BODY_LIMIT = 64 * 1024
# Admission limits (checked BEFORE any backend I/O; over the limit -> immediate 503).
MAX_ISSUE_OPS = 6  # issue, catalog reads, rotate
MAX_REVOKE_OPS = 4  # reserved so a flood of issues can never starve revocation
MAX_AUTH_OPS = 4  # logins

RECONCILE_INTERVAL = _int("VDBA_RECONCILE_INTERVAL", 60)
TEST_HOOKS = os.environ.get("VDBA_TEST_HOOKS") == "1"
FAULT_FILE = os.environ.get("VDBA_FAULT_FILE", "/data/fault-point")

PUBLIC_ORIGIN = os.environ.get("VDBA_PUBLIC_ORIGIN", "")
EXTRA_ORIGINS = {o for o in os.environ.get("VDBA_ALLOWED_ORIGINS", "").split(",") if o}
COOKIE_SECURE = os.environ.get("VDBA_COOKIE_SECURE", "auto")  # auto | 1 | 0
ALLOW_INSECURE = os.environ.get("VDBA_ALLOW_INSECURE") == "1"


def check_transport() -> None:
    """Refuse a plain-HTTP public origin on a non-loopback host unless explicitly allowed."""
    if not PUBLIC_ORIGIN:
        return
    parts = urlsplit(PUBLIC_ORIGIN)
    loopback = parts.hostname in {"localhost", "127.0.0.1", "::1"}
    if parts.scheme != "https" and not loopback and not ALLOW_INSECURE:
        raise SystemExit(
            "VDBA_PUBLIC_ORIGIN is plain http on a non-loopback host: put TLS in front of the portal "
            "or set VDBA_ALLOW_INSECURE=1"
        )
