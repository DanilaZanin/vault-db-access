"""One-off bootstrap, run as the `setup` compose service (profile "setup"):

    docker compose --profile setup run --rm setup            # via `make up`
    VDBA_SETUP_ARGS=--keep-root docker compose --profile setup run --rm setup

Idempotent. Exits non-zero on any failure. Never prints tokens, keys or passwords.

What it does: init + unseal Vault (keys and root token go ONLY to /secrets/vault-keys.json, 0600),
enable the file audit device, mount the database engine and KV v2, register the ClickHouse plugin,
create the DB connections (non-superuser manager accounts), the fixed policies, the per-grant token
role, the admin userpass account and the middleware AppRole, hand the AppRole secret to the
middleware through /secrets/approle, then revoke the root token.
"""

import argparse
import json
import os
import shlex
import sys
import tempfile
from pathlib import Path

import hvac
from hvac import exceptions as vexc

from . import config, preflight

SECRETS = Path(os.environ.get("VDBA_SECRETS_DIR", "/secrets"))
KEYS_FILE = SECRETS / "vault-keys.json"
APPROLE_OUT = SECRETS / "approle"
APP_UID = int(os.environ.get("VDBA_APP_UID", "1000"))
# On Linux hosts the bind-mounted files would be root-owned (setup runs as root); hand the key material to the
# host user who ran `make` so tests and operators can read it without sudo.
HOST_UID = int(os.environ["VDBA_HOST_UID"]) if os.environ.get("VDBA_HOST_UID") else None
PLUGIN_NAME = "clickhouse-database-plugin"
PLUGIN_SHA_FILE = Path("/opt/vdba/clickhouse-plugin.sha256")

PASSWORD_POLICY_HCL = """
length = 24
rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 4 }
rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 4 }
rule "charset" { charset = "0123456789" min-chars = 4 }
rule "charset" { charset = "-_" min-chars = 1 }
"""
# Only alphanumerics and -_ : generated passwords are embedded in SQL string literals and
# connection URLs by the database plugins, so no quoting characters may ever appear.

# Deterministic names: the reconciler can find leftovers by the "vdba_" prefix.
USERNAME_TEMPLATE = "{{ .RoleName }}_{{ random 6 | lowercase }}"

SERVICE_POLICY = """
# Roles are written by the middleware with fixed, code-generated templates.
path "database/roles/vdba_*" { capabilities = ["create", "read", "update", "delete"] }
path "database/rotate-root/postgres" { capabilities = ["update"] }
path "database/rotate-root/clickhouse" { capabilities = ["update"] }
path "kv/data/vdba/introspect/*" { capabilities = ["read"] }
# One orphan token per grant, from a token role with a FIXED allowed policy.
path "auth/token/create/vdba-grant" { capabilities = ["create", "update"] }
path "auth/token/revoke-accessor" { capabilities = ["update"] }
# Revocation (no sudo, no revoke-prefix) and lease discovery for the reconciler.
path "sys/leases/revoke/database/creds/vdba_*" { capabilities = ["update"] }
# (listing leases requires sudo in Vault; scoped to our own role prefix only)
path "sys/leases/lookup/database/creds/vdba_*" { capabilities = ["list", "sudo"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
# Needed to revoke its own previous token on re-login (token_no_default_policy drops the default policy's grant).
path "auth/token/revoke-self" { capabilities = ["update"] }
# Read-only view of the two connections (never returns the password): lets a later setup run re-check them.
path "database/config/postgres" { capabilities = ["read"] }
path "database/config/clickhouse" { capabilities = ["read"] }
# Session re-validation reads the CURRENT policies of an admin user (never the password hash).
path "auth/userpass/users/*" { capabilities = ["read"] }
# Recovery of a grant token whose create response was lost: find it by its display name (grant id).
# Accessors are not credentials; listing them needs sudo on this one path.
path "auth/token/accessors" { capabilities = ["list", "sudo"] }
path "auth/token/lookup-accessor" { capabilities = ["update"] }
# Deliberately absent: sys/policies/*, database/config WRITES, database/creds/*, sys/leases/revoke-prefix.
"""
CREDS_READER_POLICY = 'path "database/creds/vdba_*" { capabilities = ["read"] }\n'
ADMIN_POLICY = (
    "# Marker policy: portal administrators hold NO direct Vault privileges.\n"
    'path "sys/capabilities-self" { capabilities = ["update"] }\n'
)


def log(msg: str) -> None:
    print(f"[setup] {msg}", flush=True)


def write_private(path: Path, data: str, mode: int = 0o600, uid: int | None = None) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(tmp, mode)
    if uid is not None:
        os.chown(tmp, uid, uid)
    os.replace(tmp, path)


def client(token: str | None = None) -> hvac.Client:
    return hvac.Client(url=config.VAULT_ADDR, token=token, timeout=30)


# ---- init / unseal ------------------------------------------------------------------------------


def load_keys() -> dict:
    return json.loads(KEYS_FILE.read_text()) if KEYS_FILE.exists() else {}


def init_and_unseal() -> dict:
    c = client()
    keys = load_keys()
    if not c.sys.is_initialized():
        shares = int(os.environ.get("VDBA_UNSEAL_SHARES", "1"))
        threshold = int(os.environ.get("VDBA_UNSEAL_THRESHOLD", "1"))
        res = c.sys.initialize(secret_shares=shares, secret_threshold=threshold)
        keys = {"keys": res["keys_base64"], "root_token": res["root_token"], "threshold": threshold}
        write_private(KEYS_FILE, json.dumps(keys), uid=HOST_UID)  # BEFORE anything else can fail
        log(f"Vault initialized; unseal key(s) and root token written to {KEYS_FILE} (mode 0600)")
    if c.sys.is_sealed():
        if not keys.get("keys"):
            raise SystemExit(f"Vault is sealed and {KEYS_FILE} has no unseal keys: unseal it manually")
        for k in keys["keys"][: keys.get("threshold", 1)]:
            if not c.sys.submit_unseal_key(k)["sealed"]:
                break
        if c.sys.is_sealed():
            raise SystemExit("could not unseal Vault with the stored key(s)")
        log("Vault unsealed")
    return keys


def root_client(keys: dict) -> hvac.Client | None:
    for source in (
        keys.get("root_token"),
        (SECRETS / "root-token").read_text().strip() if (SECRETS / "root-token").exists() else None,
    ):
        if source:
            c = client(source)
            try:
                if c.is_authenticated():
                    return c
            except vexc.VaultError:
                pass
    return None


# ---- provisioning -------------------------------------------------------------------------------


def ensure_audit(c: hvac.Client) -> None:
    if "file/" not in (c.sys.list_enabled_audit_devices().get("data") or {}):
        c.sys.enable_audit_device(device_type="file", path="file", options={"file_path": "/vault/logs/audit.log"})
        log("file audit device enabled (/vault/logs/audit.log in the vault container)")


def ensure_engines(c: hvac.Client) -> None:
    mounts = c.sys.list_mounted_secrets_engines()["data"]
    if "database/" not in mounts:
        c.sys.enable_secrets_engine(backend_type="database", path="database")
    if "kv/" not in mounts:
        c.sys.enable_secrets_engine(backend_type="kv", path="kv", options={"version": "2"})
    c.write(f"sys/policies/password/{config.PASSWORD_POLICY_NAME}", policy=PASSWORD_POLICY_HCL)
    digest = PLUGIN_SHA_FILE.read_text().strip()
    if len(digest) != 64 or not all(ch in "0123456789abcdef" for ch in digest):
        raise SystemExit(f"bad plugin digest in {PLUGIN_SHA_FILE}")
    c.write(f"sys/plugins/catalog/database/{PLUGIN_NAME}", sha256=digest, command=PLUGIN_NAME)


PROBES = {
    # Run AS the connection's own DB account (through a throw-away role); a statement error = unsafe.
    # PostgreSQL: no superuser-like attributes, no membership in ANY predefined pg_* role (pg_execute_server_program,
    # pg_read_server_files, ... directly or through inheritance) and none in any role that is not one of ours.
    "postgres": [
        "SELECT 1 / (CASE WHEN "
        "(SELECT rolsuper OR rolbypassrls OR rolreplication OR rolcreatedb OR NOT rolcreaterole "
        " FROM pg_roles WHERE rolname = current_user) "
        "OR EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname LIKE 'pg\\_%' "
        " AND pg_has_role(current_user, r.oid, 'MEMBER')) "
        "OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid "
        " WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user) AND g.rolname NOT LIKE 'vdba\\_%') "
        "THEN 0 ELSE 1 END)"
    ],
    # ClickHouse: the EFFECTIVE grants must be exactly the allowlist (no roles at all, nothing outside appdb/system).
    "clickhouse": [
        "SELECT throwIf("
        "(SELECT count() FROM system.grants WHERE user_name = currentUser() AND ("
        "access_type NOT IN ('KILL QUERY', 'CREATE USER', 'ALTER USER', 'DROP USER', 'SELECT', 'INSERT', "
        "'ALTER UPDATE', 'ALTER DELETE') OR (database IS NOT NULL AND database NOT IN ('appdb', 'system')))) > 0 "
        "OR (SELECT count() FROM system.role_grants WHERE user_name = currentUser()) > 0)"
    ],
}


def check_connection_config(c: hvac.Client, name: str) -> None:
    """The parts that can be checked without running anything: the account and the username template (the
    reconciler finds a grant's accounts by that template's `<grant id>_` prefix)."""
    cfg = c.read(f"database/config/{name}")["data"]["connection_details"]
    if cfg.get("username") != "vault_manager":
        raise SystemExit(
            f"connection {name!r} uses account {cfg.get('username')!r}, not 'vault_manager': refusing to continue. "
            f"Delete it (vault delete database/config/{name}) and re-run setup"
        )
    if cfg.get("username_template") != USERNAME_TEMPLATE:
        raise SystemExit(
            f"connection {name!r} has username_template {cfg.get('username_template')!r}, expected "
            f"{USERNAME_TEMPLATE!r}: cleanup of half-created accounts depends on it; refusing to continue"
        )


def validate_connection(c: hvac.Client, name: str, kind: str | None = None) -> None:
    """Refuse a connection that is not our least-privilege manager: wrong account name, foreign username
    template, or an account whose EFFECTIVE privileges exceed the allowlist (checked by running a probe as that
    account). Needs a privileged client. Raises SystemExit."""
    check_connection_config(c, name)
    kind = kind or name
    probe_role = f"vdba_probe_{name}"
    c.write(
        f"database/roles/{probe_role}",
        db_name=name,
        creation_statements=PROBES[kind],
        revocation_statements=["SELECT 1"],
        default_ttl="30s",
        max_ttl="30s",
    )
    lease = None
    try:
        lease = c.read(f"database/creds/{probe_role}")["lease_id"]
    except vexc.VaultError as exc:
        raise SystemExit(
            f"connection {name!r} failed the least-privilege probe (extra privileges or role memberships?): "
            f"refusing. {exc}"
        ) from exc
    finally:
        if lease:
            c.write(f"sys/leases/revoke/{lease}")
        c.delete(f"database/roles/{probe_role}")
    log(f"connection {name!r} verified: account vault_manager, our username template, privileges within the allowlist")


WEAK_SSLMODES = {"disable", "allow", "prefer"}
SSLMODES = WEAK_SSLMODES | {"require", "verify-ca", "verify-full"}


def pg_sslmode() -> str:
    mode = os.environ.get("VDBA_PG_SSLMODE", "")
    insecure_ok = os.environ.get("VDBA_ALLOW_INSECURE") == "1"
    if mode and mode not in SSLMODES:
        raise SystemExit(f"VDBA_PG_SSLMODE={mode!r} is not one of {sorted(SSLMODES)}")
    if mode in WEAK_SSLMODES and not insecure_ok:
        raise SystemExit(
            f"VDBA_PG_SSLMODE={mode} sends data without verified TLS: needs VDBA_ALLOW_INSECURE=1 (demo only)"
        )
    if mode:
        return mode
    if os.environ.get("VDBA_PG_SSLROOTCERT"):
        return "verify-full"
    if not insecure_ok:
        raise SystemExit(
            "no TLS configured for Postgres: set VDBA_PG_SSLMODE (e.g. verify-full) or VDBA_PG_SSLROOTCERT, "
            "or set VDBA_ALLOW_INSECURE=1 to accept plain text on the internal network (demo only)"
        )
    return "disable"


def ensure_connection(c: hvac.Client, name: str, plugin: str, url: str, user: str, password: str) -> None:
    if c.read(f"database/config/{name}") is not None:
        log(f"connection {name!r} already configured; validating it (it may have been rotated)")
        validate_connection(c, name)
        return
    c.write(
        f"database/config/{name}",
        plugin_name=plugin,
        allowed_roles="vdba_*",
        connection_url=url,
        username=user,
        password=password,
        username_template=USERNAME_TEMPLATE,
        password_policy=config.PASSWORD_POLICY_NAME,
        verify_connection=True,
    )
    validate_connection(c, name)


def ensure_connections(c: hvac.Client, env: dict[str, str]) -> None:
    ensure_connection(
        c,
        "postgres",
        "postgresql-database-plugin",
        f"postgresql://{{{{username}}}}:{{{{password}}}}@{config.POSTGRES_HOST}:{config.POSTGRES_PORT}/"
        f"{config.POSTGRES_DB}?sslmode={pg_sslmode()}"
        + (f"&sslrootcert={os.environ['VDBA_PG_SSLROOTCERT']}" if os.environ.get("VDBA_PG_SSLROOTCERT") else ""),
        "vault_manager",
        env["PG_MANAGER_PASSWORD"],
    )
    ensure_connection(
        c,
        "clickhouse",
        PLUGIN_NAME,
        f"clickhouse://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_NATIVE_PORT}"
        "?username={{username}}&password={{password}}&dial_timeout=10s"
        + ("&secure=true" if os.environ.get("VDBA_CH_SECURE") == "1" else ""),
        "vault_manager",
        env["CLICKHOUSE_MANAGER_PASSWORD"],
    )
    for db, var in (("postgres", "PG_INTROSPECT_PASSWORD"), ("clickhouse", "CLICKHOUSE_INTROSPECT_PASSWORD")):
        c.secrets.kv.v2.create_or_update_secret(
            path=f"vdba/introspect/{db}",
            secret={"username": "vault_introspect", "password": env[var]},
            mount_point="kv",
        )


def ensure_policies_and_roles(c: hvac.Client, env: dict[str, str]) -> None:
    c.sys.create_or_update_policy(config.SERVICE_POLICY_NAME, SERVICE_POLICY)
    c.sys.create_or_update_policy(config.CREDS_READER_POLICY_NAME, CREDS_READER_POLICY)
    c.sys.create_or_update_policy(config.ADMIN_POLICY_NAME, ADMIN_POLICY)
    c.write(
        f"auth/token/roles/{config.TOKEN_ROLE_NAME}",
        allowed_policies=[config.CREDS_READER_POLICY_NAME],
        orphan=True,
        renewable=False,
        token_no_default_policy=True,
        token_type="service",
        token_explicit_max_ttl=f"{int(os.environ.get('VDBA_TTL_MAX_SECONDS', config.TTL_MAX)) + 3600}s",
    )
    auth = c.sys.list_auth_methods()["data"]
    if "userpass/" not in auth:
        c.sys.enable_auth_method("userpass", path="userpass")
    if "approle/" not in auth:
        c.sys.enable_auth_method("approle", path="approle")
    c.write(
        f"auth/userpass/users/{env['VDBA_ADMIN_USER']}",
        password=env["VDBA_ADMIN_PASSWORD"],
        token_policies=[config.ADMIN_POLICY_NAME],
        token_ttl="8h",
        token_max_ttl="8h",
    )
    c.write(
        f"auth/approle/role/{config.APPROLE_NAME}",
        token_policies=[config.SERVICE_POLICY_NAME],
        token_no_default_policy=True,
        token_ttl="1h",
        token_max_ttl="24h",
        token_type="service",
        secret_id_num_uses=0,
        secret_id_ttl=0,
    )


def approle_login_ok(role_id: str, secret_id: str) -> bool:
    try:
        client().auth.approle.login(role_id=role_id, secret_id=secret_id)
        return True
    except vexc.VaultError:
        return False


def recheck_without_root() -> None:
    """No privileged token: re-check what the service identity may read (account + username template of both
    connections) and say loudly what could not be re-checked."""
    svc = client()
    svc.auth.approle.login(
        role_id=(APPROLE_OUT / "role_id").read_text().strip(), secret_id=(APPROLE_OUT / "secret_id").read_text().strip()
    )
    for name in ("postgres", "clickhouse"):
        try:
            check_connection_config(svc, name)
        except vexc.Forbidden:
            log(f"WARNING: cannot read connector {name!r} with the service identity (older policy): NOT re-checked")
            continue
        log(f"connector {name!r} re-checked with the service identity (account and username_template ok)")
    log(
        "WARNING: the root token is revoked, so the least-privilege probe was NOT re-run: the effective privileges "
        "of the vault_manager accounts were not re-validated. Re-run setup with a root token to do that."
    )


def deliver_approle(c: hvac.Client) -> None:
    """Writes role_id / secret_id into /secrets/approle (the only directory the middleware mounts)."""
    APPROLE_OUT.mkdir(parents=True, exist_ok=True)
    os.chown(APPROLE_OUT, APP_UID, APP_UID)
    os.chmod(APPROLE_OUT, 0o700)
    role_id = c.read(f"auth/approle/role/{config.APPROLE_NAME}/role-id")["data"]["role_id"]
    sid_file = APPROLE_OUT / "secret_id"
    if sid_file.exists() and approle_login_ok(role_id, sid_file.read_text().strip()):
        log("existing AppRole secret_id is still valid; keeping it")
    else:
        secret_id = c.write(f"auth/approle/role/{config.APPROLE_NAME}/secret-id")["data"]["secret_id"]
        write_private(sid_file, secret_id, 0o400, APP_UID)
        log("new AppRole secret_id written to secrets/approle/secret_id")
    write_private(APPROLE_OUT / "role_id", role_id, 0o400, APP_UID)


def self_check() -> None:
    """Prove the service identity works (and is as narrow as intended) before root goes away."""
    role_id = (APPROLE_OUT / "role_id").read_text().strip()
    secret_id = (APPROLE_OUT / "secret_id").read_text().strip()
    svc = client()
    svc.auth.approle.login(role_id=role_id, secret_id=secret_id)
    svc.secrets.kv.v2.read_secret_version(path="vdba/introspect/postgres", mount_point="kv")
    for bad in ("sys/policies/acl/evil", "database/config/evil"):
        try:
            svc.write(bad, policy='path "*" { capabilities = ["sudo"] }', plugin_name="x")
        except vexc.Forbidden:
            continue
        raise SystemExit(f"self-check failed: service identity could write {bad}")
    log("self-check ok: AppRole login works; policy/config writes are forbidden")


def mint_test_admin(c: hvac.Client) -> None:
    """TEST STACKS ONLY (VDBA_TEST_HOOKS=1, i.e. `make check`): the integration tests need a privileged token
    to create/delete Vault users and inspect tokens, and Vault 2.x offers no unauthenticated generate-root.
    It is a 2 h non-root token written to ./secrets/test-admin-token; the real root token is still revoked."""
    c.sys.create_or_update_policy(
        "vdba-test-admin", 'path "*" { capabilities = ["create","read","update","delete","list","sudo"] }'
    )
    tok = c.auth.token.create(policies=["vdba-test-admin"], ttl="2h", no_parent=True, renewable=False)
    write_private(SECRETS / "test-admin-token", tok["auth"]["client_token"], uid=HOST_UID)
    log("TEST HOOKS ON: wrote a 2 h test-admin token to secrets/test-admin-token (never do this in production)")


def revoke_root(c: hvac.Client, keep: bool) -> None:
    if keep:
        log("--keep-root: root token left in place (revoke it yourself when done)")
        return
    keys = load_keys()
    keys["root_accessor"] = c.auth.token.lookup_self()["data"]["accessor"]  # lets anyone confirm the token is dead
    write_private(KEYS_FILE, json.dumps(keys), uid=HOST_UID)
    c.auth.token.revoke_self()
    keys.pop("root_token", None)
    write_private(KEYS_FILE, json.dumps(keys), uid=HOST_UID)
    (SECRETS / "root-token").unlink(missing_ok=True)
    log("root token revoked and removed from disk")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep-root", action="store_true", help="do not revoke the root token at the end")
    args = ap.parse_args(shlex.split(os.environ.get("VDBA_SETUP_ARGS", "")) + sys.argv[1:])

    env = dict(os.environ)
    bad = preflight.problems(env)
    if bad:
        raise SystemExit("refusing to run setup: " + "; ".join(bad))
    SECRETS.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRETS, 0o700)

    keys = init_and_unseal()
    root = root_client(keys)
    if root is None:
        role_id_f, sid_f = APPROLE_OUT / "role_id", APPROLE_OUT / "secret_id"
        if (
            role_id_f.exists()
            and sid_f.exists()
            and approle_login_ok(role_id_f.read_text().strip(), sid_f.read_text().strip())
        ):
            log("already provisioned (root token is revoked and the AppRole login works); nothing to provision")
            recheck_without_root()
            return
        raise SystemExit(
            "no usable root token and the AppRole files are missing or invalid. To get a new root token follow "
            "README 'Getting a new root token' (it needs `enable_unauthenticated_access = [\"generate-root\"]` in the "
            "Vault server config for the duration of the procedure), put it in ./secrets/root-token, run setup again."
        )
    ensure_audit(root)  # first, so everything after it is audited
    ensure_engines(root)
    ensure_connections(root, env)
    ensure_policies_and_roles(root, env)
    deliver_approle(root)
    self_check()
    if os.environ.get("VDBA_TEST_HOOKS") == "1":
        mint_test_admin(root)
    revoke_root(root, args.keep_root)
    log(f"done: portal admin is {env['VDBA_ADMIN_USER']!r}; the middleware can now log in via AppRole")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[setup] FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
