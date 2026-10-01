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
# Deliberately absent: sys/policies/*, database/config/*, database/creds/*, sys/leases/revoke-prefix.
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
        write_private(KEYS_FILE, json.dumps(keys))  # BEFORE anything else can fail
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


def ensure_connection(c: hvac.Client, name: str, plugin: str, url: str, user: str, password: str) -> None:
    if c.read(f"database/config/{name}") is not None:
        log(f"connection {name!r} already configured; leaving it (it may have been rotated)")
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
    log(f"connection {name!r} configured (as non-superuser {user!r}, connection verified)")


def ensure_connections(c: hvac.Client, env: dict[str, str]) -> None:
    ensure_connection(
        c,
        "postgres",
        "postgresql-database-plugin",
        f"postgresql://{{{{username}}}}:{{{{password}}}}@{config.POSTGRES_HOST}:{config.POSTGRES_PORT}/"
        f"{config.POSTGRES_DB}?sslmode=disable",
        "vault_manager",
        env["PG_MANAGER_PASSWORD"],
    )
    ensure_connection(
        c,
        "clickhouse",
        PLUGIN_NAME,
        f"clickhouse://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_NATIVE_PORT}"
        "?username={{username}}&password={{password}}&dial_timeout=10s",
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


def revoke_root(c: hvac.Client, keep: bool) -> None:
    if keep:
        log("--keep-root: root token left in place (revoke it yourself when done)")
        return
    c.auth.token.revoke_self()
    keys = load_keys()
    keys.pop("root_token", None)
    write_private(KEYS_FILE, json.dumps(keys))
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
            log("already provisioned (root token is revoked and the AppRole login works); nothing to do")
            return
        raise SystemExit(
            "no usable root token. If this is a re-run after the root token was revoked, generate a new one "
            "with `vault operator generate-root`, put it in ./secrets/root-token and run setup again."
        )
    ensure_audit(root)  # first, so everything after it is audited
    ensure_engines(root)
    ensure_connections(root, env)
    ensure_policies_and_roles(root, env)
    deliver_approle(root)
    self_check()
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
