"""All Vault access for the running portal goes through the middleware's own AppRole identity.
Admin tokens are only ever used to check "who is this" at login."""

import re
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import hvac
from hvac import exceptions as vexc

from . import config
from .models import DbType

T = TypeVar("T")
RELOGIN_AFTER = 45 * 60  # token_ttl is 1h


class VaultUnavailable(Exception):
    pass


def new_client(token: str | None = None) -> hvac.Client:
    return hvac.Client(url=config.VAULT_ADDR, token=token, timeout=config.VAULT_TIMEOUT)


def _read_approle() -> tuple[str, str]:
    d = Path(config.APPROLE_DIR)
    try:
        return (d / "role_id").read_text().strip(), (d / "secret_id").read_text().strip()
    except OSError as exc:
        raise VaultUnavailable("AppRole credentials not available (has `make up` / setup run?)") from exc


class Service:
    """Vault client logged in as the AppRole `vdba-service`; re-logs in on expiry/403."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._client: hvac.Client | None = None
        self._logged_in_at = 0.0

    def _login(self) -> hvac.Client:
        role_id, secret_id = _read_approle()
        c = new_client()
        try:
            c.auth.approle.login(role_id=role_id, secret_id=secret_id)
        except (vexc.VaultError, OSError) as exc:
            raise VaultUnavailable(f"AppRole login failed: {type(exc).__name__}") from exc
        old = self._client
        self._client, self._logged_in_at = c, time.time()
        if old is not None:  # do not leave the previous service token alive until its TTL
            try:
                old.auth.token.revoke_self()
            except Exception:  # noqa: BLE001, S110
                pass
        return c

    def client(self) -> hvac.Client:
        with self._lock:
            if self._client is None or time.time() - self._logged_in_at > RELOGIN_AFTER:
                return self._login()
            return self._client

    def call(self, fn: Callable[[hvac.Client], T]) -> T:
        try:
            return fn(self.client())
        except vexc.Forbidden:
            with self._lock:
                c = self._login()
            return fn(c)  # a second 403 is a real permission error
        except (vexc.VaultDown, OSError) as exc:
            raise VaultUnavailable(f"Vault unavailable: {type(exc).__name__}") from exc


service = Service()


# ---- helpers used by issue/revoke/reconcile ---------------------------------------------------


def connection_name(db_type: DbType | str) -> str:
    return config.CONNECTION_NAMES[str(db_type)]


def write_role(role: str, db_type: DbType, creation: list[str], revocation: list[str], ttl: int) -> None:
    service.call(
        lambda c: c.write(
            f"database/roles/{role}",
            db_name=connection_name(db_type),
            creation_statements=creation,
            revocation_statements=revocation,
            default_ttl=f"{ttl}s",
            max_ttl=f"{ttl}s",
        )
    )


def delete_role(role: str) -> None:
    service.call(lambda c: c.delete(f"database/roles/{role}"))


def create_grant_token(ttl: int, label: str) -> tuple[str, str]:
    """Orphan service token that will own exactly this grant's lease. Returns (token, accessor).
    `label` (the grant id) becomes the token's display name so a token whose create response was
    lost can still be found and revoked (see find_token_accessors)."""
    resp = service.call(
        lambda c: c.write(
            f"auth/token/create/{config.TOKEN_ROLE_NAME}",
            ttl=f"{ttl + config.TOKEN_GRACE_SECONDS}s",
            display_name=label,
        )
    )
    return resp["auth"]["client_token"], resp["auth"]["accessor"]


MAX_ACCESSOR_SCAN = 20000


def _gone(exc: Exception) -> bool:
    return isinstance(exc, (vexc.InvalidRequest, vexc.InvalidPath)) and "invalid accessor" in str(exc).lower()


def find_token_accessors(label: str) -> list[str]:
    """Accessors of live tokens created for `label` (recovery path only; O(live tokens)).

    Vault stores the display name as "token-<name>" with "_" rewritten to "-". A lookup that fails for any
    reason other than "that token is already gone" raises, and so does a listing too long to scan: the caller
    must then NOT consider the cleanup complete."""
    resp = service.call(lambda c: c.list("auth/token/accessors"))
    keys = (resp or {}).get("data", {}).get("keys", [])
    if len(keys) > MAX_ACCESSOR_SCAN:
        raise RuntimeError(f"{len(keys)} tokens: too many to scan, cannot confirm the grant token is gone")
    wanted = "token-" + label.replace("_", "-")
    found = []
    for acc in keys:
        try:
            info = service.call(lambda c, a=acc: c.write("auth/token/lookup-accessor", accessor=a))
        except Exception as exc:
            if _gone(exc):
                continue  # expired or revoked between list and lookup
            raise
        if info["data"].get("display_name") in (wanted, "token-" + label, label):
            found.append(acc)
    return found


def read_credentials(grant_token: str, role: str) -> dict[str, Any]:
    """Read database/creds/<role> ONCE with the per-grant token; the token is then discarded."""
    c = new_client(grant_token)
    resp = c.read(f"database/creds/{role}")
    if resp is None:
        raise RuntimeError("empty credentials response")
    return {
        "username": resp["data"]["username"],
        "password": resp["data"]["password"],
        "lease_id": resp["lease_id"],
        "lease_duration": int(resp["lease_duration"]),
    }


def list_leases(role: str) -> list[str]:
    resp = service.call(lambda c: c.list(f"sys/leases/lookup/database/creds/{role}"))
    keys = (resp or {}).get("data", {}).get("keys", [])
    return [f"database/creds/{role}/{k}" for k in keys]


def revoke_lease(lease_id: str) -> None:
    """Synchronous: returns only after the DB revocation statements have run (or raises)."""
    try:
        service.call(lambda c: c.write(f"sys/leases/revoke/{lease_id}", sync=True))
    except (vexc.InvalidPath, vexc.InvalidRequest) as exc:
        if "not found" not in str(exc).lower() and "invalid lease" not in str(exc).lower():
            raise


def revoke_accessor(accessor: str) -> None:
    try:
        service.call(lambda c: c.write("auth/token/revoke-accessor", accessor=accessor))
    except (vexc.InvalidPath, vexc.InvalidRequest, vexc.Forbidden) as exc:
        if "invalid accessor" not in str(exc).lower():
            raise


def run_as_manager(db_type: DbType, label: str, statements: list[str]) -> None:
    """Run fixed statements as the DB connection's manager account, via Vault (the middleware holds no
    DB credentials): a one-shot role whose creation statements ARE the work, read once with a one-shot
    token. Raises if any statement fails (so a successful return is a confirmation)."""
    role = f"{label}"
    ttl = config.HELPER_TTL_SECONDS
    token = accessor = lease = None
    try:
        write_role(role, db_type, statements, ["SELECT 1"], ttl)
        token, accessor = create_grant_token(ttl, role)
        lease = read_credentials(token, role)["lease_id"]
    finally:
        for fn, arg in ((revoke_lease, lease), (revoke_accessor, accessor), (delete_role, role)):
            if arg or fn is delete_role:
                try:
                    fn(arg or role)
                except Exception:  # noqa: BLE001, S110 - expires on its own within HELPER_TTL
                    pass


def rotate_root(db_type: DbType) -> None:
    service.call(lambda c: c.write(f"database/rotate-root/{connection_name(db_type)}"))


def introspect_credentials(db_type: DbType) -> tuple[str, str]:
    resp = service.call(
        lambda c: c.secrets.kv.v2.read_secret_version(
            path=f"vdba/introspect/{db_type.value}", mount_point="kv", raise_on_deleted_version=True
        )
    )
    data = resp["data"]["data"]
    return data["username"], data["password"]


# ---- admin login (userpass) --------------------------------------------------------------------


def userpass_login(username: str, password: str) -> tuple[str, list[str]]:
    try:
        r = new_client().auth.userpass.login(username=username, password=password)
    except vexc.InvalidRequest as exc:
        raise PermissionError("invalid credentials") from exc
    except (vexc.VaultError, OSError) as exc:
        raise VaultUnavailable(f"Vault unavailable: {type(exc).__name__}") from exc
    return r["auth"]["client_token"], r["auth"].get("token_policies", [])


def user_policies(username: str) -> list[str] | None:
    """CURRENT policies of a userpass user (None if the user no longer exists). Read by the service
    identity: a token's own policy list is frozen at login and cannot show that rights were removed."""
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", username):
        return None
    try:
        resp = service.call(lambda c: c.read(f"auth/userpass/users/{username}"))
    except vexc.InvalidPath:
        return None
    return None if resp is None else list(resp["data"].get("token_policies") or [])


def token_policies(token: str) -> list[str] | None:
    """Policies of an admin token, or None if the token is dead."""
    try:
        return new_client(token).auth.token.lookup_self()["data"]["policies"]
    except vexc.Forbidden:
        return None
    except (vexc.VaultError, OSError) as exc:
        raise VaultUnavailable(f"Vault unavailable: {type(exc).__name__}") from exc


def revoke_token_quietly(token: str) -> None:
    try:
        new_client(token).auth.token.revoke_self()
    except Exception:  # noqa: BLE001, S110 - best effort at logout/expiry
        pass
