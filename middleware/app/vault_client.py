"""All Vault access for the running portal goes through the middleware's own AppRole identity.
Admin tokens are only ever used to check "who is this" at login."""

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
        self._client, self._logged_in_at = c, time.time()
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


def create_grant_token(ttl: int) -> tuple[str, str]:
    """Orphan service token that will own exactly this grant's lease. Returns (token, accessor)."""
    resp = service.call(
        lambda c: c.write(
            f"auth/token/create/{config.TOKEN_ROLE_NAME}",
            ttl=f"{ttl + config.TOKEN_GRACE_SECONDS}s",
            display_name="vdba-grant",
        )
    )
    return resp["auth"]["client_token"], resp["auth"]["accessor"]


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
