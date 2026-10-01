"""Issue / revoke / reconcile. Every external step writes its identifiers to the store FIRST so a
crash at any point leaves enough information to clean up (see reconcile())."""

import logging
import threading
import time
from datetime import UTC, datetime
from typing import Any

from . import config, db_introspect, faults, store, vault_client
from .models import TERMINAL, DbType, GrantRequest, Status
from .statement_builder import build_statements

log = logging.getLogger("vdba.grants")

_db_locks = {DbType.postgres: threading.Lock(), DbType.clickhouse: threading.Lock()}  # issue/revoke serialized per DB
_ops = threading.BoundedSemaphore(config.MAX_CONCURRENT_OPS)
_inflight: set[str] = set()
_inflight_lock = threading.Lock()


class Busy(Exception):
    pass


class NotFound(Exception):
    pass


def _begin(db_type: DbType, grant_id: str):
    if not _ops.acquire(timeout=20):
        raise Busy("too many concurrent operations")
    lock = _db_locks[db_type]
    if not lock.acquire(timeout=60):
        _ops.release()
        raise Busy(f"another {db_type.value} operation is taking too long")
    with _inflight_lock:
        _inflight.add(grant_id)
    return lock


def _end(lock, grant_id: str) -> None:
    with _inflight_lock:
        _inflight.discard(grant_id)
    lock.release()
    _ops.release()


def validate_ttl(ttl: int) -> None:
    if not config.TTL_MIN <= ttl <= config.TTL_MAX:
        raise ValueError(f"ttl_seconds must be between {config.TTL_MIN} and {config.TTL_MAX}")


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def public(g: dict[str, Any]) -> dict[str, Any]:
    """What the API/UI may show about a grant: no credentials exist in the store, and no Vault ids."""
    return {
        "grant_id": g["id"], "db_type": g["db_type"], "scope": g["scope"], "tables": g["tables"],
        "commands": g["commands"], "requested_for": g["requested_for"], "issued_by": g["issued_by"],
        "ttl_seconds": g["ttl_seconds"], "status": g["status"], "username": g["username"],
        "created_at": iso(g["created_at"]), "expires_at": iso(g["expires_at"]),
    }  # fmt: skip


def issue(req: GrantRequest, actor: str, request_id: str) -> dict[str, Any]:
    """Returns the public grant plus the one-time `password`. Nothing secret is persisted."""
    validate_ttl(req.ttl_seconds)
    cat = db_introspect.catalog(req.db_type)
    creation, revocation = build_statements(
        req.db_type, req.scope, req.tables, req.commands, set(cat.tables), cat.sequences
    )
    grant_id = store.new_grant_id()
    lock = _begin(req.db_type, grant_id)
    try:
        store.insert_grant({
            "id": grant_id, "db_type": req.db_type.value, "scope": req.scope.value,
            "tables": req.tables if req.scope.value == "tables" else [], "commands": req.commands,
            "requested_for": req.requested_for, "issued_by": actor, "ttl_seconds": req.ttl_seconds,
        })  # fmt: skip
        try:
            vault_client.write_role(grant_id, req.db_type, creation, revocation, req.ttl_seconds)
            faults.point("after_role_create")
            token, accessor = vault_client.create_grant_token(req.ttl_seconds)
            store.update_grant(grant_id, token_accessor=accessor)  # BEFORE the token is used
            creds = vault_client.read_credentials(token, grant_id)
            del token  # only ever held in this frame
            faults.point("after_creds_read")
            store.update_grant(
                grant_id,
                status=Status.active.value,
                username=creds["username"],
                lease_id=creds["lease_id"],
                expires_at=time.time() + creds["lease_duration"],
            )
        except BaseException as exc:
            store.audit(request_id, grant_id, actor, "issue", "error", type(exc).__name__)
            log.exception("issue failed for %s", grant_id)
            _teardown(grant_id, Status.failed, request_id)
            raise
        store.audit(request_id, grant_id, actor, "issue", "ok", f"{req.db_type.value} {req.scope.value}")
    finally:
        _end(lock, grant_id)
    out = public(store.get_grant(grant_id))  # type: ignore[arg-type]
    out["password"] = creds["password"]
    return out


def revoke(grant_id: str, actor: str, request_id: str) -> dict[str, Any]:
    g = store.get_grant(grant_id)
    if g is None:
        raise NotFound(grant_id)
    if g["status"] in (Status.revoked.value, Status.expired.value, Status.failed.value):
        return public(g)
    lock = _begin(DbType(g["db_type"]), grant_id)
    try:
        store.update_grant(grant_id, status=Status.revoking.value)
        store.audit(request_id, grant_id, actor, "revoke", "started")
        _teardown(grant_id, Status.revoked, request_id, actor=actor, raise_errors=True)
    finally:
        _end(lock, grant_id)
    return public(store.get_grant(grant_id))  # type: ignore[arg-type]


def _teardown(
    grant_id: str, final: Status, request_id: str | None, actor: str = "system", raise_errors: bool = False
) -> None:
    """Idempotent cleanup in the order: leases (sync, kills the DB account) -> token -> role.
    On failure the row stays `revoking` with last_error so the reconciler retries."""
    g = store.get_grant(grant_id)
    if g is None:
        return
    try:
        leases = set(vault_client.list_leases(grant_id))
        if g["lease_id"]:
            leases.add(g["lease_id"])
        for lease in sorted(leases):
            vault_client.revoke_lease(lease)
        if g["token_accessor"]:
            vault_client.revoke_accessor(g["token_accessor"])
        vault_client.delete_role(grant_id)
    except Exception as exc:  # noqa: BLE001 - recorded and retried by the reconciler
        store.update_grant(grant_id, status=Status.revoking.value, last_error=f"{type(exc).__name__}: {exc}"[:300])
        store.audit(request_id, grant_id, actor, "teardown", "error", type(exc).__name__)
        log.warning("teardown of %s failed: %s", grant_id, type(exc).__name__)
        if raise_errors:
            raise
        return
    store.update_grant(grant_id, status=final.value, last_error=None)
    store.audit(request_id, grant_id, actor, "teardown", final.value)


def reconcile_once() -> None:
    """Retry anything left half-done and finish expired grants. Safe to run at any time."""
    now = time.time()
    rows = store.list_grants(limit=1000)
    for g in rows:
        with _inflight_lock:
            if g["id"] in _inflight:
                continue
        st = g["status"]
        if st == Status.issuing.value:
            final = Status.failed
        elif st == Status.revoking.value:
            final = Status.revoked
        elif st == Status.active.value and g["expires_at"] and now > g["expires_at"] + 15:
            final = Status.expired
        else:
            continue
        lock = _begin(DbType(g["db_type"]), g["id"])
        try:
            fresh = store.get_grant(g["id"])
            if fresh and fresh["status"] not in {s.value for s in TERMINAL}:
                _teardown(g["id"], final, None)
        finally:
            _end(lock, g["id"])
    _report_orphans()


def _report_orphans() -> None:
    """DB accounts with our prefix that no live grant explains (e.g. a partial CREATE USER)."""
    live = {g["username"] for g in store.list_grants(limit=1000) if g["username"]
            and g["status"] in (Status.active.value, Status.revoking.value, Status.issuing.value)}  # fmt: skip
    pending = any(g["status"] == Status.issuing.value for g in store.list_grants((Status.issuing.value,)))
    if pending:
        return
    for db_type in DbType:
        try:
            names = db_introspect.leftover_users(db_type)
        except Exception as exc:  # noqa: BLE001
            log.warning("orphan scan for %s skipped: %s", db_type.value, type(exc).__name__)
            continue
        for name in names:
            if name not in live and not store.audit_exists("orphan_account", name):
                log.warning("untracked %s account %s", db_type.value, name)
                store.audit(None, None, "system", "orphan_account", "warning", name)


def reconcile_loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            reconcile_once()
        except Exception:  # noqa: BLE001
            log.exception("reconcile failed")
        stop.wait(config.RECONCILE_INTERVAL)
