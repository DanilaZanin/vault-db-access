"""Issue / revoke / reconcile. Every external step writes its identifiers to the store FIRST so a
crash at any point leaves enough information to clean up (see reconcile())."""

import logging
import secrets
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from . import config, db_introspect, faults, statement_builder, store, vault_client
from .models import DbType, GrantRequest, Status
from .statement_builder import build_statements

log = logging.getLogger("vdba.grants")

_db_locks = {
    DbType.postgres: threading.Lock(),
    DbType.clickhouse: threading.Lock(),
}  # issue/revoke serialized per DB
_inflight: set[str] = set()
_inflight_lock = threading.Lock()
_admission = {
    "issue": threading.BoundedSemaphore(config.MAX_ISSUE_OPS),
    "revoke": threading.BoundedSemaphore(config.MAX_REVOKE_OPS),
    "auth": threading.BoundedSemaphore(config.MAX_AUTH_OPS),
}


class Busy(Exception):
    pass


class NotFound(Exception):
    pass


@contextmanager
def admit(kind: str):
    """Admission control BEFORE any backend I/O: over the limit -> immediate Busy (HTTP 503), never queueing
    behind a slow backend. Revocation has its own reserved slots."""
    sem = _admission[kind]
    if not sem.acquire(blocking=False):
        raise Busy(f"too many concurrent {kind} operations")
    try:
        yield
    finally:
        sem.release()


def _begin(db_type: DbType, grant_id: str):
    lock = _db_locks[db_type]
    if not lock.acquire(timeout=60):
        raise Busy(f"another {db_type.value} operation is taking too long")
    with _inflight_lock:
        _inflight.add(grant_id)
    return lock


def _end(lock, grant_id: str) -> None:
    with _inflight_lock:
        _inflight.discard(grant_id)
    lock.release()


def validate_ttl(ttl: int) -> None:
    if not config.TTL_MIN <= ttl <= config.TTL_MAX:
        raise ValueError(f"ttl_seconds must be between {config.TTL_MIN} and {config.TTL_MAX}")


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def public(g: dict[str, Any]) -> dict[str, Any]:
    """What the API/UI may show about a grant: no credentials exist in the store, and no Vault ids."""
    return {
        "grant_id": g["id"],
        "db_type": g["db_type"],
        "scope": g["scope"],
        "tables": g["tables"],
        "commands": g["commands"],
        "requested_for": g["requested_for"],
        "issued_by": g["issued_by"],
        "ttl_seconds": g["ttl_seconds"],
        "status": g["status"],
        "username": g["username"],
        "created_at": iso(g["created_at"]),
        "expires_at": iso(g["expires_at"]),
    }


def issue(req: GrantRequest, actor: str, request_id: str) -> dict[str, Any]:
    """Returns the public grant plus the one-time `password`. Nothing secret is persisted."""
    validate_ttl(req.ttl_seconds)
    cat = db_introspect.catalog(req.db_type)
    creation, revocation = build_statements(
        req.db_type, req.scope, req.tables, req.commands, set(cat.tables), cat.sequences
    )
    creation = faults.mutate_statements(creation)
    grant_id = store.new_grant_id()
    lock = _begin(req.db_type, grant_id)
    try:
        store.insert_grant(
            {
                "id": grant_id,
                "db_type": req.db_type.value,
                "scope": req.scope.value,
                "tables": req.tables if req.scope.value == "tables" else [],
                "commands": req.commands,
                "requested_for": req.requested_for,
                "issued_by": actor,
                "ttl_seconds": req.ttl_seconds,
            }
        )
        try:
            vault_client.write_role(grant_id, req.db_type, creation, revocation, req.ttl_seconds)
            faults.point("after_role_create")
            token, accessor = vault_client.create_grant_token(req.ttl_seconds, grant_id)
            faults.point("after_token_create")  # the accessor is not stored yet: recovery finds it by name
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


def _run(db_type: DbType, grant_id: str, statements: list[str]) -> None:
    if statements:
        vault_client.run_as_manager(db_type, f"{grant_id}_h{secrets.token_hex(2)}", statements)


def _lock_out_and_terminate(db_type: DbType, account: str, grant_id: str) -> None:
    """PostgreSQL: committed NOLOGIN first, then terminate backends until pg_stat_activity shows none.
    (ClickHouse: DROP USER is immediate and also ends open sessions.)"""
    if db_type != DbType.postgres:
        return
    _run(db_type, grant_id, statement_builder.lockout_statements(db_type, account))
    deadline = time.time() + 20
    while db_introspect.pg_backends(account) > 0:
        if time.time() > deadline:
            raise RuntimeError(f"backends of {account} still alive after termination attempts")
        _run(db_type, grant_id, statement_builder.terminate_statements(db_type, account))
        time.sleep(0.3)


def _teardown(
    grant_id: str, final: Status, request_id: str | None, actor: str = "system", raise_errors: bool = False
) -> None:
    """Idempotent cleanup; anything already gone counts as done. Order:
    find the grant's token(s) and DB accounts -> committed lockout + confirmed session termination ->
    synchronous lease revoke (Vault runs the DB revocation statements) -> confirm the accounts are gone
    (drop them as the manager if not, e.g. a partial CREATE USER with no lease) -> revoke token -> delete role.
    On any failure the row stays `revoking` and the reconciler retries."""
    g = store.get_grant(grant_id)
    if g is None:
        return
    db = DbType(g["db_type"])
    try:
        accessors = {g["token_accessor"]} if g["token_accessor"] else set()
        if not g["token_accessor"]:  # the create-token response may have been lost
            accessors |= set(vault_client.find_token_accessors(grant_id))
        accounts = db_introspect.find_accounts(db, grant_id)
        for account in accounts:
            _lock_out_and_terminate(db, account, grant_id)
        leases = set(vault_client.list_leases(grant_id))
        if g["lease_id"]:
            leases.add(g["lease_id"])
        for lease in sorted(leases):
            vault_client.revoke_lease(lease)
        for account in db_introspect.find_accounts(db, grant_id):
            _lock_out_and_terminate(db, account, grant_id)
            _run(db, grant_id, statement_builder.drop_statements(db, account))
        left = db_introspect.find_accounts(db, grant_id)
        if left:
            raise RuntimeError(f"accounts still present after cleanup: {left}")
        for accessor in accessors:
            vault_client.revoke_accessor(accessor)
        vault_client.delete_role(grant_id)
    except Exception as exc:  # noqa: BLE001 - recorded and retried by the reconciler
        log.warning("teardown of %s failed: %s: %s", grant_id, type(exc).__name__, exc)  # full text: server log only
        store.update_grant(grant_id, status=Status.revoking.value, last_error=type(exc).__name__)
        store.audit(request_id, grant_id, actor, "teardown", "error", type(exc).__name__)
        if raise_errors:
            raise
        return
    store.update_grant(grant_id, status=final.value, last_error=None)
    store.audit(request_id, grant_id, actor, "teardown", final.value)


def _final_for(g: dict[str, Any], now: float) -> Status | None:
    """What a row needs, decided from its CURRENT state (never from an earlier snapshot)."""
    st = g["status"]
    if st == Status.issuing.value:
        return Status.failed
    if st == Status.revoking.value:
        return Status.revoked
    if st == Status.active.value and g["expires_at"] and now > g["expires_at"] + 15:
        return Status.expired
    return None


def reconcile_one(grant_id: str) -> None:
    g = store.get_grant(grant_id)
    if g is None:
        return
    lock = _begin(DbType(g["db_type"]), grant_id)
    try:
        fresh = store.get_grant(grant_id)  # re-read under the lock: an in-flight issue may have finished
        final = _final_for(fresh, time.time()) if fresh else None
        if final:
            _teardown(grant_id, final, None)
    finally:
        _end(lock, grant_id)


def reconcile_once() -> None:
    """Retry anything left half-done and finish expired grants. Safe to run at any time."""
    now = time.time()
    for g in store.list_by_status((Status.issuing.value, Status.revoking.value, Status.active.value)):
        with _inflight_lock:
            if g["id"] in _inflight:
                continue
        if _final_for(g, now) is not None:
            try:
                reconcile_one(g["id"])
            except Exception:  # noqa: BLE001
                log.exception("reconcile of %s failed", g["id"])
    for sess in store.purge_sessions():
        vault_client.revoke_token_quietly(sess["vault_token"])
    _report_orphans()


def _report_orphans() -> None:
    """DB accounts with our prefix that no live grant explains."""
    rows = store.list_by_status((Status.active.value, Status.revoking.value, Status.issuing.value))
    if any(g["status"] == Status.issuing.value for g in rows):
        return
    live = {g["username"] for g in rows if g["username"]}
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
