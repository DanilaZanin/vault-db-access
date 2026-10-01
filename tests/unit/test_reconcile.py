import time

import pytest
from app import grants, store
from app.models import Status


@pytest.fixture
def db(tmp_path, monkeypatch):
    store.init(str(tmp_path / "t.sqlite3"))
    calls = []
    monkeypatch.setattr(grants, "_teardown", lambda gid, final, rid, **kw: calls.append((gid, final)))
    return calls


def new(status, expires_in=3600):
    gid = store.new_grant_id()
    store.insert_grant({"id": gid, "db_type": "postgres", "scope": "tables", "tables": [], "commands": ["SELECT"],
                        "requested_for": "x", "issued_by": "a", "ttl_seconds": 30})  # fmt: skip
    store.update_grant(gid, status=status, expires_at=time.time() + expires_in)
    return gid


def test_reconciler_decides_from_fresh_state_not_the_snapshot(db, monkeypatch):
    gid = new("issuing")
    stale = store.get_grant(gid)  # what the reconciler saw ...
    store.update_grant(gid, status=Status.active.value)  # ... before the issue finished and became active
    monkeypatch.setattr(store, "list_by_status", lambda statuses: [stale])
    monkeypatch.setattr(grants, "_report_orphans", lambda: None)
    grants.reconcile_once()
    assert db == [], "an active grant must never be torn down because of a stale 'issuing' snapshot"
    assert store.get_grant(gid)["status"] == "active"


def test_reconciler_handles_each_state(db):
    a, b, c = new("issuing"), new("revoking"), new("active", expires_in=-60)
    d = new("active", expires_in=600)
    for gid in (a, b, c, d):
        grants.reconcile_one(gid)
    assert db == [(a, Status.failed), (b, Status.revoked), (c, Status.expired)]


def test_old_rows_are_found_without_a_global_limit(tmp_path):
    store.init(str(tmp_path / "t.sqlite3"))
    old = new("revoking")
    store.update_grant(old)  # touch
    for _ in range(1100):
        gid = store.new_grant_id()
        store.insert_grant({"id": gid, "db_type": "postgres", "scope": "tables", "tables": [], "commands": ["SELECT"],
                            "requested_for": "x", "issued_by": "a", "ttl_seconds": 30})  # fmt: skip
        store.update_grant(gid, status="revoked")
    assert [g["id"] for g in store.list_by_status(("revoking",))] == [old]


def test_admission_limit_is_immediate_and_per_kind():
    held = []
    try:
        for _ in range(grants.config.MAX_AUTH_OPS):
            cm = grants.admit("auth")
            cm.__enter__()
            held.append(cm)
        with pytest.raises(grants.Busy), grants.admit("auth"):
            pass
        with grants.admit("revoke"):  # other kinds keep their own slots
            pass
    finally:
        for cm in held:
            cm.__exit__(None, None, None)
