import time

import pytest
from app import preflight, store
from app.models import GrantRequest
from pydantic import ValidationError

OK = {
    "db_type": "postgres",
    "scope": "tables",
    "tables": ["customers"],
    "commands": ["SELECT"],
    "ttl_seconds": 60,
    "requested_for": "alice",
}


def test_grant_request_accepts_valid_payload():
    assert GrantRequest.model_validate(OK).ttl_seconds == 60


@pytest.mark.parametrize(
    "patch",
    [
        {"allow_create": True},  # option removed in v0.1: unknown fields are rejected
        {"credential_type": "token"},
        {"ttl_seconds": "60"},
        {"ttl_seconds": True},
        {"ttl_seconds": "abc"},
        {"ttl_seconds": 1.5},
        {"requested_for": "  "},
        {"requested_for": "a\nb"},
        {"commands": []},
        {"db_type": "mysql"},
    ],
)
def test_grant_request_rejects(patch):
    with pytest.raises(ValidationError):
        GrantRequest.model_validate({**OK, **patch})


GOOD_ENV = {k: "x" * 24 for k in preflight.REQUIRED_SECRETS} | {"VDBA_ADMIN_USER": "admin"}


def test_preflight_accepts_real_values():
    assert preflight.problems(GOOD_ENV) == []


@pytest.mark.parametrize("bad", ["", "changeme", "xxxCHANGEMExxxxxxxxxxxxxx", "short"])
def test_preflight_refuses_placeholders(bad):
    for name in preflight.REQUIRED_SECRETS:
        assert preflight.problems({**GOOD_ENV, name: bad}), name


@pytest.mark.parametrize("bad", ["a" * 16 + "'", "a" * 16 + "\\", "a" * 16 + " x", "a" * 16 + "$(id)", "a" * 16 + ";"])
def test_preflight_rejects_characters_that_need_sql_quoting(bad):
    assert preflight.problems({**GOOD_ENV, "CLICKHOUSE_MANAGER_PASSWORD": bad})


def test_preflight_requires_every_secret():
    for name in preflight.REQUIRED_SECRETS:
        env = {k: v for k, v in GOOD_ENV.items() if k != name}
        assert preflight.problems(env), name


def test_store_staged_grant_and_sessions(tmp_path):
    store.init(str(tmp_path / "t.sqlite3"))
    gid = store.new_grant_id()
    store.insert_grant(
        {
            "id": gid,
            "db_type": "postgres",
            "scope": "tables",
            "tables": ["a"],
            "commands": ["SELECT"],
            "requested_for": "x",
            "issued_by": "admin",
            "ttl_seconds": 30,
        }
    )
    assert store.get_grant(gid)["status"] == "issuing"
    store.update_grant(gid, status="active", username="u", lease_id="l", expires_at=time.time() + 30)
    g = store.get_grant(gid)
    assert g["status"] == "active" and g["tables"] == ["a"]
    assert not any(k in g for k in ("password", "vault_token"))
    assert store.list_by_status(("active",))[0]["id"] == gid  # nothing secret has a column
    sid, csrf = store.create_session("admin", "tok")
    assert store.get_session(sid)["csrf"] == csrf
    assert sid not in str(dict(store._conn.execute("SELECT * FROM sessions").fetchone()))  # only the hash is stored
    store.delete_session(sid)
    assert store.get_session(sid) is None
    store.audit("r1", gid, "admin", "issue", "ok", "x")
    assert store.audit_exists("issue", "x")
