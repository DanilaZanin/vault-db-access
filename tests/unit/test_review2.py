import json
import shutil
import subprocess
from pathlib import Path

import pytest
from app import config, db_introspect, grants, setup, vault_client
from hvac import exceptions as vexc

ROOT = Path(__file__).resolve().parents[2]


# N3 ---------------------------------------------------------------------------------------------
class FakeService:
    def __init__(self, keys, lookups):
        self.keys, self.lookups = keys, lookups

    def call(self, fn):
        class C:
            def __init__(c, outer):
                c.o = outer

            def list(c, path):
                return {"data": {"keys": c.o.keys}}

            def write(c, path, accessor):
                v = c.o.lookups[accessor]
                if isinstance(v, Exception):
                    raise v
                return {"data": v}

        return fn(C(self))


def test_token_discovery_matches_the_rewritten_display_name(monkeypatch):
    # Vault turns "_" into "-" in display names
    fake = FakeService(["a", "b"], {"a": {"display_name": "token-vdba-0123456789"}, "b": {"display_name": "token-x"}})
    monkeypatch.setattr(vault_client, "service", fake)
    assert vault_client.find_token_accessors("vdba_0123456789") == ["a"]


def test_token_discovery_skips_only_confirmed_gone_accessors(monkeypatch):
    gone = vexc.InvalidRequest("invalid accessor")
    fake = FakeService(["a", "b"], {"a": gone, "b": {"display_name": "token-vdba-0123456789"}})
    monkeypatch.setattr(vault_client, "service", fake)
    assert vault_client.find_token_accessors("vdba_0123456789") == ["b"]


@pytest.mark.parametrize("err", [vexc.InternalServerError("boom"), vexc.Forbidden("nope"), OSError("down")])
def test_token_discovery_errors_are_not_swallowed(monkeypatch, err):
    fake = FakeService(["a", "b"], {"a": err, "b": {"display_name": "x"}})
    monkeypatch.setattr(vault_client, "service", fake)
    with pytest.raises(type(err)):
        vault_client.find_token_accessors("vdba_0123456789")


def test_truncated_token_listing_is_not_declared_complete(monkeypatch):
    keys = [f"k{i}" for i in range(vault_client.MAX_ACCESSOR_SCAN + 1)]
    monkeypatch.setattr(vault_client, "service", FakeService(keys, {}))
    with pytest.raises(RuntimeError, match="cannot confirm"):
        vault_client.find_token_accessors("vdba_0123456789")


# N5 / N6 ----------------------------------------------------------------------------------------
def test_pg_tls_settings_reach_the_introspection_connection(monkeypatch):
    monkeypatch.setattr(config, "PG_SSLMODE", "verify-full")
    monkeypatch.setattr(config, "PG_SSLROOTCERT", "/certs/ca.pem")
    kw = db_introspect.pg_ssl_kwargs()
    assert kw == {"sslmode": "verify-full", "sslrootcert": "/certs/ca.pem"}


def test_clickhouse_tls_settings_reach_the_introspection_client(monkeypatch):
    monkeypatch.setattr(config, "CH_SECURE", True)
    monkeypatch.setattr(config, "CH_CA_CERT", "/certs/ca.pem")
    kw = db_introspect.ch_ssl_kwargs()
    assert kw["secure"] is True and kw["verify"] is True and kw["ca_cert"] == "/certs/ca.pem"


@pytest.mark.parametrize("mode", ["disable", "allow", "prefer"])
def test_weak_sslmode_needs_the_insecure_flag(monkeypatch, mode):
    monkeypatch.setenv("VDBA_PG_SSLMODE", mode)
    monkeypatch.delenv("VDBA_PG_SSLROOTCERT", raising=False)
    monkeypatch.setenv("VDBA_ALLOW_INSECURE", "0")
    with pytest.raises(SystemExit):
        setup.pg_sslmode()
    monkeypatch.setenv("VDBA_ALLOW_INSECURE", "1")
    assert setup.pg_sslmode() == mode


def test_sslmode_is_validated_and_strong_modes_pass(monkeypatch):
    monkeypatch.setenv("VDBA_ALLOW_INSECURE", "0")
    monkeypatch.setenv("VDBA_PG_SSLMODE", "bogus")
    with pytest.raises(SystemExit):
        setup.pg_sslmode()
    monkeypatch.setenv("VDBA_PG_SSLMODE", "require")
    assert setup.pg_sslmode() == "require"
    monkeypatch.delenv("VDBA_PG_SSLMODE")
    monkeypatch.setenv("VDBA_PG_SSLROOTCERT", "/ca.pem")
    assert setup.pg_sslmode() == "verify-full"


# N7 ---------------------------------------------------------------------------------------------
def _compose_config(env, *files):
    args = ["docker", "compose", *[x for f in files for x in ("-f", f)], "config", "--format", "json"]
    out = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False, env=env)  # noqa: S603
    assert out.returncode == 0, f"docker compose config failed ({out.returncode}): {out.stderr}"
    return json.loads(out.stdout)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_production_settings_reach_the_middleware_container():
    import os

    env = {
        **os.environ,
        "VDBA_PUBLIC_ORIGIN": "https://vdba.example",
        "VDBA_COOKIE_SECURE": "1",
        "VDBA_ALLOWED_ORIGINS": "https://other.example",
        "VDBA_PG_SSLMODE": "verify-full",
        "VDBA_PG_SSLROOTCERT": "/certs/ca.pem",
        "VDBA_CH_SECURE": "1",
        "VDBA_CH_CA_CERT": "/certs/ch-ca.pem",
    }
    mw = _compose_config(env, "docker-compose.yml")["services"]["middleware"]["environment"]
    for key, value in [
        ("VDBA_PUBLIC_ORIGIN", "https://vdba.example"),
        ("VDBA_COOKIE_SECURE", "1"),
        ("VDBA_ALLOWED_ORIGINS", "https://other.example"),
        ("VDBA_PG_SSLMODE", "verify-full"),
        ("VDBA_PG_SSLROOTCERT", "/certs/ca.pem"),
        ("VDBA_CH_SECURE", "1"),
        ("VDBA_CH_CA_CERT", "/certs/ch-ca.pem"),
    ]:
        assert mw.get(key) == value, key


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_release_override_runs_exactly_the_verified_digests():
    import os

    d1, d2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    env = {**os.environ, "VDBA_VERSION": "v0.1.0", "VDBA_MIDDLEWARE_DIGEST": d1, "VDBA_VAULT_DIGEST": d2}
    svc = _compose_config(env, "docker-compose.yml", "compose.release.yml")["services"]
    assert svc["middleware"]["image"].endswith(f"@{d1}") and svc["vault"]["image"].endswith(f"@{d2}")
    assert "build" not in svc["middleware"] and "build" not in svc["vault"]
    env = {k: v for k, v in env.items() if "DIGEST" not in k}
    assert _compose_config(env, "docker-compose.yml", "compose.release.yml")["services"]["vault"]["image"].endswith(
        ":v0.1.0"
    )


# N8 ---------------------------------------------------------------------------------------------
def test_dockerfile_does_not_mask_failures():
    text = (ROOT / "middleware" / "Dockerfile").read_text()
    assert "; true" not in text and "|| true" not in text


# Sol 11 -----------------------------------------------------------------------------------------
def test_admission_limits_leave_threads_for_revocation():
    total = sum(s._initial_value for s in grants._admission.values())  # noqa: SLF001
    assert total < 40, "anyio's default threadpool has 40 threads: the admission limits must leave spare ones"
    assert "session" in grants._admission and "revoke" in grants._admission  # noqa: SLF001


# the settings must be USED, not just defined -------------------------------------------------------
def test_db_connections_pass_the_ssl_kwargs(monkeypatch):
    seen = {}
    monkeypatch.setattr(vault_client, "introspect_credentials", lambda db: ("u", "p"))
    monkeypatch.setattr(config, "PG_SSLMODE", "verify-full")
    monkeypatch.setattr(config, "PG_SSLROOTCERT", "/ca.pem")
    monkeypatch.setattr(config, "CH_SECURE", True)
    monkeypatch.setattr(config, "CH_CA_CERT", "/ch-ca.pem")
    monkeypatch.setattr(db_introspect.psycopg, "connect", lambda **kw: seen.setdefault("pg", kw))
    monkeypatch.setattr(db_introspect.clickhouse_connect, "get_client", lambda **kw: seen.setdefault("ch", kw))
    db_introspect._pg_connect()  # noqa: SLF001
    db_introspect._ch_client()  # noqa: SLF001
    assert seen["pg"]["sslmode"] == "verify-full" and seen["pg"]["sslrootcert"] == "/ca.pem"
    assert seen["ch"]["secure"] is True and seen["ch"]["verify"] is True and seen["ch"]["ca_cert"] == "/ch-ca.pem"


@pytest.mark.parametrize("mode", ["disable", "allow", "prefer", "bogus"])
def test_middleware_config_rejects_weak_or_unknown_sslmode(monkeypatch, mode):
    monkeypatch.setattr(config, "PG_SSLMODE", mode)
    monkeypatch.setattr(config, "ALLOW_INSECURE", False)
    with pytest.raises(SystemExit):
        config.check_transport()
    if mode != "bogus":
        monkeypatch.setattr(config, "ALLOW_INSECURE", True)
        config.check_transport()
