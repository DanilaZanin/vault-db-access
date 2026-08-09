import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "middleware"))

from app.models import DbType, Scope  # noqa: E402
from app.statement_builder import build_statements  # noqa: E402

KNOWN = {"customers", "orders", "products"}


def test_postgres_table_scoped_select_only():
    creation, revocation = build_statements(DbType.postgres, Scope.tables, ["customers"], ["SELECT"], False, KNOWN)
    joined = " ".join(creation)
    assert 'GRANT SELECT ON "customers" TO "{{name}}";' in creation
    assert "orders" not in joined
    assert "products" not in joined
    assert 'DROP ROLE IF EXISTS "{{name}}";' in revocation


def test_postgres_whole_db_multi_command():
    creation, _ = build_statements(DbType.postgres, Scope.database, [], ["SELECT", "INSERT"], False, KNOWN)
    assert 'GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO "{{name}}";' in creation


def test_postgres_allow_create_grants_schema_create():
    creation, _ = build_statements(DbType.postgres, Scope.database, [], ["SELECT"], True, KNOWN)
    assert 'GRANT CREATE ON SCHEMA public TO "{{name}}";' in creation


def test_postgres_no_create_grant_when_not_allowed():
    creation, _ = build_statements(DbType.postgres, Scope.tables, ["customers"], ["SELECT"], False, KNOWN)
    assert not any("CREATE ON SCHEMA" in s for s in creation)


def test_postgres_rejects_unknown_table():
    with pytest.raises(ValueError):
        build_statements(DbType.postgres, Scope.tables, ["not_a_table"], ["SELECT"], False, KNOWN)


def test_postgres_rejects_bad_command():
    with pytest.raises(ValueError):
        build_statements(DbType.postgres, Scope.tables, ["customers"], ["DROP TABLE"], False, KNOWN)


def test_postgres_rejects_empty_commands():
    with pytest.raises(ValueError):
        build_statements(DbType.postgres, Scope.tables, ["customers"], [], False, KNOWN)


def test_clickhouse_table_scoped():
    creation, revocation = build_statements(DbType.clickhouse, Scope.tables, ["orders"], ["SELECT"], False, KNOWN)
    assert "GRANT SELECT ON appdb.orders TO '{{name}}';" in creation
    assert "DROP USER IF EXISTS '{{name}}';" in revocation


def test_clickhouse_allow_create_grants_drop_too():
    creation, _ = build_statements(DbType.clickhouse, Scope.database, [], ["SELECT"], True, KNOWN)
    assert any("CREATE TABLE" in s for s in creation)
    assert any("DROP TABLE" in s for s in creation)


def test_clickhouse_rejects_unknown_table():
    with pytest.raises(ValueError):
        build_statements(DbType.clickhouse, Scope.tables, ["bogus"], ["SELECT"], False, KNOWN)
