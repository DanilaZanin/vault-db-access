import pytest
from app.models import DbType, Scope
from app.statement_builder import build_statements, valid_identifier

KNOWN = {"customers", "orders", "products"}
SEQS = {"customers": ["customers_id_seq"], "orders": ["orders_id_seq"], "products": ["products_id_seq"]}


def pg(scope, tables, commands, known=KNOWN, seqs=SEQS):
    return build_statements(DbType.postgres, scope, tables, commands, known, seqs)


def ch(scope, tables, commands, known=KNOWN):
    return build_statements(DbType.clickhouse, scope, tables, commands, known)


def test_postgres_table_scoped_select_only():
    creation, revocation = pg(Scope.tables, ["customers"], ["SELECT"])
    assert 'GRANT SELECT ON TABLE "public"."customers" TO "{{name}}";' in creation
    joined = " ".join(creation)
    assert "orders" not in joined and "products" not in joined
    assert not any("SEQUENCE" in s for s in creation)  # SELECT does not need sequences
    assert 'DROP ROLE IF EXISTS "{{name}}";' in revocation


def test_postgres_revocation_locks_out_before_dropping():
    _, revocation = pg(Scope.tables, ["customers"], ["SELECT"])
    assert revocation.index('ALTER ROLE "{{name}}" NOLOGIN;') < 3
    assert "pg_terminate_backend" in revocation[3]
    assert revocation.index('DROP OWNED BY "{{name}}";') < revocation.index('DROP ROLE IF EXISTS "{{name}}";')


def test_postgres_insert_grants_only_owned_sequences():
    creation, _ = pg(Scope.tables, ["customers"], ["SELECT", "INSERT"])
    seq = [s for s in creation if "SEQUENCE" in s]
    assert seq == ['GRANT USAGE ON SEQUENCE "public"."customers_id_seq" TO "{{name}}";']
    assert not any("ALL SEQUENCES" in s for s in creation)


def test_postgres_database_scope_expands_to_existing_tables_only():
    creation, _ = pg(Scope.database, [], ["SELECT"])
    assert not any("ALL TABLES" in s for s in creation)
    for t in KNOWN:
        assert f'GRANT SELECT ON TABLE "public"."{t}" TO "{{{{name}}}}";' in creation


def test_no_create_or_drop_privileges_are_ever_generated():
    for scope in Scope:
        for builder in (pg, ch):
            creation, _ = builder(scope, ["customers"], ["SELECT", "INSERT"])
            text = " ".join(creation).upper()
            assert "CREATE ON" not in text and "DROP TABLE" not in text and "CREATE TABLE" not in text


def test_postgres_role_expires_with_the_lease():
    creation, _ = pg(Scope.tables, ["customers"], ["SELECT"])
    assert "VALID UNTIL '{{expiration}}'" in creation[0]


@pytest.mark.parametrize("builder", [pg, ch])
def test_rejects_unknown_table_command_and_empty(builder):
    with pytest.raises(ValueError):
        builder(Scope.tables, ["not_a_table"], ["SELECT"])
    with pytest.raises(ValueError):
        builder(Scope.tables, ["customers"], ["DROP TABLE"])
    with pytest.raises(ValueError):
        builder(Scope.tables, ["customers"], [])
    with pytest.raises(ValueError):
        builder(Scope.tables, [], ["SELECT"])


@pytest.mark.parametrize("bad", ["customers\n", "customers ", 'a"b', "a`b", "x;DROP", "", "1abc", "a" * 64])
def test_identifier_validation_is_a_fullmatch(bad):
    with pytest.raises(ValueError):
        valid_identifier(bad)
    with pytest.raises(ValueError):
        ch(Scope.tables, [bad], ["SELECT"], known={bad, "customers"})


def test_clickhouse_table_scoped():
    creation, revocation = ch(Scope.tables, ["orders"], ["SELECT"])
    assert "GRANT SELECT ON `appdb`.`orders` TO '{{name}}';" in creation
    assert not any("customers" in s for s in creation)
    assert revocation == ["DROP USER IF EXISTS '{{name}}';"]


def test_clickhouse_user_expires_with_the_lease():
    creation, _ = ch(Scope.tables, ["orders"], ["SELECT"])
    assert "VALID UNTIL '{{expiration}}'" in creation[0]


def test_postgres_vault_side_revocation_is_time_bounded():
    _, revocation = pg(Scope.tables, ["customers"], ["SELECT"])
    assert revocation[0].startswith("SET LOCAL lock_timeout") and revocation[1].startswith(
        "SET LOCAL statement_timeout"
    )


def test_maintenance_statements_only_accept_our_account_names():
    from app.statement_builder import drop_statements, lockout_statements, terminate_statements

    good = "vdba_0123456789_abc123"
    assert 'ALTER ROLE "vdba_0123456789_abc123" NOLOGIN;' in lockout_statements(DbType.postgres, good)
    assert "usename = 'vdba_0123456789_abc123'" in terminate_statements(DbType.postgres, good)[0]
    assert drop_statements(DbType.clickhouse, good) == ["DROP USER IF EXISTS 'vdba_0123456789_abc123';"]
    for bad in ("postgres", "vault_manager", good + "'; DROP", good.upper(), "vdba_0123456789_abc123\n", ""):
        for fn in (lockout_statements, terminate_statements, drop_statements):
            with pytest.raises(ValueError):
                fn(DbType.postgres, bad)
