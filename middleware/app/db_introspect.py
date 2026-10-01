"""Read-only catalog lookups with the dedicated introspection accounts (credentials come from
Vault KV, read by the service identity). These accounts have no access to table data."""

from dataclasses import dataclass, field

import clickhouse_connect
import psycopg

from . import config, vault_client
from .models import DbType
from .statement_builder import IDENTIFIER_RE


@dataclass
class Catalog:
    tables: list[str]
    sequences: dict[str, list[str]] = field(default_factory=dict)  # table -> owned sequences


def _ok(names: list[str]) -> list[str]:
    # Names that are not plain identifiers (e.g. with a newline) can never be granted from the UI.
    return [n for n in names if IDENTIFIER_RE.fullmatch(n)]


def _pg_connect() -> psycopg.Connection:
    user, password = vault_client.introspect_credentials(DbType.postgres)
    return psycopg.connect(
        host=config.POSTGRES_HOST,
        port=config.POSTGRES_PORT,
        user=user,
        password=password,
        dbname=config.POSTGRES_DB,
        connect_timeout=config.DB_TIMEOUT,
        autocommit=True,
        options=f"-c statement_timeout={config.DB_TIMEOUT * 1000}",
    )


def _ch_client():
    user, password = vault_client.introspect_credentials(DbType.clickhouse)
    return clickhouse_connect.get_client(
        host=config.CLICKHOUSE_HOST,
        port=config.CLICKHOUSE_HTTP_PORT,
        username=user,
        password=password,
        connect_timeout=config.DB_TIMEOUT,
        send_receive_timeout=config.DB_TIMEOUT,
    )


_SEQ_SQL = """
SELECT t.relname, s.relname
FROM pg_class s
JOIN pg_depend d ON d.objid = s.oid AND d.classid = 'pg_class'::regclass
                AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')
JOIN pg_class t ON t.oid = d.refobjid
WHERE s.relkind = 'S' AND t.relkind IN ('r', 'p') AND t.relnamespace = 'public'::regnamespace
"""


def postgres_catalog() -> Catalog:
    with _pg_connect() as conn:
        tables = _ok(
            [
                r[0]
                for r in conn.execute(
                    "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public' ORDER BY tablename"
                ).fetchall()
            ]
        )
        seqs: dict[str, list[str]] = {}
        for table, seq in conn.execute(_SEQ_SQL).fetchall():
            if table in tables and IDENTIFIER_RE.fullmatch(seq):
                seqs.setdefault(table, []).append(seq)
    return Catalog(tables, seqs)


def clickhouse_catalog() -> Catalog:
    res = _ch_client().query(
        "SELECT name FROM system.tables WHERE database = %(db)s AND NOT is_temporary ORDER BY name",
        parameters={"db": config.CLICKHOUSE_DB},
    )
    return Catalog(_ok([r[0] for r in res.result_rows]))


def catalog(db_type: DbType) -> Catalog:
    return postgres_catalog() if db_type == DbType.postgres else clickhouse_catalog()


def leftover_users(db_type: DbType) -> list[str]:
    """Database accounts carrying our prefix (used by the reconciler to spot untracked ones)."""
    pattern = config.ROLE_PREFIX.replace("_", r"\_") + "%"
    if db_type == DbType.postgres:
        with _pg_connect() as conn:
            return [r[0] for r in conn.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE %s", (pattern,))]
    res = _ch_client().query("SELECT name FROM system.users WHERE name LIKE %(p)s", parameters={"p": pattern})
    return [r[0] for r in res.result_rows]
