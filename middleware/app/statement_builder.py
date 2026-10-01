"""Builds the fixed SQL templates stored in Vault roles.

Only validated identifiers and enum commands ever reach the SQL; nothing the admin types is
interpolated. `{{name}}`, `{{password}}`, `{{expiration}}` are Vault placeholders.
"""

import re

from . import config
from .models import DbType, Scope

IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")


def valid_identifier(name: str) -> str:
    # fullmatch, not match: "$" in a regex accepts a trailing newline (ClickHouse LF-spoofing).
    if not isinstance(name, str) or not IDENTIFIER_RE.fullmatch(name):
        raise ValueError(f"invalid identifier: {name!r}")
    return name


def _commands(commands: list[str], allowed: list[str]) -> str:
    if not commands:
        raise ValueError("at least one command must be selected")
    for cmd in commands:
        if cmd not in allowed:
            raise ValueError(f"command not allowed: {cmd!r}")
    return ", ".join(dict.fromkeys(commands))


def _tables(scope: Scope, tables: list[str], known: set[str]) -> list[str]:
    """Table-scoped = the listed tables; database-scoped = every table that exists right now."""
    if scope == Scope.database:
        chosen = sorted(known)
        if not chosen:
            raise ValueError("no tables exist in the target schema")
    else:
        chosen = list(dict.fromkeys(tables))
        if not chosen:
            raise ValueError("at least one table must be selected for table-scoped access")
    for t in chosen:
        valid_identifier(t)
        if t not in known:
            raise ValueError(f"unknown table: {t!r}")
    return chosen


def build_postgres_statements(
    scope: Scope,
    tables: list[str],
    commands: list[str],
    known_tables: set[str],
    sequences: dict[str, list[str]],
) -> tuple[list[str], list[str]]:
    cmds = _commands(commands, config.ALLOWED_POSTGRES_COMMANDS)
    chosen = _tables(scope, tables, known_tables)
    statements = [
        "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' CONNECTION LIMIT 5;",
        f'GRANT CONNECT ON DATABASE "{config.POSTGRES_DB}" TO "{{{{name}}}}";',
        'GRANT USAGE ON SCHEMA "public" TO "{{name}}";',
    ]
    for t in chosen:
        statements.append(f'GRANT {cmds} ON TABLE "public"."{t}" TO "{{{{name}}}}";')
    if "INSERT" in cmds:
        # Only sequences OWNED BY the granted tables (serial/identity defaults), never others.
        for t in chosen:
            for seq in sequences.get(t, []):
                valid_identifier(seq)
                statements.append(f'GRANT USAGE ON SEQUENCE "public"."{seq}" TO "{{{{name}}}}";')
    revocation = [
        "SET LOCAL lock_timeout = '5s';",
        "SET LOCAL statement_timeout = '20s';",
        'ALTER ROLE "{{name}}" NOLOGIN;',
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}';",
        'DROP OWNED BY "{{name}}";',
        'DROP ROLE IF EXISTS "{{name}}";',
    ]
    return statements, revocation


def build_clickhouse_statements(
    scope: Scope, tables: list[str], commands: list[str], known_tables: set[str]
) -> tuple[list[str], list[str]]:
    cmds = _commands(commands, config.ALLOWED_CLICKHOUSE_COMMANDS)
    chosen = _tables(scope, tables, known_tables)
    statements = [
        "CREATE USER '{{name}}' IDENTIFIED WITH sha256_password BY '{{password}}' VALID UNTIL '{{expiration}}';"
    ]
    for t in chosen:
        statements.append(f"GRANT {cmds} ON `{config.CLICKHOUSE_DB}`.`{t}` TO '{{{{name}}}}';")
    revocation = [
        "DROP USER IF EXISTS '{{name}}';",
    ]
    return statements, revocation


def build_statements(
    db_type: DbType,
    scope: Scope,
    tables: list[str],
    commands: list[str],
    known_tables: set[str],
    sequences: dict[str, list[str]] | None = None,
) -> tuple[list[str], list[str]]:
    if db_type == DbType.postgres:
        return build_postgres_statements(scope, tables, commands, known_tables, sequences or {})
    return build_clickhouse_statements(scope, tables, commands, known_tables)


# ---- fixed maintenance statements, run as the DB manager through Vault (vault_client.run_as_manager) ----
ACCOUNT_RE = re.compile(r"vdba_[0-9a-f]{10}_[a-z0-9]{6}")


def valid_account(name: str) -> str:
    if not ACCOUNT_RE.fullmatch(name):
        raise ValueError(f"invalid account name: {name!r}")
    return name


def lockout_statements(db_type: DbType, account: str) -> list[str]:
    """Committed lockout: no new logins. (ClickHouse needs no separate step: DROP USER is immediate.)"""
    valid_account(account)
    if db_type == DbType.postgres:
        return ["SET LOCAL lock_timeout = '3s';", f'ALTER ROLE "{account}" NOLOGIN;']
    return []


def terminate_statements(db_type: DbType, account: str) -> list[str]:
    valid_account(account)
    if db_type == DbType.postgres:
        return [f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{account}';"]  # noqa: S608 - validated
    return []


def drop_statements(db_type: DbType, account: str) -> list[str]:
    valid_account(account)
    if db_type == DbType.postgres:
        return [
            "SET LOCAL lock_timeout = '5s';",
            f'DROP OWNED BY "{account}";',
            f'DROP ROLE IF EXISTS "{account}";',
        ]
    return [f"DROP USER IF EXISTS '{account}';"]
