import re

from . import config
from .models import DbType, Scope

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_identifier(name: str) -> str:
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"invalid identifier: {name!r}")
    return name


def _validate_commands(commands: list[str], allowed: list[str]) -> list[str]:
    if not commands:
        raise ValueError("at least one command must be selected")
    for cmd in commands:
        if cmd not in allowed:
            raise ValueError(f"command not allowed: {cmd!r}")
    return commands


def build_postgres_statements(
    scope: Scope, tables: list[str], commands: list[str], allow_create: bool, known_tables: set[str]
) -> tuple[list[str], list[str]]:
    commands = _validate_commands(commands, config.ALLOWED_POSTGRES_COMMANDS)
    commands_sql = ", ".join(commands)

    statements = [
        'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\';',
        f'GRANT CONNECT ON DATABASE {config.POSTGRES_DB} TO "{{{{name}}}}";',
        'GRANT USAGE ON SCHEMA public TO "{{name}}";',
    ]

    if scope == Scope.database:
        if not known_tables:
            raise ValueError("no tables exist in the target schema")
        statements.append(f'GRANT {commands_sql} ON ALL TABLES IN SCHEMA public TO "{{{{name}}}}";')
    else:
        if not tables:
            raise ValueError("at least one table must be selected for table-scoped access")
        for table in tables:
            _validate_identifier(table)
            if table not in known_tables:
                raise ValueError(f"unknown table: {table!r}")
            statements.append(f'GRANT {commands_sql} ON "{table}" TO "{{{{name}}}}";')

    if "INSERT" in commands:
        # SERIAL/IDENTITY default values need sequence usage, not just table access.
        statements.append('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{name}}";')

    if allow_create:
        statements.append('GRANT CREATE ON SCHEMA public TO "{{name}}";')

    revocation_statements = [
        'DROP OWNED BY "{{name}}";',
        'DROP ROLE IF EXISTS "{{name}}";',
    ]
    return statements, revocation_statements


def build_clickhouse_statements(
    scope: Scope, tables: list[str], commands: list[str], allow_create: bool, known_tables: set[str]
) -> tuple[list[str], list[str]]:
    commands = _validate_commands(commands, config.ALLOWED_CLICKHOUSE_COMMANDS)
    commands_sql = ", ".join(commands)

    statements = ["CREATE USER '{{name}}' IDENTIFIED BY '{{password}}';"]

    if scope == Scope.database:
        if not known_tables:
            raise ValueError("no tables exist in the target schema")
        statements.append(f"GRANT {commands_sql} ON {config.CLICKHOUSE_DB}.* TO '{{{{name}}}}';")
    else:
        if not tables:
            raise ValueError("at least one table must be selected for table-scoped access")
        for table in tables:
            _validate_identifier(table)
            if table not in known_tables:
                raise ValueError(f"unknown table: {table!r}")
            statements.append(f"GRANT {commands_sql} ON {config.CLICKHOUSE_DB}.{table} TO '{{{{name}}}}';")

    if allow_create:
        statements.append(f"GRANT CREATE TABLE ON {config.CLICKHOUSE_DB}.* TO '{{{{name}}}}';")
        statements.append(f"GRANT DROP TABLE ON {config.CLICKHOUSE_DB}.* TO '{{{{name}}}}';")

    revocation_statements = ["DROP USER IF EXISTS '{{name}}';"]
    return statements, revocation_statements


def build_statements(
    db_type: DbType, scope: Scope, tables: list[str], commands: list[str], allow_create: bool, known_tables: set[str]
) -> tuple[list[str], list[str]]:
    if db_type == DbType.postgres:
        return build_postgres_statements(scope, tables, commands, allow_create, known_tables)
    return build_clickhouse_statements(scope, tables, commands, allow_create, known_tables)
