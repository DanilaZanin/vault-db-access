from dataclasses import dataclass
from enum import Enum


class DbType(str, Enum):
    postgres = "postgres"
    clickhouse = "clickhouse"


class Scope(str, Enum):
    database = "database"
    tables = "tables"


class CredentialType(str, Enum):
    password = "password"
    token = "token"


@dataclass
class GrantRequest:
    db_type: DbType
    scope: Scope
    tables: list[str]
    commands: list[str]
    allow_create: bool
    credential_type: CredentialType
    ttl_seconds: int
    requested_for: str


@dataclass
class IssuedGrant:
    role_name: str
    db_type: str
    scope: str
    tables: list[str]
    commands: list[str]
    allow_create: bool
    credential_type: str
    ttl_seconds: int
    created_at: str
    requested_for: str
    issued_by: str
    username: str | None = None
    password: str | None = None
    vault_token: str | None = None
    policy_name: str | None = None
