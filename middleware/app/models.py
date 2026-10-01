import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator


class DbType(StrEnum):
    postgres = "postgres"
    clickhouse = "clickhouse"


class Scope(StrEnum):
    database = "database"
    tables = "tables"


class Status(StrEnum):
    issuing = "issuing"
    active = "active"
    revoking = "revoking"
    revoked = "revoked"
    expired = "expired"
    failed = "failed"


TERMINAL = {Status.revoked, Status.expired, Status.failed}
_PRINTABLE = re.compile(r"[^\x00-\x1f\x7f]+")


class GrantRequest(BaseModel):
    """Password grants only. Unknown fields (e.g. the removed allow_create) are rejected."""

    model_config = ConfigDict(extra="forbid")

    db_type: DbType
    scope: Scope
    tables: list[str] = Field(default_factory=list, max_length=200)
    commands: list[str] = Field(min_length=1, max_length=8)
    ttl_seconds: StrictInt
    requested_for: str = Field(min_length=1, max_length=120)

    @field_validator("requested_for")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.strip()
        if not v or not _PRINTABLE.fullmatch(v):
            raise ValueError("must be non-empty printable text")
        return v
