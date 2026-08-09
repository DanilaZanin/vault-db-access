import uuid

import hvac

from . import config
from .models import DbType


def get_client(token: str) -> hvac.Client:
    return hvac.Client(url=config.VAULT_ADDR, token=token)


def new_role_name() -> str:
    return f"grant-{uuid.uuid4().hex[:10]}"


def create_role(
    client: hvac.Client,
    role_name: str,
    db_type: DbType,
    creation_statements: list[str],
    revocation_statements: list[str],
    ttl_seconds: int,
) -> None:
    connection_name = (
        config.POSTGRES_CONNECTION_NAME if db_type == DbType.postgres else config.CLICKHOUSE_CONNECTION_NAME
    )
    client.write(
        f"database/roles/{role_name}",
        db_name=connection_name,
        creation_statements=creation_statements,
        revocation_statements=revocation_statements,
        default_ttl=f"{ttl_seconds}s",
        max_ttl=f"{ttl_seconds}s",
        credential_type="password",
        credential_config={"password_policy": config.PASSWORD_POLICY_NAME},
    )


def read_credentials(client: hvac.Client, role_name: str) -> dict:
    resp = client.read(f"database/creds/{role_name}")
    return {
        "username": resp["data"]["username"],
        "password": resp["data"]["password"],
        "lease_id": resp["lease_id"],
        "lease_duration": resp["lease_duration"],
    }


def issue_token_grant(client: hvac.Client, role_name: str, ttl_seconds: int) -> dict:
    policy_name = f"read-{role_name}"
    policy_hcl = f'path "database/creds/{role_name}" {{\n  capabilities = ["read"]\n}}\n'
    client.write(f"sys/policies/acl/{policy_name}", policy=policy_hcl)
    token_resp = client.auth.token.create(
        role_name="grant-token-issuer",
        policies=[policy_name],
        ttl=f"{ttl_seconds}s",
        renewable=False,
        display_name=role_name,
    )
    return {"vault_token": token_resp["auth"]["client_token"], "policy_name": policy_name}


def revoke_grant(client: hvac.Client, role_name: str, policy_name: str | None) -> None:
    client.write(f"sys/leases/revoke-prefix/database/creds/{role_name}")
    client.delete(f"database/roles/{role_name}")
    if policy_name:
        client.delete(f"sys/policies/acl/{policy_name}")
