#!/bin/bash
# Runs once on first start of the ClickHouse container. Creates the SQL-managed (not XML)
# manager account Vault connects as, so its password can be set from .env and rotated by Vault,
# plus a read-only introspection account. Passwords come from the environment.
set -euo pipefail

clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery <<SQL
CREATE USER vault_manager IDENTIFIED WITH sha256_password BY '${VDBA_CH_MANAGER_PASSWORD}';
-- Only what the issue/revoke/rotate cycle needs. NOTE: CREATE/ALTER/DROP USER are global in
-- ClickHouse (they cannot be limited to our users); see SECURITY notes in the README.
GRANT CREATE USER, ALTER USER, DROP USER ON *.* TO vault_manager;
GRANT SELECT, INSERT, ALTER UPDATE, ALTER DELETE ON appdb.* TO vault_manager WITH GRANT OPTION;

CREATE USER vault_introspect IDENTIFIED WITH sha256_password BY '${VDBA_CH_INTROSPECT_PASSWORD}';
GRANT SHOW TABLES ON appdb.* TO vault_introspect;
GRANT SHOW USERS ON *.* TO vault_introspect;
SQL
