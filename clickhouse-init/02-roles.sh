#!/bin/bash
# Runs once on first start of the ClickHouse container. Creates the SQL-managed (not XML)
# manager account Vault connects as, so its password can be set from .env and rotated by Vault,
# plus a read-only introspection account. Passwords come from the environment.
set -euo pipefail

# Passwords are placed inside SQL string literals: escape \ and ' (preflight also restricts them to
# [A-Za-z0-9_-], so this is defence in depth).
esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"; }
MGR_PW=$(esc "$VDBA_CH_MANAGER_PASSWORD")
INTRO_PW=$(esc "$VDBA_CH_INTROSPECT_PASSWORD")

clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery <<SQL
CREATE USER vault_manager IDENTIFIED WITH sha256_password BY '${MGR_PW}';
-- Only what the issue/revoke/rotate cycle needs. NOTE: CREATE/ALTER/DROP USER are global in
-- ClickHouse (they cannot be limited to our users); see SECURITY notes in the README.
GRANT CREATE USER, ALTER USER, DROP USER ON *.* TO vault_manager;
GRANT SELECT, INSERT, ALTER UPDATE, ALTER DELETE ON appdb.* TO vault_manager WITH GRANT OPTION;
-- lets setup's least-privilege probe (run AS vault_manager) read the manager's own grants
GRANT SELECT(user_name, access_type) ON system.grants TO vault_manager;

CREATE USER vault_introspect IDENTIFIED WITH sha256_password BY '${INTRO_PW}';
GRANT SHOW TABLES ON appdb.* TO vault_introspect;
GRANT SHOW USERS ON *.* TO vault_introspect;
SQL
