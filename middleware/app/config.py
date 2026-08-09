import os

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vdba-vault:8200")
VAULT_SECRETS_PATH = "/vault-secrets/vault-init.json"
VAULT_PLUGIN_PATH = "/vault-plugins/clickhouse-database-plugin"

# Only used by first_time_setup.py (to seed the initial Vault DB connection and the
# permanent introspection accounts). The running middleware never reads these directly:
# after root-credential rotation only Vault knows the connection password.
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "vdba-postgres")
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))
POSTGRES_SUPERUSER = "postgres"
POSTGRES_SUPERUSER_PASSWORD = os.environ.get("POSTGRES_SUPERUSER_PASSWORD")
POSTGRES_DB = "appdb"

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "vdba-clickhouse")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_HTTP_PORT = int(os.environ.get("CLICKHOUSE_HTTP_PORT", "8123"))
CLICKHOUSE_ADMIN_USER = "vaultadmin"
CLICKHOUSE_ADMIN_PASSWORD = os.environ.get("CLICKHOUSE_VAULTADMIN_PASSWORD")
CLICKHOUSE_DB = "appdb"

# Permanent, never-rotated, minimal-privilege accounts used only to list table names
# for the grant-form pickers. Created once by first_time_setup.py; passwords are
# generated then and stored in VAULT_SECRETS_PATH.
POSTGRES_INTROSPECT_USER = "vault_introspect"
CLICKHOUSE_INTROSPECT_USER = "vault_introspect"

SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY")

PASSWORD_POLICY_NAME = "temp-account-policy"
POSTGRES_CONNECTION_NAME = "postgres-test"
CLICKHOUSE_CONNECTION_NAME = "clickhouse-test"
ADMIN_POLICY_NAME = "db-access-admin"

GRANTS_STORE_PATH = "/vault-secrets/grants.json"

ALLOWED_POSTGRES_COMMANDS = ["SELECT", "INSERT", "UPDATE", "DELETE"]
ALLOWED_CLICKHOUSE_COMMANDS = ["SELECT", "INSERT", "ALTER UPDATE", "ALTER DELETE"]
