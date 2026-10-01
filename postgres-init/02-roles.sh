#!/bin/bash
# Runs once on first start of the Postgres container (as the bootstrap superuser).
# Creates the NON-superuser account Vault connects as (vault_manager) and the read-only
# introspection account the portal uses to list tables. Passwords come from the environment.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username postgres --dbname appdb \
     -v mgr_pw="$VDBA_PG_MANAGER_PASSWORD" -v intro_pw="$VDBA_PG_INTROSPECT_PASSWORD" <<'SQL'
-- Vault's connection account: can create/drop roles (CREATEROLE) but is NOT a superuser, so a
-- creation statement can never mint SUPERUSER/REPLICATION/BYPASSRLS roles.
CREATE ROLE vault_manager LOGIN NOSUPERUSER CREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS
    CONNECTION LIMIT 10 PASSWORD :'mgr_pw';
-- Roles created by vault_manager are automatically granted back to it with SET + INHERIT, which
-- it needs to terminate their sessions (pg_terminate_backend), DROP OWNED and DROP ROLE.
ALTER ROLE vault_manager SET createrole_self_grant = 'set, inherit';

CREATE ROLE vault_introspect LOGIN NOSUPERUSER NOCREATEROLE CONNECTION LIMIT 5 PASSWORD :'intro_pw';

-- No implicit access for everybody: only explicitly granted roles can connect / use the schema.
REVOKE ALL ON DATABASE appdb FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE appdb TO vault_manager WITH GRANT OPTION;
GRANT CONNECT ON DATABASE appdb TO vault_introspect;
GRANT USAGE ON SCHEMA public TO vault_manager WITH GRANT OPTION;
GRANT USAGE ON SCHEMA public TO vault_introspect;

-- vault_manager may hand out exactly these privileges on existing and future (postgres-owned)
-- tables, and sequences. It holds no CREATE anywhere and owns no data.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vault_manager WITH GRANT OPTION;
-- Sequences: ALL (USAGE, SELECT, UPDATE), not just USAGE. DROP OWNED BY revokes "all" rights from the
-- departing role, and PostgreSQL refuses ("permission denied for column tableoid") unless the grantor
-- holds the grant option for all of them. The templates only ever GRANT USAGE.
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO vault_manager WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vault_manager WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT ALL ON SEQUENCES TO vault_manager WITH GRANT OPTION;
SQL
