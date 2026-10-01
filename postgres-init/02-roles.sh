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

-- Maintenance functions owned by vault_manager (run as the caller, i.e. as vault_manager, so they can only touch
-- what it may touch). They are the ONLY revocation SQL Vault runs, and they are idempotent: a role that is already
-- gone is a no-op, so a retried or late Vault revocation (including expiry with the web app stopped) cannot get
-- stuck on "role does not exist". Vault splits statements on semicolons, hence one SELECT per call.
CREATE SCHEMA vdba AUTHORIZATION vault_manager;
REVOKE ALL ON SCHEMA vdba FROM PUBLIC;
SET ROLE vault_manager;

CREATE FUNCTION vdba.lockout_role(rolename text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
    IF rolename !~ '^vdba_[0-9a-f]{10}_[a-z0-9]{6}$' THEN
        RAISE EXCEPTION 'refusing to touch role %', rolename;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = rolename) THEN
        EXECUTE format('ALTER ROLE %I NOLOGIN', rolename);
        EXECUTE format('ALTER ROLE %I VALID UNTIL %L', rolename, '1970-01-01 00:00:00+00');
    END IF;
END
$fn$;

CREATE FUNCTION vdba.cleanup_role(rolename text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
    n integer;
    tries integer := 0;
BEGIN
    IF rolename !~ '^vdba_[0-9a-f]{10}_[a-z0-9]{6}$' THEN
        RAISE EXCEPTION 'refusing to touch role %', rolename;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = rolename) THEN
        RETURN;
    END IF;
    PERFORM set_config('lock_timeout', '5s', true);
    PERFORM vdba.lockout_role(rolename);
    LOOP
        PERFORM pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = rolename;
        PERFORM pg_stat_clear_snapshot();
        SELECT count(*) INTO n FROM pg_stat_activity WHERE usename = rolename;
        EXIT WHEN n = 0;
        tries := tries + 1;
        IF tries > 50 THEN
            RAISE EXCEPTION 'backends of % still alive after % attempts', rolename, tries;
        END IF;
        PERFORM pg_sleep(0.2);
    END LOOP;
    EXECUTE format('DROP OWNED BY %I', rolename);
    EXECUTE format('DROP ROLE IF EXISTS %I', rolename);
END
$fn$;
RESET ROLE;
SQL
