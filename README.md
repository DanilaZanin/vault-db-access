# vault-db-access

vault-db-access is a small web portal and API that issues temporary PostgreSQL and ClickHouse accounts on top of
HashiCorp Vault's database secrets engine. An administrator picks a database, tables, commands and a TTL. Vault
creates the database account, the portal shows the password once, and Vault revokes the account when the TTL ends
or when an administrator revokes it. The portal does not store the issued database passwords or the per-grant
Vault tokens. It does store the admin's own rights-less Vault login token (session table) and holds the service
identity's AppRole SecretID as a file; see [SECURITY.md](SECURITY.md).

It is meant for small teams that want short-lived, table-scoped database access (on-call, support, one-off
analysis) without handing out shared passwords. It needs only Vault OSS / Community Edition: no Enterprise
feature is used.

Status: v0.1, single node, demo-grade deployment files. Read [SECURITY.md](SECURITY.md) before using it for real.

## 60-second demo

Needs Docker with compose v2, `make`, `openssl` and [uv](https://docs.astral.sh/uv/) (only for the tests).
`make up` takes about 17 s when the images are already built and cached (measured), and about 3 minutes on the first
run, which pulls and builds the images. The four containers use about 380 MB of RAM together.

```
git clone https://github.com/DanilaZanin/vault-db-access && cd vault-db-access
git checkout hardening-v0.1        # until v0.1.0 is merged to main
make up
```

`make up` writes `.env` with random secrets, builds the images, starts PostgreSQL, ClickHouse and Vault, runs the
one-off setup (initialises and unseals Vault, provisions it, revokes the root token) and starts the portal:

```
[setup] Vault initialized; unseal key(s) and root token written to /secrets/vault-keys.json (mode 0600)
[setup] Vault unsealed
[setup] file audit device enabled (/vault/logs/audit.log in the vault container)
[setup] connection 'postgres' verified: account vault_manager, our username template, privileges within the allowlist
[setup] connection 'clickhouse' verified: account vault_manager, our username template, privileges within the allowlist
[setup] new AppRole secret_id written to secrets/approle/secret_id
[setup] self-check ok: AppRole login works; policy/config writes are forbidden
[setup] root token revoked and removed from disk
[setup] done: portal admin is 'admin'; the middleware can now log in via AppRole
portal: http://127.0.0.1:8000  (admin user/password: see VDBA_ADMIN_* in .env)
```

Open http://127.0.0.1:8000 and log in with `VDBA_ADMIN_USER` / `VDBA_ADMIN_PASSWORD` from `.env`. The form issues a
grant; the same thing through the JSON API (this is the real response, password masked here):

```
POST /api/grants   {"db_type":"postgres","scope":"tables","tables":["customers"],
                    "commands":["SELECT"],"ttl_seconds":600,"requested_for":"alice"}
200  Cache-Control: no-store
{
  "grant_id": "vdba_91431696f3",
  "db_type": "postgres",
  "scope": "tables",
  "tables": ["customers"],
  "commands": ["SELECT"],
  "requested_for": "alice",
  "issued_by": "admin",
  "ttl_seconds": 600,
  "status": "active",
  "username": "vdba_91431696f3_ohsthz",
  "created_at": "2026-10-01T08:27:16Z",
  "expires_at": "2026-10-01T08:37:16Z",
  "password": "<shown once>"
}
```

The recipient connects (here from inside the Postgres container; a `psql` on the host works the same against
127.0.0.1:5432):

```
$ docker compose exec -T -e PGPASSWORD=... postgres psql -h 127.0.0.1 -U vdba_91431696f3_ohsthz -d appdb \
    -c "SELECT id, name FROM customers"
 id |     name
----+---------------
  1 | Alice Ivanova
  2 | Boris Petrov
(2 rows)

... -c "SELECT * FROM orders"
ERROR:  permission denied for table orders
... -c "INSERT INTO customers (name,email) VALUES ('x','y')"
ERROR:  permission denied for table customers
```

After `POST /api/grants/vdba_91431696f3/revoke` (an admin clicking "Revoke" does the same) the account is gone:

```
200
{"grant_id": "vdba_91431696f3", "db_type": "postgres", "scope": "tables", "tables": ["customers"],
 "commands": ["SELECT"], "requested_for": "alice", "issued_by": "admin", "ttl_seconds": 600,
 "status": "revoked", "username": "vdba_91431696f3_ohsthz",
 "created_at": "2026-10-01T08:27:16Z", "expires_at": "2026-10-01T08:37:16Z"}
... -c "SELECT id, name FROM customers"
psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  role "vdba_91431696f3_ohsthz" does not exist
```

Logging in from a script (this is what the integration tests do; every step below was run against the demo):

1. `GET /login`: the response sets the `vdba_pre` cookie and the HTML form contains `<input name="csrf_token" value="...">`.
2. `POST /login` as a form with `csrf_token`, `username`, `password`, the `vdba_pre` cookie and the header
   `Origin: http://127.0.0.1:8000`. Success is a 303 that sets the `vdba_sid` session cookie.
3. `GET /api/session` returns `{"username": ..., "csrf_token": ...}`.
4. Every later POST needs the header `Origin: http://127.0.0.1:8000` and `X-CSRF-Token: <that token>`.

Reset everything with `make down` (it deletes the volumes and `./secrets`).

## How it works

```
 admin (browser / API)
        |  login: Vault userpass, then a server-side portal session (+ CSRF)
        v
 +-----------------+   AppRole "vdba-service"    +-----------------------+
 |  portal         | --------------------------> |  Vault (OSS)          |
 |  (middleware,   |   narrow policy: roles for  |  database engine      |
 |  SQLite store)  |   vdba_*, token create,     |  file audit device    |
 +-----------------+   lease revoke, KV read     +-----------+-----------+
        ^                                                    |  connects as
        | reads catalog with a read-only                     |  non-superuser
        | introspection account (from Vault KV)              v  "vault_manager"
        |                                         +-----------------------+
        +-----------------------------------------|  PostgreSQL 18        |
                                                  |  ClickHouse 25.8 LTS  |
 recipient: psql / clickhouse client  ----------> |  vdba_<grant>_<rand>  |
            with the one-time password            +-----------------------+
```

- Two different identities. An admin logs in with a Vault userpass account that holds only a marker policy and
  can do nothing in Vault. The portal itself uses an AppRole identity that may write database roles named
  `vdba_*` (SQL from fixed templates), create per-grant tokens, revoke leases and tokens, run the maintenance
  SQL through one-shot roles and read the introspection secrets. It cannot write policies or connections or
  read credentials.
- Vault connects to each database as `vault_manager`, a non-superuser (details of its grants are in
  `postgres-init/02-roles.sh` and `clickhouse-init/02-roles.sh`). Role creation SQL is generated by the portal from
  fixed templates and validated identifiers.
- For every grant the portal creates one orphan Vault token (display name = grant id) and reads
  `database/creds/<grant>` once with it. That token owns the lease, so logging out as an admin does not revoke the
  grant. The recipient never receives a Vault token; the token is thrown away after the read and its accessor is
  kept to revoke it later.

Grant lifecycle (every external step is written to SQLite first):

```
issuing --> active --> revoking --> revoked
   |           |  (TTL ends)  ^
   |           +--> expired   |   revoke or reconciler retry
   +--> failed (cleaned up)   +-- stays here with last_error until the cleanup is confirmed
```

A reconciler runs at start and every 60 s. It retries `issuing` and `revoking` rows, finishes expired grants,
finds leftovers by the `vdba_<grant>_` prefix and warns about untracked accounts. Revocation locks the PostgreSQL
role (`NOLOGIN`), terminates its sessions and checks `pg_stat_activity` until none remain, revokes the lease
synchronously (Vault runs the drop statements), confirms the account is gone and revokes the token. Expiry works
without the portal: Vault revokes the lease by itself and PostgreSQL's `VALID UNTIL` blocks logins meanwhile.

## Security model

Full threat model and residual risks: [SECURITY.md](SECURITY.md). Summary:

- An admin cannot write Vault policies, roles or connections; the portal's service identity cannot write
  policies or connections (it does write `vdba_*` database roles). The root token is revoked at the end of setup.
  The middleware container mounts only the AppRole files.
- Setup refuses a database connector whose account is not `vault_manager`, whose username template is foreign, or
  whose effective privileges exceed an allowlist (superuser-like attributes, predefined or foreign role
  memberships on PostgreSQL; extra grants or roles on ClickHouse). It cannot prove that the service identity is
  unable to do harm through the roles it writes: on ClickHouse that includes `ALTER USER` on any SQL-managed user.
- A recipient gets the listed tables (and the sequences owned by them) and no DDL, for the TTL. On revoke through
  the portal a PostgreSQL account is locked out, its sessions are terminated and confirmed gone in
  `pg_stat_activity`, then dropped; a ClickHouse account has its running queries killed and is dropped. Expiry
  without the portal is Vault's own best-effort revocation of the same effect, without the confirmation step.
- Passwords are shown once, sent with `Cache-Control: no-store`, and never stored or logged.
- Sessions are server-side and re-validated against the current Vault user. State-changing requests need a CSRF
  token and a matching `Origin`. Request bodies are limited to 64 KiB. Vault's file audit device is on.

Residual risks you must know about:

- ClickHouse `CREATE/ALTER/DROP USER` rights are global. A compromised portal could change other SQL-managed
  ClickHouse users. Use a dedicated ClickHouse instance.
- `bootstrap_admin` in the demo ClickHouse is a full administrator reachable on the published port.
- Transport security between the components is the operator's job. The demo is plain HTTP on 127.0.0.1 and an
  internal docker network and says so (`VDBA_ALLOW_INSECURE=1`).
- The store is one SQLite file used by one process. There is no HA.
- The ClickHouse plugin has dependency advisories without an upstream fix (docker/docker, pgproto3); Trivy lists
  them. Debian base-image CVEs without a fix remain in the middleware image.
- The Vault `revoke-accessor` permission is global, and there is no login rate limiting.

## Production checklist

- Put TLS in front of the portal (reverse proxy) and set `VDBA_PUBLIC_ORIGIN=https://...`; the portal refuses a
  plain-http public origin on a non-loopback host unless `VDBA_ALLOW_INSECURE=1`.
- Run Vault with a TLS listener (edit `VAULT_LOCAL_CONFIG` in `docker-compose.yml`) and change `VAULT_ADDR`.
- PostgreSQL: set `VDBA_PG_SSLMODE=verify-full` and `VDBA_PG_SSLROOTCERT=<path to the CA>` in `.env`, and remove
  `VDBA_ALLOW_INSECURE`. The same variables are used by Vault (its connection to Postgres, set once by setup) and by
  the middleware (its introspection connection), so the CA file must be readable at that path in BOTH the vault and
  the middleware containers (mount it into both). Setup and the middleware refuse `disable`, `allow` and `prefer`
  (and unknown values) unless `VDBA_ALLOW_INSECURE=1`, and setup refuses to run with no TLS setting at all.
- ClickHouse: enable TLS on the server (the secure native port, usually 9440, and the secure HTTP port, usually
  8443; the demo server does not enable them). Then set `VDBA_CH_SECURE=1`, `VDBA_CH_CA_CERT=<path to the CA>`,
  `VDBA_CLICKHOUSE_NATIVE_PORT=9440` and `VDBA_CLICKHOUSE_HTTP_PORT=8443`. `VDBA_CH_SECURE=1` makes the middleware
  verify the server certificate over HTTPS and makes setup add `secure=true` to Vault's native connection. The
  plugin's own CA handling is limited: use a certificate that the vault container already trusts.
- Use a dedicated ClickHouse instance. Remove or lock down `bootstrap_admin` and do not publish its port.
- Back up the `/data` volume. The SQLite file contains the admins' Vault login tokens (8 h, marker policy only) and
  hashed session ids, so store the copy like a secret and keep it OUT of the repository directory:
  ```
  docker compose exec -T middleware python -c "import sqlite3;s=sqlite3.connect('/data/vdba.sqlite3');d=sqlite3.connect('/tmp/backup.sqlite3');s.backup(d)"
  docker compose cp middleware:/tmp/backup.sqlite3 ~/vdba-backup/vdba.sqlite3    # any directory outside the clone
  docker compose exec -T middleware rm /tmp/backup.sqlite3
  ```
  Also back up the Vault data volume and `./secrets/vault-keys.json` (the unseal key) separately.
- After a Vault restart it is sealed again: `make setup` unseals it from `./secrets/vault-keys.json` and changes
  nothing else.
- Re-running setup after the root token was revoked: setup then only unseals, checks the AppRole login and re-checks
  the connector account and username template with the service identity. It prints a warning that the privilege
  probe was not re-run. To change policies or connections, or to re-run the probe, you need a root token again.
  Vault 2.1.1 only allows `generate-root` unauthenticated when the server config says so. The procedure (run on the
  Docker host, every command was run against the demo stack):
  ```
  printf '\nenable_unauthenticated_access = ["generate-root"]\n' >> vault/config.hcl
  docker compose restart vault && make setup                       # setup unseals it again
  V() { docker compose exec -T -e VAULT_ADDR=http://127.0.0.1:8200 vault vault "$@"; }
  INIT=$(V operator generate-root -init -format=json)
  NONCE=$(echo "$INIT" | python3 -c "import sys,json;print(json.load(sys.stdin)['nonce'])")
  OTP=$(echo "$INIT" | python3 -c "import sys,json;print(json.load(sys.stdin)['otp'])")
  KEY=$(python3 -c "import json;print(json.load(open('secrets/vault-keys.json'))['keys'][0])")
  ENC=$(echo "$KEY" | V operator generate-root -nonce=$NONCE -format=json - | python3 -c "import sys,json;print(json.load(sys.stdin)['encoded_token'])")
  V operator generate-root -decode=$ENC -otp=$OTP > secrets/root-token && chmod 600 secrets/root-token
  # remove the enable_unauthenticated_access line from vault/config.hcl again, then:
  docker compose restart vault && make setup                       # unseals, re-provisions, revokes the new root
  ```
  With more than one unseal key, repeat the `-nonce` step with each key until the response contains
  `"complete": true`. Alternatively run setup with `SETUP_ARGS=--keep-root` (the root token then stays in
  `./secrets/vault-keys.json`, store it offline). For the demo, `make down && make up` starts over and deletes all data.
- Upgrading from the layout before v0.1: breaking changes are listed in [CHANGELOG.md](CHANGELOG.md): `grants.json`
  became SQLite (old grants are not migrated, revoke them first), `vaultadmin.xml` is gone, token delivery and
  `allow_create` are removed, setup is the new one-off service, connectors are non-superuser, `.env` changed, ports
  are loopback-only, API clients need `Origin` and CSRF.
- Published images (available after the first `v*` tag is released) are built for amd64 and arm64 with SBOM and
  provenance attestations. The release workflow scans every platform digest with Trivy before it promotes `latest`
  (stable tags only), signs both images with cosign keyless and verifies the signatures against the exact workflow
  identity. The GitHub release lists both digests and attaches the full Trivy reports. Both GHCR packages are public,
  so anonymous pulls and `make up-release` work without a login.
  Verify BOTH images, then run exactly the digests you verified:
  ```
  V=v0.1.0
  ID="https://github.com/DanilaZanin/vault-db-access/.github/workflows/release.yml@refs/tags/$V"
  for img in vault-db-access-middleware vault-db-access-vault; do
    cosign verify ghcr.io/danilazanin/$img:$V --certificate-identity "$ID" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
  done
  # use the digests printed by cosign (or listed in the release notes):
  VDBA_VERSION=$V VDBA_MIDDLEWARE_DIGEST=sha256:... VDBA_VAULT_DIGEST=sha256:... make up-release
  ```
  `make up-release` is `docker compose -f docker-compose.yml -f compose.release.yml ...`. Checked for v0.1.0:
  both signatures verify, and a fresh clone with the two digests reaches a healthy portal in about 2.5 minutes.

## What it does not do yet (ideas for v0.2)

- OIDC / SSO with groups mapped to databases (today: Vault userpass accounts with the `db-access-admin` policy).
- An approval workflow for grant requests.
- Token delivery mode (recipient logs into Vault) and `allow_create` scratch schemas, both removed in v0.1 because
  they need an ownership and cleanup contract.
- A Helm chart and high availability.

## Development

```
make lint     # ruff check + format check, hadolint if installed
make audit    # pip-audit on the locked runtime dependencies
make unit     # unit tests only
make test     # unit tests, then integration tests if a stack is running (skipped with a banner otherwise)
make check    # fresh stack with test hooks, unit + integration; fails if the stack is unreachable
make images   # build vdba-app:local and vdba-vault:local
make down     # destroy stack, volumes and ./secrets
```

Layout: `middleware/app` (portal, setup, reconciler), `postgres-init` and `clickhouse-init` (sample data and the
manager accounts), `vault/` (Vault image with the pinned ClickHouse plugin), `tests/unit`, `tests/integration`.
Unit tests need no Docker (two of them call `docker compose config`). Integration tests (`tests/integration`) run
against the real compose stack and include the security regression tests: each one checks the behaviour named in
its title against the real services (for example the exploit request is refused, or the account is really gone in
the database). They are regression tests, not a proof of absence of other flaws. `make check` sets
`VDBA_REQUIRE_STACK=1`, so an unreachable stack is a failure, never a skip, and starts the stack with
`VDBA_TEST_HOOKS=1` (fault injection for crash tests and a 2-hour test-admin token in `secrets/test-admin-token`;
never use that in production). CI (`.github/workflows/ci.yml`) runs everything plus pip-audit, hadolint, actionlint
and Trivy.

| Finding | Regression test (tests/integration) |
|---|---|
| Admin escalates to Vault root via policies, roles, connections (SSRF) | `test_01_admin_token_cannot_touch_policies_roles_or_connections`, `test_02_service_identity_is_narrow` |
| Root token / secrets mounted into the running app | `test_02b_middleware_has_no_root_secrets`, `test_02c_root_token_revoked_and_audit_device_on` |
| Ports open on all interfaces | `test_02d_ports_are_loopback_only` |
| Passwords in `grants.json` and `GET /api/grants` | `test_03_no_password_is_ever_exposed_or_stored` |
| Revoke race, account survives revocation | `test_04_revoke_kills_the_account_within_five_seconds`, `test_04b_open_postgres_session_is_terminated_on_revoke`, `test_postgres_termination_is_confirmed_by_pg_stat_activity` |
| Logout revokes the admin's grants | `test_05_logout_of_the_issuing_admin_does_not_revoke_grants` |
| TTL not validated, `allow_create` truthy strings | `test_06_ttl_is_validated`, `test_06b_removed_and_unknown_fields_are_rejected`, `test_06c_expires_at_follows_the_vault_lease` |
| No CSRF, vault token in cookie, 14-day session | `test_07_csrf`, `test_07b_session_and_cookie_hygiene`, `test_state_changing_request_without_origin_or_fetch_metadata_is_rejected` |
| Multipart DoS / body limit | `test_body_limit_cannot_be_bypassed_with_chunked_encoding` |
| Session survives removal of admin rights | `test_session_ends_when_admin_rights_are_removed` |
| INSERT grants all sequences, DROP on whole database, grants beyond listed tables | `test_08_postgres_grant_is_limited_to_listed_tables_and_sequences`, `test_08b_postgres_all_commands_and_whole_database`, `test_08c_clickhouse_grant_is_limited_and_cannot_drop` |
| Interrupted issue leaves resources | `test_09_interrupted_issue_is_cleaned_by_the_reconciler`, `test_lost_token_create_response_does_not_leave_a_live_token`, `test_partial_clickhouse_account_is_removed_when_a_later_grant_fails` |
| Old operations dropped from the retry list | `test_old_revoking_row_is_retried_even_behind_a_thousand_newer_rows` |
| Expiry depends on the web app | `test_10_expiry_works_without_the_web_app` |
| Hard-coded ClickHouse admin, rotate fails, superuser connectors | `test_11_manager_password_comes_from_env_and_rotation_works`, `test_setup_refuses_a_superuser_or_wrong_account_connector` |
| Default / placeholder secrets | `test_12_stack_refuses_to_start_with_changeme` |
| SQLite WAL readable, session ids stored in clear | `test_sqlite_files_and_session_ids_are_private` |
| One database down hides the other, backend errors leak | `test_one_database_down_does_not_hide_the_other_catalog`, `test_errors_never_leak_backend_text` |
| Old service tokens never revoked on re-login | `test_service_relogin_revokes_the_previous_token` |
| Existing connector with extra privileges, memberships or a foreign username template | `test_setup_refuses_a_postgres_manager_with_dangerous_memberships`, `test_setup_refuses_a_clickhouse_manager_with_extra_grants_or_roles`, `test_setup_refuses_a_connector_with_a_foreign_username_template`, `test_setup_without_root_still_rechecks_connectors_and_warns` |
| PostgreSQL cleanup fails on a role that is already gone (retry, expiry) | `test_cleanup_function_is_idempotent_and_guarded`, `test_revoke_after_the_role_was_already_dropped_is_clean`, `test_vault_expiry_after_the_role_was_already_dropped_is_clean` |
| Running ClickHouse query survives revoke | `test_clickhouse_running_query_stops_after_revoke` |
| Oversized chunked JSON body reported as 400 | `test_oversized_chunked_json_body_is_413_not_400` |
| Real backend failures (paused database / Vault) leak details | `test_real_backend_failures_do_not_leak_details` |

Unit tests cover the SQL builders (identifier validation, sequences, maintenance statements), the request model,
the preflight check, the SQLite store, templates, the reconciler's decisions, admission limits, token discovery
error handling, TLS settings, compose passthrough of production settings and the release override.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
