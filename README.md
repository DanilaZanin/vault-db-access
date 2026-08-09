# Vault DB Access

Self-service temporary database credentials on top of HashiCorp Vault 1.19's
Database Secrets Engine. An admin (a real Vault user, not a shared account)
picks a database (PostgreSQL or ClickHouse), a scope (whole DB or specific
tables), a set of allowed SQL commands, a lifetime, and how the recipient
should get their credentials (plaintext login+password, or a Vault token they
use to self-serve via the Vault UI). Vault generates and revokes the actual
database account; this app only translates the admin's choices into Vault DB
roles and never sees or stores long-lived secrets itself.

## Why no tab inside Vault's own UI?

Vault OSS's UI has no plugin/extension system, and the one native mechanism
that could show a banner/link inside it ("Custom Messages") is a **Vault
Enterprise** feature. So there's a separate small admin UI (this app) instead
of a tab inside Vault. Bookmark both.

## Components

- `vault/` — Vault 1.19.0 image with the `ContentSquare/vault-plugin-database-clickhouse`
  plugin built in (Vault has no built-in ClickHouse support).
- `postgres-init/`, `clickhouse-init/` — sample schemas for local testing.
- `middleware/` — the FastAPI admin app.
  - `app/first_time_setup.py` — **run once**, not on every start (see below).
  - `app/bootstrap.py` — reusable idempotent Vault-config helpers used by setup.
  - `app/main.py` — the running app: login, grant issuance, connection settings.
  - `app/statement_builder.py` — turns (scope, tables, commands) into SQL.
  - `app/db_introspect.py` — lists live table names for the picker (uses a
    permanent, minimal-privilege `vault_introspect` account, *not* the
    rotatable admin/root connection credential).
- `tests/` — unit tests (`test_statement_builder.py`) and full-stack
  integration tests (`test_integration.py`) that run against the real stack.

## Security model

- The running app **never holds Vault's root token or a shared admin
  password**. Every admin logs into Vault's own `userpass` auth method with
  their own account; the app uses *that person's* Vault token for every
  subsequent call. Vault's ACL policies are the only enforcement point — an
  account without the `db-access-admin` policy simply cannot do anything
  here, in or outside this UI.
- Root/privileged tokens are only ever used by `first_time_setup.py`, which
  you run once per Vault deployment (it's idempotent, safe to re-run).
- Generated database passwords are 12 chars via a Vault `password_policy`;
  logins are alphanumeric-only via a Vault `username_template` — both native
  Vault features, not custom code.
- Token-mode grants get a Vault token scoped, via a dedicated
  `grant-token-issuer` token role, to `read` on exactly one
  `database/creds/<role>` path — nothing else, including no ability to
  browse other grants.
- Admin/root DB connection credentials can be rotated from the UI
  (`/settings`) via Vault's native `database/rotate-root/<name>` — after
  that, nobody (including this app) can read the password back; Vault
  manages it internally from then on.

## Getting started (new clone)

Requirements: Docker + Docker Compose. Nothing else needs installing on the
host — Vault, Postgres, ClickHouse and the admin app all run in containers.

```bash
git clone https://github.com/DanilaZanin/vault-db-access.git
cd vault-db-access
cp .env.example .env        # fill in real values, or leave the DB passwords
                             # blank and configure them later via /settings
docker compose build
docker compose up -d
docker compose run --rm middleware python -m app.first_time_setup \
  --init --persist-secrets \
  --admin-user <your-name> --admin-password '<pick-a-password>'
```

Then open `http://<host>:8000` and log in with the admin user/password you
just created. That's the whole setup — everything else (issuing accounts,
picking tables/commands, rotating the DB connection password) happens in
that UI afterwards. See "Production deployment" below before using this for
anything beyond local testing/evaluation — the quickstart above intentionally
takes shortcuts (single unseal key stored on disk, plain HTTP) that are fine
for trying it out but not for a real deployment.

## Local dev/test quickstart

```bash
docker compose build
docker compose up -d
docker compose run --rm middleware python -m app.first_time_setup \
  --init --persist-secrets \
  --admin-user ivanov --admin-password 'change-me'
```

`--init --persist-secrets` is dev-only: it initializes Vault with a single
unseal key/share and stores the root token + key on disk (`./secrets/`) so
the container can unseal itself. **Do not use this in production** — see below.

Log into `http://<host>:8000` with the Vault username/password you just
created. Vault's own UI is at `http://<host>:8200`.

To add more admins later (as root, or as any existing `db-access-admin`):

```bash
vault write auth/userpass/users/petrov password='...' token_policies=db-access-admin
```

## Production deployment

The stack is deployment-target-agnostic (plain Docker Compose today,
Kubernetes later) — everything below is env-var driven, no code changes.

**1. Vault init/unseal — do this the real way.** In production, initialize
Vault with multiple key shares distributed to different trusted people
(`VAULT_INIT_SHARES` / `VAULT_INIT_THRESHOLD` if using `--init`, or better,
run `vault operator init`/`unseal` yourself outside this app entirely). Then
run setup with a temporary token instead of `--init`:

```bash
VAULT_ROOT_TOKEN=hvs.xxx docker compose run --rm middleware python -m app.first_time_setup \
  --admin-user ivanov --admin-password 'change-me'
```

Nothing is written to disk in this mode. For real HA/auto-unseal, add a
`seal "awskms" {}` (or azure/gcp) stanza as an extra `.hcl` file under
`vault/` — Vault merges every file in the config directory, so this needs no
changes to `config.hcl`.

**2. TLS.** The listener isn't in `config.hcl` — it's supplied via the
`VAULT_LOCAL_CONFIG` env var in `docker-compose.yml` specifically so this is
a config change, not a code change:

```json
{"listener":{"tcp":{"address":"0.0.0.0:8200","tls_disable":false,
  "tls_cert_file":"/vault/tls/cert.pem","tls_key_file":"/vault/tls/key.pem"}},
 "api_addr":"https://vault.example.com:8200"}
```

Mount your cert/key into `/vault/tls` and set `VAULT_ADDR` accordingly for
the middleware.

**3. `SESSION_SECRET_KEY`.** Set this explicitly (`openssl rand -hex 32`) —
without it the app generates a random one at every restart and invalidates
all sessions. Required if you ever run more than one middleware replica.

**4. Postgres/ClickHouse root connection.** Either seed it once via
`POSTGRES_SUPERUSER_PASSWORD` / `CLICKHOUSE_VAULTADMIN_PASSWORD` passed only
to the `first_time_setup` run (never to the long-running service), or skip
that entirely and enter it through `/settings` after first login. Rotate it
from the same page whenever you like.

**5. Container.** The middleware image already runs as non-root (uid 1000)
and has a healthcheck. If bind-mounting `./secrets`, `chown -R 1000:1000` it
first (or use a named volume instead, which Docker owns correctly automatically).

## Errors hit while building this (and the fixes)

Kept here so nobody re-discovers these the hard way if they extend this project.

1. **Vault double-loaded its own config and refused to start** ("address
   already in use" on 8200, inside a single container). The official
   `hashicorp/vault` entrypoint always passes `-config=/vault/config` itself;
   also passing `-config=/vault/config/config.hcl` on the `command:` line
   loads the same listener stanza twice. Fix: just mount `config.hcl` into
   `/vault/config/` and use `command: ["server"]`, nothing else.

2. **Vault crashed with `permission denied` writing to its storage path.**
   The entrypoint only `chown`s `/vault/config`, `/vault/logs`, `/vault/file`
   to the non-root `vault` user — not arbitrary custom paths. Fix: use
   `storage "file" { path = "/vault/file" }`, not `/vault/data`.

3. **hvac (the Python Vault client) doesn't have a method for everything.**
   `client.sys.register_plugin(...)` and `client.sys.create_or_update_password_policy(...)`
   don't exist in hvac 2.3.0 — use the generic `client.write("sys/plugins/catalog/...")`
   /`client.write("sys/policies/password/...")` instead of assuming a named
   wrapper exists. Also: policy management must go through the modern
   `sys/policies/acl/<name>` path (`client.write`/`client.delete`), not the
   legacy `client.sys.create_or_update_policy`/`delete_policy` wrappers (they
   hit `sys/policy/`, a different, deprecated endpoint) — a policy scoped
   to `sys/policies/acl/*` will 403 against the legacy path in a very
   confusing way ("permission denied" even though the policy "looks right").

4. **The ClickHouse Vault plugin failed with `fork/exec: no such file or
   directory` even though the file clearly existed.** It was built with cgo
   enabled (default on a glibc/Debian builder), producing a dynamically
   linked binary — but the official Vault image is Alpine/musl and has no
   glibc loader. Fix: `CGO_ENABLED=0 GOOS=linux go build`.

5. **`INSERT` grants failed with "permission denied for sequence"** on
   Postgres tables with `SERIAL`/`IDENTITY` columns. Table-level `INSERT`
   alone isn't enough; the role also needs
   `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public`.

6. **ClickHouse queries silently returned "unknown table" for the right
   table name.** `clickhouse_connect.get_client()` doesn't default to any
   particular database — pass `database=` explicitly or unqualified table
   names resolve against `default`, not your actual DB.

7. **A minimal-privilege "just list table names" account saw zero tables.**
   Both `information_schema.tables` (Postgres) and `system.tables`
   (ClickHouse) are privilege-filtered per user. Fix: Postgres →
   `pg_catalog.pg_tables` instead (not filtered); ClickHouse →
   `GRANT SHOW TABLES ON db.* TO user` (lighter than `SELECT`) before
   `system.tables` shows anything.

8. **Rotating the Postgres/ClickHouse root connection password broke table
   listing.** Obvious in hindsight: after `database/rotate-root`, nobody —
   including this app — can read that password back, by design. Any feature
   that isn't the Vault role-issuing machinery itself needs its *own*,
   separate, never-rotated credential. That's why there's a permanent
   `vault_introspect` account distinct from the connection's root credential.

9. **`sys/leases/revoke-prefix/*` returned `permission denied` despite the
   policy granting `update` on it.** It's one of Vault's "sudo-protected"
   paths — `update` alone isn't enough, the policy also needs `sudo` in the
   same capabilities list.

10. **Minting a scoped token for token-mode delivery failed with `child
    policies must be subset of parent`.** A non-root Vault token can't create
    a child token carrying a policy it doesn't itself hold. Fix: a dedicated
    token role (`auth/token/roles/grant-token-issuer` with
    `allowed_policies_glob=["read-grant-*"]`), and mint through
    `auth/token/create/grant-token-issuer` instead of the bare
    `auth/token/create`.

11. **Switched the middleware container to a non-root user for hardening,
    then it couldn't write to the bind-mounted `./secrets` folder.** Bind
    mounts keep host ownership; `chown -R 1000:1000 ./secrets` (matching the
    container's uid) fixes it, or use a named volume instead.

## Running tests

```bash
docker compose run --rm middleware python -m app.first_time_setup \
  --init --persist-secrets --admin-user ivanov --admin-password 'IvanovPass123!'

docker run --rm --network vault-db-access_vault-db-access \
  -v "$(pwd)":/work -w /work \
  -e VAULT_ADMIN_PASSWORD='IvanovPass123!' \
  python:3.12-slim \
  bash -c "pip install -q -r middleware/requirements.txt pytest requests && pytest tests/ -v"
```
