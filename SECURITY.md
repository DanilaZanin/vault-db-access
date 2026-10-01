# Security (draft, v0.1)

## Reporting
Please report vulnerabilities privately (GitHub security advisory on this repository) rather than in a public
issue. Include the version/commit and a reproduction.

## What this is
A portal in front of HashiCorp Vault's database secrets engine that issues temporary PostgreSQL / ClickHouse
accounts. Password grants only.

## Threat model
Actors: portal admin (issues grants), recipient (holds the credentials), network attacker, compromised middleware.

Goals:
1. An admin cannot gain more than "issue/revoke grants on the configured databases". The admin's own Vault token
   carries only a marker policy (no policy, role or connection writes). The middleware's service identity is
   separate and does write Vault database roles named `vdba_*` (with SQL generated from fixed templates), create
   per-grant tokens, revoke leases/tokens and read the introspection secrets; it cannot write policies or
   connections or read credentials.
2. A recipient gets the scope shown in the UI (listed tables, sequences owned by them, no DDL) for the TTL. What is
   guaranteed, and how well it is tested:
   - Revoke through the portal: PostgreSQL accounts are locked out (committed), their sessions terminated and
     confirmed gone in `pg_stat_activity`, then dropped (tested, including a running query). ClickHouse accounts have
     their running queries killed and the user dropped (tested with a long-running query).
   - Expiry without the web app: Vault revokes the lease itself and runs one idempotent statement
     (`vdba.cleanup_role` / `KILL QUERY` + `DROP USER`). This is best effort: if the database is unreachable at that
     moment Vault retries, and the PostgreSQL `VALID UNTIL` (lease + 5 s) keeps new logins out meanwhile. The
     autonomous path does not have the middleware's confirmation step.
3. A compromised middleware cannot reach Vault root or become a database superuser through the manager accounts:
   root is revoked after setup, the AppRole policy has no policy/config-write/creds access, and setup refuses
   connectors whose account is not `vault_manager`, whose username template is foreign, or whose effective
   privileges exceed an allowlist (PostgreSQL: no superuser-like attributes, no predefined-role or foreign
   memberships; ClickHouse: only the listed grants, no roles). It CAN run SQL as the (non-superuser) managers
   through the roles it writes: on ClickHouse that includes `ALTER USER` on every SQL-managed user (see below).
4. The portal does not store the issued database passwords or the per-grant Vault tokens: passwords are shown once
   and never stored or logged, the token is used once and only its accessor is kept. What it does keep: the
   admin's own Vault login token (marker policy only, 8 h) in the SQLite session table (file 0600 in a 0700
   directory, session ids stored as sha256), and the AppRole SecretID as a read-only file mounted into the
   middleware (see residual risks).
5. Every issue/revoke is auditable: Vault's file audit device (outside the middleware's reach) plus an application
   audit table with request id, actor, action and result.

## Residual risks (known, accepted for v0.1)
- **ClickHouse manager rights are global.** `CREATE/ALTER/DROP USER ON *.*` cannot be limited to our accounts, and a
  compromised middleware can write a Vault role with arbitrary SQL that runs as the manager. It can therefore alter
  other SQL-managed ClickHouse users (for example change an administrator's password). **Use a dedicated ClickHouse
  instance for this portal.** Isolation on a shared ClickHouse server is not guaranteed.
- **`bootstrap_admin` (ClickHouse) is a full administrator reachable over the network** (the HTTP port is published
  on 127.0.0.1 in the demo). Its password lives only in `.env` and the ClickHouse container; the middleware never
  receives it. Restrict the port and rotate/remove the account in any non-demo deployment.
- **Vault `revoke-accessor` is global.** The service identity may revoke any token by accessor; the portal only ever
  passes accessors stored in its own grant rows, but a compromised middleware could revoke other tokens. Run this Vault
  as a dedicated instance or namespace. The same identity can run SQL as the database managers (via roles it writes).
- **Plain HTTP between components in the demo.** Everything binds to 127.0.0.1 and the internal docker network; Vault
  to Postgres uses `sslmode=disable` only when `VDBA_ALLOW_INSECURE=1`. Production needs TLS on the portal, Vault
  (listener), Postgres (`VDBA_PG_SSLMODE=verify-full` + `VDBA_PG_SSLROOTCERT`) and ClickHouse. Setup refuses to
  run without either TLS settings or the explicit insecure flag.
- **The AppRole SecretID is stored.** It is a long-lived file (`secrets/approle/secret_id`, mode 0400, owned by the
  middleware uid, mounted read-only into the middleware only). Single-use SecretIDs are not feasible because the middleware must re-login after restarts.
  Anyone who can read it can log in as the service identity (see above for its reach).
- **PostgreSQL VALID UNTIL is the lease expiry + 5 s** (Vault's own margin); Vault revokes the lease at expiry.
- **Orphan accounts** left by a crash between a database CREATE and Vault recording the lease are removed by the
  reconciler (by the `vdba_<grant>_` name prefix) and reported in the audit log.
- **No login rate limiting** (Vault userpass has none). Put the portal behind your own rate limiter / SSO.
- **Third-party ClickHouse plugin** (ContentSquare/vault-plugin-database-clickhouse, pinned to commit 9ca33fa): its
  dependencies are bumped at build time (see `vault/Dockerfile`), but advisories without a fixed upstream release
  stay open (at the time of writing docker/docker CVE-2026-41567 and CVE-2026-42306, pgproto3/v2 CVE-2026-32286).
  Each GitHub release attaches the full Trivy report (including findings that have no fix) for every image and
  platform digest; CI and the release gate only on HIGH/CRITICAL findings that have a fix.
- Base images ship OS packages with unfixed CVEs from time to time; images are rebuilt with `apt-get upgrade` and
  scanned, leftovers are listed in the release notes.

## Hardening already in place
No runtime ACL writes; per-grant orphan tokens; synchronous lease revocation with confirmed session termination;
CSRF token + Origin/Fetch-Metadata checks on every state-changing request (API clients must send a matching
`Origin`); server-side sessions that are re-validated against the current Vault user (deleting the user or removing
`db-access-admin` ends the session within the re-check interval); byte-counted 64 KiB body limit; admission limits
before any backend I/O; SQLite files 0600 in a 0700 directory; passwords restricted to `[A-Za-z0-9_-]` in `.env`;
setup validates that Vault's database connections use the least-privilege manager account and that it has no
superuser-like rights before it revokes the root token.
