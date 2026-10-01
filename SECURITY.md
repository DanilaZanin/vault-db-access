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
1. An admin cannot gain more than "issue/revoke grants on the configured databases" (no Vault policy, role or
   connection writes; the admin's Vault token carries only a marker policy).
2. A recipient gets exactly the scope shown in the UI (listed tables, sequences owned by them, no DDL) for exactly
   the TTL; the account is locked out, its sessions terminated and the account dropped on revoke or expiry, with or
   without the web app running.
3. A compromised middleware cannot reach Vault root or a database superuser: root is revoked after setup, the
   middleware's AppRole policy has no policy/config/creds access, and the database connectors are non-superuser.
4. No long-lived secret is stored by the portal: issued passwords are shown once and never stored or logged;
   the SQLite store holds only metadata, hashed session ids and the admin's own (rights-less) Vault login token.
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
- **AppRole SecretID is a long-lived file** (`secrets/approle/secret_id`, mode 0400, mounted read-only into the
  middleware only). Single-use SecretIDs are not feasible because the middleware must re-login after restarts.
  Anyone who can read it can log in as the service identity (see above for its reach).
- **PostgreSQL VALID UNTIL is the lease expiry + 5 s** (Vault's own margin); Vault revokes the lease at expiry.
- **Orphan accounts** left by a crash between a database CREATE and Vault recording the lease are removed by the
  reconciler (by the `vdba_<grant>_` name prefix) and reported in the audit log.
- **No login rate limiting** (Vault userpass has none). Put the portal behind your own rate limiter / SSO.
- **Third-party ClickHouse plugin** (ContentSquare/vault-plugin-database-clickhouse, pinned to commit 9ca33fa) is
  unmaintained upstream-style: its dependencies are bumped at build time (see `vault/Dockerfile`), but any advisory
  that has no fixed upstream release stays open; the Trivy report of the images is part of each release. Findings
  without an upstream fix are listed in the release notes.
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
