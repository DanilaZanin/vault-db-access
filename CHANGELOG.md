# Changelog

## v0.1.0

First hardened release. It is a rewrite of the security model and **not compatible** with the previous layout.

### Breaking changes
- `grants.json` is gone. Grants live in a SQLite store (`/data/vdba.sqlite3`, WAL) with a staged-operation log and an
  audit table. Old grants are not migrated: revoke them before upgrading.
- `clickhouse-init/vaultadmin.xml` (hard-coded ClickHouse admin) is removed. Vault connects to ClickHouse and PostgreSQL
  as non-superuser `vault_manager` accounts created from `.env`.
- Token delivery is removed: only password grants exist. `allow_create` (CREATE/DROP rights) is removed.
- New setup flow: `make up` (or the one-off `setup` compose service) replaces `python -m app.first_time_setup`. Setup
  initialises and unseals Vault, writes keys only to `./secrets`, provisions everything, hands the middleware an
  AppRole identity and revokes the root token. Admins no longer hold Vault database/policy privileges.
- `.env` changed (see `.env.example`); the stack refuses to start with empty or `changeme` secrets.
- Ports bind to 127.0.0.1 only. The `vault-plugins` volume is gone (plugin is baked into the vault image).
- API clients must send a matching `Origin` header and a CSRF token (`GET /api/session`) on state-changing requests.

### Security
- All Vault writes use the middleware's own narrow AppRole identity; no runtime ACL policy writes.
- Per-grant orphan token owns each lease; admin logout no longer revokes grants.
- Confirmed revocation (committed lockout, session termination checked in `pg_stat_activity`), reconciler for crashes,
  expiry works without the web app. Server-side sessions re-validated against the current Vault user, CSRF everywhere,
  byte-counted body limit, admission limits, private SQLite files, Vault file audit device.
- Dependencies updated (pip-audit clean); images pinned by digest; ClickHouse plugin pinned to a commit.

### Added
- `SECURITY.md` (threat model and residual risks), `LICENSE` (Apache-2.0), CI (ruff, unit, pip-audit, hadolint,
  actionlint, Trivy, full integration suite on a real compose stack), signed multi-arch images on GHCR.
