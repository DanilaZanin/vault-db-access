# Contributing

- Open an issue before a large change. Security problems: see SECURITY.md, do not open a public issue.
- Setup: Docker with compose v2, `uv`, `make`. Run `make check` before sending a PR: it builds a fresh stack,
  runs unit tests and the integration suite against it, and fails if the stack is unreachable.
- `make lint` (ruff check + format check) and `make audit` (pip-audit) must pass. Python 3.12, line length 120.
- Every security-relevant change needs a regression test that fails without the fix (integration test against the
  real stack if it concerns Vault or a database). Do not weaken or skip tests in the security gate.
- Pin new container images by digest and new GitHub Actions by full commit SHA (Renovate keeps them current).
- Commit messages: imperative, one logical change per commit. By contributing you agree your work is licensed under
  Apache-2.0.
