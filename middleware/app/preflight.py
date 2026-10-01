"""Refuse to start the stack with missing or placeholder secrets."""

import os
import re
import sys

REQUIRED_SECRETS = [
    "POSTGRES_ADMIN_PASSWORD",
    "PG_MANAGER_PASSWORD",
    "PG_INTROSPECT_PASSWORD",
    "CLICKHOUSE_ADMIN_PASSWORD",
    "CLICKHOUSE_MANAGER_PASSWORD",
    "CLICKHOUSE_INTROSPECT_PASSWORD",
    "VDBA_ADMIN_PASSWORD",
]
MIN_LENGTH = 16
# Secrets end up inside SQL string literals in init scripts: allow only characters that never need quoting.
SAFE = re.compile(r"[A-Za-z0-9_-]+")


def problems(env: dict[str, str]) -> list[str]:
    bad = []
    for name in REQUIRED_SECRETS:
        value = env.get(name, "")
        if not value:
            bad.append(f"{name} is empty")
        elif "changeme" in value.lower():
            bad.append(f"{name} still contains the placeholder 'changeme'")
        elif not SAFE.fullmatch(value):
            bad.append(f"{name} may only contain letters, digits, '_' and '-'")
        elif len(value) < MIN_LENGTH:
            bad.append(f"{name} is shorter than {MIN_LENGTH} characters")
    if not env.get("VDBA_ADMIN_USER"):
        bad.append("VDBA_ADMIN_USER is empty")
    return bad


def main() -> None:
    bad = problems(dict(os.environ))
    if bad:
        print("Refusing to start: fix .env (run `make env` to generate random values):", file=sys.stderr)
        for line in bad:
            print(f"  - {line}", file=sys.stderr)
        sys.exit(1)
    print("preflight ok")


if __name__ == "__main__":
    main()
