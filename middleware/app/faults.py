"""Test-only fault injection ("kill the process at point X"). Inert unless VDBA_TEST_HOOKS=1."""

import os
from pathlib import Path

from . import config


def point(name: str) -> None:
    if not config.TEST_HOOKS:
        return
    try:
        armed = Path(config.FAULT_FILE).read_text().strip()
    except OSError:
        return
    if armed == name:
        Path(config.FAULT_FILE).unlink(missing_ok=True)  # one-shot
        os._exit(137)  # noqa: SLF001 - simulate SIGKILL: no cleanup, no exception handlers


def mutate_statements(creation: list[str]) -> list[str]:
    """Test hook: append a statement that fails AFTER the account was created (partial create)."""
    if config.TEST_HOOKS:
        try:
            if Path(config.FAULT_FILE).read_text().strip() == "bad_statement":
                Path(config.FAULT_FILE).unlink(missing_ok=True)
                return [*creation, "GRANT BOGUS PRIVILEGE ON nothing TO '{{name}}';"]
        except OSError:
            pass
    return creation
