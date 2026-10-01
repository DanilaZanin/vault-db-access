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
