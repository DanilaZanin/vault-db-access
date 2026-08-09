import json
import os
import threading
from dataclasses import asdict

from . import config
from .models import IssuedGrant

_lock = threading.Lock()


def _load() -> list[dict]:
    if not os.path.exists(config.GRANTS_STORE_PATH):
        return []
    with open(config.GRANTS_STORE_PATH) as f:
        return json.load(f)


def _save(items: list[dict]) -> None:
    with open(config.GRANTS_STORE_PATH, "w") as f:
        json.dump(items, f, indent=2)


def add(grant: IssuedGrant) -> None:
    with _lock:
        items = _load()
        items.append(asdict(grant))
        _save(items)


def list_all() -> list[dict]:
    with _lock:
        return _load()


def remove(role_name: str) -> dict | None:
    with _lock:
        items = _load()
        match = next((g for g in items if g["role_name"] == role_name), None)
        items = [g for g in items if g["role_name"] != role_name]
        _save(items)
        return match
