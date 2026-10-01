from pathlib import Path

import jinja2
import pytest

TEMPLATES = Path(__file__).resolve().parents[2] / "middleware" / "app" / "templates"
GRANT = {
    "grant_id": "vdba_0123456789",
    "requested_for": "<b>x</b>",
    "issued_by": "admin",
    "db_type": "postgres",
    "scope": "tables",
    "tables": ["a"],
    "commands": ["SELECT"],
    "status": "active",
    "expires_at": "t",
    "username": "u",
}
CTX = {
    "username": "admin",
    "csrf": "tok",
    "error": "boom",
    "message": "ok",
    "pg_tables": ["a"],
    "ch_tables": ["a"],
    "pg_commands": ["SELECT"],
    "ch_commands": ["SELECT"],
    "grants": [GRANT],
    "ttl_min": 10,
    "ttl_max": 100,
    "result": {**GRANT, "password": "pw"},
}


@pytest.mark.parametrize("name", ["index.html", "login.html", "settings.html"])
def test_templates_render_and_escape(name):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES), autoescape=True)
    html = env.get_template(name).render(**CTX)
    assert "<b>x</b>" not in html  # user-supplied text is escaped
    if name != "login.html":
        assert 'name="csrf_token"' in html
