import datetime
import secrets
from dataclasses import asdict

import hvac
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import bootstrap, config, db_introspect, grant_store, vault_client
from .models import CredentialType, DbType, GrantRequest, IssuedGrant, Scope
from .statement_builder import build_statements

app = FastAPI(title="Vault DB Access Admin")
templates = Jinja2Templates(directory="app/templates")

_session_key = config.SESSION_SECRET_KEY or secrets.token_hex(32)
if not config.SESSION_SECRET_KEY:
    print("WARNING: SESSION_SECRET_KEY not set, using an ephemeral key (sessions won't survive a restart)")
app.add_middleware(SessionMiddleware, secret_key=_session_key)


class NotAuthenticated(Exception):
    pass


@app.exception_handler(NotAuthenticated)
def _not_authenticated_handler(request: Request, exc: NotAuthenticated):
    return RedirectResponse("/login", status_code=303)


def get_admin_client(request: Request) -> hvac.Client:
    """Every privileged action runs as the logged-in admin's own Vault token,
    never a shared/root credential -- Vault's ACLs are the only source of truth
    for who is allowed to do this."""
    token = request.session.get("vault_token")
    if not token:
        raise NotAuthenticated()
    c = vault_client.get_client(token)
    try:
        lookup = c.auth.token.lookup_self()
    except Exception:
        raise NotAuthenticated()
    policies = lookup["data"].get("policies", [])
    if config.ADMIN_POLICY_NAME not in policies:
        raise NotAuthenticated()
    return c


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    c = vault_client.get_client(None)
    try:
        result = c.auth.userpass.login(username=username, password=password)
    except Exception:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid credentials"}, status_code=401
        )

    token = result["auth"]["client_token"]
    policies = result["auth"].get("token_policies", [])
    if config.ADMIN_POLICY_NAME not in policies:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "This account does not have DB-access admin rights in Vault"},
            status_code=403,
        )

    request.session["vault_token"] = token
    request.session["username"] = username
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    token = request.session.get("vault_token")
    if token:
        try:
            vault_client.get_client(token).auth.token.revoke_self()
        except Exception:
            pass
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


def _render_index(request: Request, result=None, error=None, status_code: int = 200):
    pg_tables = db_introspect.list_postgres_tables()
    ch_tables = db_introspect.list_clickhouse_tables()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "username": request.session.get("username"),
            "pg_tables": pg_tables,
            "ch_tables": ch_tables,
            "pg_commands": config.ALLOWED_POSTGRES_COMMANDS,
            "ch_commands": config.ALLOWED_CLICKHOUSE_COMMANDS,
            "grants": grant_store.list_all(),
            "result": result,
            "error": error,
        },
        status_code=status_code,
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request, _: hvac.Client = Depends(get_admin_client)):
    return _render_index(request)


@app.post("/grants", response_class=HTMLResponse)
def create_grant(
    request: Request,
    db_type: DbType = Form(...),
    scope: Scope = Form(...),
    tables: list[str] = Form(default=[]),
    commands: list[str] = Form(default=[]),
    allow_create: bool = Form(default=False),
    credential_type: CredentialType = Form(...),
    ttl_seconds: int = Form(...),
    requested_for: str = Form(...),
    client: hvac.Client = Depends(get_admin_client),
):
    known_tables = set(
        db_introspect.list_postgres_tables() if db_type == DbType.postgres else db_introspect.list_clickhouse_tables()
    )

    try:
        req = GrantRequest(
            db_type=db_type,
            scope=scope,
            tables=tables,
            commands=commands,
            allow_create=allow_create,
            credential_type=credential_type,
            ttl_seconds=ttl_seconds,
            requested_for=requested_for.strip(),
        )
        if not req.requested_for:
            raise ValueError("'issued to' must not be empty")
        result = _issue_grant(client, req, known_tables, request.session.get("username", "unknown"))
        return _render_index(request, result=result)
    except ValueError as exc:
        return _render_index(request, error=str(exc), status_code=400)


def _issue_grant(client: hvac.Client, req: GrantRequest, known_tables: set[str], issued_by: str) -> IssuedGrant:
    creation_statements, revocation_statements = build_statements(
        req.db_type, req.scope, req.tables, req.commands, req.allow_create, known_tables
    )
    role_name = vault_client.new_role_name()
    vault_client.create_role(
        client, role_name, req.db_type, creation_statements, revocation_statements, req.ttl_seconds
    )

    grant = IssuedGrant(
        role_name=role_name,
        db_type=req.db_type.value,
        scope=req.scope.value,
        tables=req.tables,
        commands=req.commands,
        allow_create=req.allow_create,
        credential_type=req.credential_type.value,
        ttl_seconds=req.ttl_seconds,
        created_at=datetime.datetime.utcnow().isoformat() + "Z",
        requested_for=req.requested_for,
        issued_by=issued_by,
    )

    if req.credential_type == CredentialType.password:
        creds = vault_client.read_credentials(client, role_name)
        grant.username = creds["username"]
        grant.password = creds["password"]
    else:
        token_info = vault_client.issue_token_grant(client, role_name, req.ttl_seconds)
        grant.vault_token = token_info["vault_token"]
        grant.policy_name = token_info["policy_name"]

    grant_store.add(grant)
    return grant


@app.post("/grants/{role_name}/revoke")
def revoke_grant(role_name: str, client: hvac.Client = Depends(get_admin_client)):
    grant = grant_store.remove(role_name)
    if grant is None:
        raise HTTPException(status_code=404, detail="grant not found")
    vault_client.revoke_grant(client, role_name, grant.get("policy_name"))
    return {"status": "revoked", "role_name": role_name}


@app.post("/api/grants")
async def api_create_grant(request: Request, client: hvac.Client = Depends(get_admin_client)):
    payload = await request.json()
    db_type = DbType(payload["db_type"])
    known_tables = set(
        db_introspect.list_postgres_tables() if db_type == DbType.postgres else db_introspect.list_clickhouse_tables()
    )

    req = GrantRequest(
        db_type=db_type,
        scope=Scope(payload["scope"]),
        tables=payload.get("tables", []),
        commands=payload.get("commands", []),
        allow_create=payload.get("allow_create", False),
        credential_type=CredentialType(payload["credential_type"]),
        ttl_seconds=payload["ttl_seconds"],
        requested_for=payload.get("requested_for", "test"),
    )
    try:
        grant = _issue_grant(client, req, known_tables, request.session.get("username", "unknown"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return asdict(grant)


@app.get("/api/grants")
def api_list_grants(_: hvac.Client = Depends(get_admin_client)):
    return grant_store.list_all()


@app.get("/api/tables/{db_type}")
def api_list_tables(db_type: DbType, _: hvac.Client = Depends(get_admin_client)):
    if db_type == DbType.postgres:
        return {"tables": db_introspect.list_postgres_tables()}
    return {"tables": db_introspect.list_clickhouse_tables()}


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, _: hvac.Client = Depends(get_admin_client), message: str | None = None):
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "username": request.session.get("username"), "message": message},
    )


@app.post("/settings/{db_type}")
def update_connection(
    db_type: DbType,
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    client: hvac.Client = Depends(get_admin_client),
):
    if db_type == DbType.postgres:
        bootstrap.ensure_postgres_connection(client, username, password)
    else:
        bootstrap.ensure_clickhouse_connection(client, username, password)
    return RedirectResponse(f"/settings?message=Connection+for+{db_type.value}+updated", status_code=303)


@app.post("/settings/{db_type}/rotate")
def rotate_connection(db_type: DbType, client: hvac.Client = Depends(get_admin_client)):
    name = config.POSTGRES_CONNECTION_NAME if db_type == DbType.postgres else config.CLICKHOUSE_CONNECTION_NAME
    client.write(f"database/rotate-root/{name}")
    return RedirectResponse(
        f"/settings?message=Root+credential+for+{db_type.value}+rotated+(Vault+now+knows+it,+no+one+else+does)",
        status_code=303,
    )
