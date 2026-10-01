import hmac
import logging
import secrets
import threading
import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from . import config, db_introspect, grants, store, vault_client
from .models import DbType, GrantRequest

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("vdba")
config.check_transport()

COOKIE = "vdba_sid"
PRE_COOKIE = "vdba_pre"  # pre-login CSRF token (double submit)
SAFE = {"GET", "HEAD", "OPTIONS"}
GRANT_ID = Path(pattern=r"^vdba_[0-9a-f]{10}$")
templates = Jinja2Templates(directory="app/templates")


@asynccontextmanager
async def lifespan(_: FastAPI):
    store.init()
    stop = threading.Event()
    t = threading.Thread(target=grants.reconcile_loop, args=(stop,), name="reconciler", daemon=True)
    t.start()
    yield
    stop.set()


api = FastAPI(title="Vault DB Access", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


class Guard:
    """Pure-ASGI wrapper: request id, body-size limit, security headers."""

    CSP = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)
        headers = {k.lower(): v for k, v in scope["headers"]}
        rid = uuid.uuid4().hex[:12]
        scope.setdefault("state", {})["request_id"] = rid
        if scope["method"] in {"POST", "PUT", "PATCH"}:
            length = headers.get(b"content-length")
            if length is None or not length.isdigit():
                return await self._reject(send, rid, 411, "Content-Length required")
            if int(length) > config.BODY_LIMIT:
                return await self._reject(send, rid, 413, "request body too large")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                h = message.setdefault("headers", [])
                h += [
                    (b"x-request-id", rid.encode()),
                    (b"cache-control", b"no-store"),
                    (b"pragma", b"no-cache"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", self.CSP.encode()),
                ]
            await send(message)

        await self.inner(scope, receive, send_wrapper)

    @staticmethod
    async def _reject(send, rid, status, text):
        body = f'{{"detail":"{text}"}}'.encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"x-request-id", rid.encode()), (b"cache-control", b"no-store")]})  # fmt: skip
        await send({"type": "http.response.body", "body": body})


# ---- errors ---------------------------------------------------------------------------------


class NotAuthenticated(Exception):
    pass


def _wants_json(request: Request) -> bool:
    return request.url.path.startswith("/api/") or "application/json" in request.headers.get("content-type", "")


@api.exception_handler(NotAuthenticated)
def _unauth(request: Request, _: NotAuthenticated):
    if _wants_json(request):
        return JSONResponse({"detail": "not authenticated"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


@api.exception_handler(RequestValidationError)
def _validation(request: Request, exc: RequestValidationError):
    msg = "; ".join(f"{'.'.join(map(str, e['loc'][1:]))}: {e['msg']}" for e in exc.errors())
    return JSONResponse({"detail": msg or "invalid request"}, status_code=400)


@api.exception_handler(vault_client.VaultUnavailable)
def _vault_down(request: Request, exc: vault_client.VaultUnavailable):
    log.warning("vault unavailable: %s", exc)
    return JSONResponse({"detail": "Vault is unavailable (sealed or unreachable)"}, status_code=503)


@api.exception_handler(Exception)
def _internal(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "-")
    log.error("unhandled %s on %s (request %s)", type(exc).__name__, request.url.path, rid)
    return JSONResponse({"detail": f"internal error (request {rid})"}, status_code=500)


# ---- sessions + CSRF --------------------------------------------------------------------------


def _secure_cookie(request: Request) -> bool:
    if config.COOKIE_SECURE == "auto":
        return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    return config.COOKIE_SECURE == "1"


def _set_cookie(request: Request, response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, httponly=True, samesite="lax", secure=_secure_cookie(request), path="/")


def check_origin(request: Request) -> None:
    site = request.headers.get("sec-fetch-site")
    if site and site not in {"same-origin", "none"}:
        raise HTTPException(403, "cross-site request rejected")
    origin = request.headers.get("origin")
    if origin is None:
        return
    allowed = {request.headers.get("host", "")} | {urlsplit(o).netloc for o in config.EXTRA_ORIGINS}
    if config.PUBLIC_ORIGIN:
        allowed.add(urlsplit(config.PUBLIC_ORIGIN).netloc)
    if origin == "null" or urlsplit(origin).netloc not in allowed:
        raise HTTPException(403, "origin not allowed")


async def _submitted_token(request: Request) -> str:
    tok = request.headers.get("x-csrf-token")
    if tok:
        return tok
    ctype = request.headers.get("content-type", "")
    if ctype.startswith("application/x-www-form-urlencoded"):
        return str((await request.form()).get("csrf_token", ""))
    return ""


def current_session(request: Request) -> dict | None:
    sid = request.cookies.get(COOKIE)
    if not sid:
        return None
    s = store.get_session(sid)
    if s is None:
        return None
    now = time.time()
    if now - s["created_at"] > config.SESSION_ABSOLUTE_SECONDS or now - s["last_seen"] > config.SESSION_IDLE_SECONDS:
        store.delete_session(sid)
        vault_client.revoke_token_quietly(s["vault_token"])
        return None
    checked = False
    if now - s["last_check"] > config.SESSION_RECHECK_SECONDS:
        policies = vault_client.token_policies(s["vault_token"])
        if not policies or config.ADMIN_POLICY_NAME not in policies:
            store.delete_session(sid)
            return None
        checked = True
    store.touch_session(sid, checked)
    return s


async def require_admin(request: Request) -> dict:
    s = await run_in_threadpool(current_session, request)
    if s is None:
        raise NotAuthenticated()
    if request.method not in SAFE:
        check_origin(request)
        if not hmac.compare_digest(await _submitted_token(request), s["csrf"]):
            raise HTTPException(403, "missing or invalid CSRF token")
    return s


def _page(request: Request, name: str, ctx: dict, status: int = 200) -> Response:
    return templates.TemplateResponse(request, name, ctx, status_code=status)


# ---- auth routes ------------------------------------------------------------------------------


@api.get("/healthz")
def healthz():
    return {"status": "ok", "test_hooks": config.TEST_HOOKS}


@api.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None):
    pre = secrets.token_urlsafe(32)
    resp = _page(request, "login.html", {"error": error, "csrf": pre})
    _set_cookie(request, resp, PRE_COOKIE, pre, 1800)
    return resp


@api.post("/login")
async def login_submit(request: Request):
    check_origin(request)
    form = await request.form()
    pre = request.cookies.get(PRE_COOKIE, "")
    if not pre or not hmac.compare_digest(str(form.get("csrf_token", "")), pre):
        raise HTTPException(403, "missing or invalid CSRF token")
    username, password = str(form.get("username", "")), str(form.get("password", ""))

    def fail(msg: str, status: int):
        store.audit(request.state.request_id, None, username[:64], "login", "denied", msg)
        new_pre = secrets.token_urlsafe(32)
        r = _page(request, "login.html", {"error": msg, "csrf": new_pre}, status)
        _set_cookie(request, r, PRE_COOKIE, new_pre, 1800)
        return r

    if not username or not password or len(username) > 128 or len(password) > 512:
        return fail("Invalid credentials", 401)
    try:
        token, policies = await run_in_threadpool(vault_client.userpass_login, username, password)
    except PermissionError:
        return fail("Invalid credentials", 401)
    if config.ADMIN_POLICY_NAME not in policies:
        await run_in_threadpool(vault_client.revoke_token_quietly, token)
        return fail("This account is not a portal administrator", 403)
    old = request.cookies.get(COOKIE)
    if old:
        store.delete_session(old)  # login always issues a fresh session id
    sid, _ = store.create_session(username, token)
    store.audit(request.state.request_id, None, username, "login", "ok")
    resp = RedirectResponse("/", status_code=303)
    _set_cookie(request, resp, COOKIE, sid, config.SESSION_ABSOLUTE_SECONDS)
    resp.delete_cookie(PRE_COOKIE, path="/")
    return resp


@api.post("/logout")
async def logout(request: Request, s: dict = Depends(require_admin)):
    store.delete_session(s["sid"])
    await run_in_threadpool(vault_client.revoke_token_quietly, s["vault_token"])
    store.audit(request.state.request_id, None, s["username"], "logout", "ok")
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE, path="/")
    return resp  # issued grants are owned by per-grant tokens, so they survive the logout


# ---- UI ---------------------------------------------------------------------------------------


def _index(request: Request, s: dict, result=None, error=None, status: int = 200) -> Response:
    try:
        pg = db_introspect.postgres_catalog().tables
        ch = db_introspect.clickhouse_catalog().tables
    except Exception as exc:  # noqa: BLE001
        log.warning("catalog lookup failed: %s", type(exc).__name__)
        pg, ch = [], []
        error = error or "Could not list tables (database unreachable?)"
    return _page(
        request, "index.html",
        {
            "username": s["username"], "csrf": s["csrf"], "pg_tables": pg, "ch_tables": ch,
            "pg_commands": config.ALLOWED_POSTGRES_COMMANDS, "ch_commands": config.ALLOWED_CLICKHOUSE_COMMANDS,
            "grants": [grants.public(g) for g in store.list_grants(limit=100)],
            "result": result, "error": error, "ttl_min": config.TTL_MIN, "ttl_max": config.TTL_MAX,
        },
        status,
    )  # fmt: skip


@api.get("/", response_class=HTMLResponse)
async def index(request: Request, s: dict = Depends(require_admin)):
    return await run_in_threadpool(_index, request, s)


def _issue(request: Request, s: dict, req: GrantRequest) -> dict:
    try:
        return grants.issue(req, s["username"], request.state.request_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except grants.Busy as exc:
        raise HTTPException(503, str(exc)) from exc
    except vault_client.VaultUnavailable:
        raise
    except Exception as exc:
        raise HTTPException(502, f"issuing failed and was rolled back (request {request.state.request_id})") from exc


@api.post("/grants", response_class=HTMLResponse)
async def create_grant_form(request: Request, s: dict = Depends(require_admin)):
    form = await request.form()
    try:
        ttl = int(str(form.get("ttl_seconds", "")).strip())
        req = GrantRequest.model_validate({
            "db_type": form.get("db_type"), "scope": form.get("scope"),
            "tables": form.getlist("tables"), "commands": form.getlist("commands"),
            "ttl_seconds": ttl, "requested_for": form.get("requested_for", ""),
        })  # fmt: skip
        result = await run_in_threadpool(_issue, request, s, req)
    except (ValueError, ValidationError) as exc:
        msg = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, ValidationError) else "invalid form input"
        return await run_in_threadpool(_index, request, s, None, msg, 400)
    except HTTPException as exc:
        return await run_in_threadpool(_index, request, s, None, exc.detail, exc.status_code)
    return await run_in_threadpool(_index, request, s, result)


@api.post("/grants/{grant_id}/revoke")
@api.post("/api/grants/{grant_id}/revoke")
async def revoke_grant(request: Request, grant_id: str = GRANT_ID, s: dict = Depends(require_admin)):
    try:
        g = await run_in_threadpool(grants.revoke, grant_id, s["username"], request.state.request_id)
    except grants.NotFound as exc:
        raise HTTPException(404, "grant not found") from exc
    except grants.Busy as exc:
        raise HTTPException(503, str(exc)) from exc
    except vault_client.VaultUnavailable:
        raise
    except Exception as exc:
        raise HTTPException(502, f"revocation incomplete, will be retried (request {request.state.request_id})") from exc
    if _wants_json(request) or request.headers.get("accept", "").startswith("application/json"):
        return g
    return RedirectResponse("/", status_code=303)


# ---- JSON API ---------------------------------------------------------------------------------


@api.get("/api/session")
def api_session(s: dict = Depends(require_admin)):
    return {"username": s["username"], "csrf_token": s["csrf"]}


@api.post("/api/grants")
async def api_create_grant(request: Request, body: GrantRequest, s: dict = Depends(require_admin)):
    if "application/json" not in request.headers.get("content-type", ""):
        raise HTTPException(415, "Content-Type must be application/json")
    return await run_in_threadpool(_issue, request, s, body)  # one-time password; no-store via Guard


@api.get("/api/grants")
def api_list_grants(_: dict = Depends(require_admin)):
    return [grants.public(g) for g in store.list_grants(limit=500)]


@api.get("/api/tables/{db_type}")
async def api_list_tables(db_type: DbType, _: dict = Depends(require_admin)):
    cat = await run_in_threadpool(db_introspect.catalog, db_type)
    return {"tables": cat.tables}


# ---- settings (rotation only: connection config is written by setup, never by the UI) ---------


@api.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, message: str | None = None, s: dict = Depends(require_admin)):
    return _page(request, "settings.html", {"username": s["username"], "csrf": s["csrf"], "message": message})


@api.post("/settings/{db_type}/rotate")
async def rotate_connection(request: Request, db_type: DbType, s: dict = Depends(require_admin)):
    try:
        await run_in_threadpool(vault_client.rotate_root, db_type)
    except vault_client.VaultUnavailable:
        raise
    except Exception as exc:
        store.audit(request.state.request_id, None, s["username"], "rotate", "error", db_type.value)
        raise HTTPException(502, f"rotation failed (request {request.state.request_id})") from exc
    store.audit(request.state.request_id, None, s["username"], "rotate", "ok", db_type.value)
    if _wants_json(request):
        return {"status": "rotated", "db_type": db_type.value}
    return RedirectResponse(f"/settings?message=Manager+credential+for+{db_type.value}+rotated", status_code=303)


app = Guard(api)
