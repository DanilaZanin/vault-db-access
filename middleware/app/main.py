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


class TooLarge(Exception):
    pass


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
        te, length = headers.get(b"transfer-encoding"), headers.get(b"content-length")
        if te is not None and length is not None:  # request-smuggling shape: never trust either
            return await self._reject(send, rid, 400, "Transfer-Encoding and Content-Length together")
        if length is not None and (not length.isdigit() or int(length) > config.BODY_LIMIT):
            return await self._reject(send, rid, 413, "request body too large")
        received = 0
        exceeded = False

        async def counting_receive():
            # Count real bytes on the stream: Content-Length alone proves nothing for chunked bodies.
            nonlocal received, exceeded
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > config.BODY_LIMIT:
                    exceeded = True
                    raise TooLarge()
            return msg

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                if exceeded and message["status"] == 400:
                    message["status"] = 413  # FastAPI turns any body-read error on JSON endpoints into a 400
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

        await self.inner(scope, counting_receive, send_wrapper)

    @staticmethod
    async def _reject(send, rid, status, text):
        body = f'{{"detail":"{text}"}}'.encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"x-request-id", rid.encode()),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


# ---- errors ---------------------------------------------------------------------------------


class NotAuthenticated(Exception):
    pass


@api.exception_handler(TooLarge)
def _too_large(request: Request, _: TooLarge):
    return JSONResponse({"detail": "request body too large"}, status_code=413)


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
    response.set_cookie(
        name, value, max_age=max_age, httponly=True, samesite="lax", secure=_secure_cookie(request), path="/"
    )


def check_origin(request: Request) -> None:
    """State-changing requests must prove they are same-origin: a browser always sends Origin and/or
    Sec-Fetch-Site; API clients must send `Origin` equal to the Host they call. Neither present = reject."""
    site = request.headers.get("sec-fetch-site")
    origin = request.headers.get("origin")
    if site and site not in {"same-origin", "none"}:
        raise HTTPException(403, "cross-site request rejected")
    if not origin and not site:
        raise HTTPException(403, "Origin header required")
    if not origin:
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
        # Re-validate against the CURRENT state: the token's own policy list is frozen at login, so
        # deleting the user or removing db-access-admin would otherwise go unnoticed.
        try:
            with grants.admit("session"):  # admission BEFORE any Vault I/O, separate from issue/revoke capacity
                current = vault_client.user_policies(s["username"])
                alive = vault_client.token_policies(s["vault_token"])
        except grants.Busy as exc:
            raise HTTPException(503, str(exc)) from exc
        if not current or config.ADMIN_POLICY_NAME not in current or not alive:
            store.delete_session(sid)
            vault_client.revoke_token_quietly(s["vault_token"])
            store.audit(None, None, s["username"], "session", "ended", "admin rights removed")
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
    return {"status": "ok", "test_hooks": config.TEST_HOOKS, "recheck": config.SESSION_RECHECK_SECONDS}


@api.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None):
    pre = secrets.token_urlsafe(32)
    resp = _page(request, "login.html", {"error": error, "csrf": pre})
    _set_cookie(request, resp, PRE_COOKIE, pre, 1800)
    return resp


def _login_page(request: Request, msg: str, status: int, username: str = "") -> Response:
    store.audit(request.state.request_id, None, username[:64], "login", "denied", msg)
    new_pre = secrets.token_urlsafe(32)
    r = _page(request, "login.html", {"error": msg, "csrf": new_pre}, status)
    _set_cookie(request, r, PRE_COOKIE, new_pre, 1800)
    return r


def _do_login(request: Request, username: str, password: str) -> Response:
    """Blocking work (Vault + SQLite) runs in the threadpool, under its own admission limit."""
    try:
        with grants.admit("auth"):
            if not username or not password or len(username) > 128 or len(password) > 512:
                return _login_page(request, "Invalid credentials", 401, username)
            try:
                token, policies = vault_client.userpass_login(username, password)
            except PermissionError:
                return _login_page(request, "Invalid credentials", 401, username)
            if config.ADMIN_POLICY_NAME not in policies:
                vault_client.revoke_token_quietly(token)
                return _login_page(request, "This account is not a portal administrator", 403, username)
            old = request.cookies.get(COOKIE)
            if old:  # login always issues a fresh session id; the previous session's Vault token dies too
                prev = store.get_session(old)
                store.delete_session(old)
                if prev:
                    vault_client.revoke_token_quietly(prev["vault_token"])
            sid, _ = store.create_session(username, token)
            store.audit(request.state.request_id, None, username, "login", "ok")
    except grants.Busy as exc:
        raise HTTPException(503, str(exc)) from exc
    resp = RedirectResponse("/", status_code=303)
    _set_cookie(request, resp, COOKIE, sid, config.SESSION_ABSOLUTE_SECONDS)
    resp.delete_cookie(PRE_COOKIE, path="/")
    return resp


@api.post("/login")
async def login_submit(request: Request):
    check_origin(request)
    form = await request.form()
    pre = request.cookies.get(PRE_COOKIE, "")
    if not pre or not hmac.compare_digest(str(form.get("csrf_token", "")), pre):
        raise HTTPException(403, "missing or invalid CSRF token")
    return await run_in_threadpool(_do_login, request, str(form.get("username", "")), str(form.get("password", "")))


def _do_logout(request: Request, s: dict) -> Response:
    sid = request.cookies.get(COOKIE, "")
    store.delete_session(sid)
    vault_client.revoke_token_quietly(s["vault_token"])
    store.audit(request.state.request_id, None, s["username"], "logout", "ok")
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE, path="/")
    return resp  # issued grants are owned by per-grant tokens, so they survive the logout


@api.post("/logout")
async def logout(request: Request, s: dict = Depends(require_admin)):
    return await run_in_threadpool(_do_logout, request, s)


# ---- UI ---------------------------------------------------------------------------------------


def _index(request: Request, s: dict, result=None, error=None, status: int = 200) -> Response:
    tables: dict[DbType, list[str]] = {}
    for db in DbType:  # one database being down must not hide the other one's tables
        try:
            with grants.admit("issue"):
                tables[db] = db_introspect.catalog(db).tables
        except grants.Busy:
            tables[db] = []
            error = error or "Server busy, try again"
        except Exception as exc:  # noqa: BLE001
            log.warning("catalog lookup for %s failed: %s", db.value, type(exc).__name__)
            tables[db] = []
            error = error or f"Could not list {db.value} tables (database unreachable?)"
    pg, ch = tables[DbType.postgres], tables[DbType.clickhouse]
    return _page(
        request,
        "index.html",
        {
            "username": s["username"],
            "csrf": s["csrf"],
            "pg_tables": pg,
            "ch_tables": ch,
            "pg_commands": config.ALLOWED_POSTGRES_COMMANDS,
            "ch_commands": config.ALLOWED_CLICKHOUSE_COMMANDS,
            "grants": [grants.public(g) for g in store.list_grants(limit=100)],
            "result": result,
            "error": error,
            "ttl_min": config.TTL_MIN,
            "ttl_max": config.TTL_MAX,
        },
        status,
    )


@api.get("/", response_class=HTMLResponse)
async def index(request: Request, s: dict = Depends(require_admin)):
    return await run_in_threadpool(_index, request, s)


def _issue(request: Request, s: dict, req: GrantRequest) -> dict:
    try:
        with grants.admit("issue"):
            return grants.issue(req, s["username"], request.state.request_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except grants.Busy as exc:
        raise HTTPException(503, str(exc)) from exc
    except vault_client.VaultUnavailable:
        raise
    except Exception as exc:
        log.warning("issue failed: %s: %s", type(exc).__name__, exc)
        raise HTTPException(502, f"issuing failed and was rolled back (request {request.state.request_id})") from exc


@api.post("/grants", response_class=HTMLResponse)
async def create_grant_form(request: Request, s: dict = Depends(require_admin)):
    form = await request.form()
    try:
        ttl = int(str(form.get("ttl_seconds", "")).strip())
        req = GrantRequest.model_validate(
            {
                "db_type": form.get("db_type"),
                "scope": form.get("scope"),
                "tables": form.getlist("tables"),
                "commands": form.getlist("commands"),
                "ttl_seconds": ttl,
                "requested_for": form.get("requested_for", ""),
            }
        )
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
    def work():
        with grants.admit("revoke"):
            return grants.revoke(grant_id, s["username"], request.state.request_id)

    try:
        g = await run_in_threadpool(work)
    except grants.NotFound as exc:
        raise HTTPException(404, "grant not found") from exc
    except grants.Busy as exc:
        raise HTTPException(503, str(exc)) from exc
    except vault_client.VaultUnavailable:
        raise
    except Exception as exc:
        raise HTTPException(
            502, f"revocation incomplete, will be retried (request {request.state.request_id})"
        ) from exc
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
    def work():
        with grants.admit("issue"):
            return db_introspect.catalog(db_type).tables

    try:
        return {"tables": await run_in_threadpool(work)}
    except grants.Busy as exc:
        raise HTTPException(503, str(exc)) from exc


# ---- settings (rotation only: connection config is written by setup, never by the UI) ---------


@api.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, message: str | None = None, s: dict = Depends(require_admin)):
    return _page(request, "settings.html", {"username": s["username"], "csrf": s["csrf"], "message": message})


@api.post("/settings/{db_type}/rotate")
async def rotate_connection(request: Request, db_type: DbType, s: dict = Depends(require_admin)):
    def work():
        with grants.admit("issue"):
            try:
                vault_client.rotate_root(db_type)
            except vault_client.VaultUnavailable:
                raise
            except Exception as exc:
                store.audit(request.state.request_id, None, s["username"], "rotate", "error", db_type.value)
                log.warning("rotate %s failed: %s", db_type.value, exc)
                raise HTTPException(502, f"rotation failed (request {request.state.request_id})") from exc
            store.audit(request.state.request_id, None, s["username"], "rotate", "ok", db_type.value)

    try:
        await run_in_threadpool(work)
    except grants.Busy as exc:
        raise HTTPException(503, str(exc)) from exc
    if _wants_json(request):
        return {"status": "rotated", "db_type": db_type.value}
    return RedirectResponse(f"/settings?message=Manager+credential+for+{db_type.value}+rotated", status_code=303)


app = Guard(api)
