"""PUFShield FastAPI application entry point."""

from __future__ import annotations

import logging
import secrets
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Cookie, FastAPI, Form, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .api import router as api_router
from .config import get_settings
from .pki import PKIError

settings = get_settings()
logging.basicConfig(level=settings.log_level.upper())

app = FastAPI(
    title="PUFShield",
    description="SRAM PUF + PKI based device authentication for secure boot.",
    version="0.1.0",
    debug=settings.app_debug,
)


@app.exception_handler(PKIError)
async def pki_error_handler(request: Request, exc: PKIError) -> JSONResponse:
    """Map internal PKI failures to a clean 500 instead of a bare traceback."""
    return JSONResponse(status_code=500, content={"detail": f"PKI error: {exc}"})


app.include_router(api_router)

FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
PAGES_DIR = STATIC_DIR / "pages"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ---------------------------------------------------------------------------
# Simple session store (demo-only, not production auth)
# ---------------------------------------------------------------------------
_sessions: dict[str, dict] = {}
_registered_users: dict[str, dict] = {"admin": {"username": "admin", "password": "pufshield"}}

COOKIE_NAME = "pufshield_session"
COOKIE_MAX_AGE = 86400  # 24 hours


def _create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = {"username": username}
    return token


def _validate_session(token: str | None) -> bool:
    return bool(token and token in _sessions)


def _get_session_username(token: str | None) -> str | None:
    if token and token in _sessions:
        return _sessions[token]["username"]
    return None


def _destroy_session(token: str | None) -> None:
    if token and token in _sessions:
        del _sessions[token]


def _redirect_to_login(request: Request, destination: str) -> RedirectResponse:
    params = urlencode({"redirect": destination})
    return RedirectResponse(url=f"/login?{params}", status_code=302)


# ---------------------------------------------------------------------------
# Auth API (simple demo login/logout/register)
# ---------------------------------------------------------------------------

@app.post("/api/auth/login", include_in_schema=False)
async def login_api(response: Response, username: str = Form(...), password: str = Form(...)):
    user = _registered_users.get(username)
    if user and user["password"] == password:
        token = _create_session(username)
        response.set_cookie(
            COOKIE_NAME, token, max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax",
        )
        return {"status": "ok", "username": username}
    return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})


@app.post("/api/auth/register", include_in_schema=False)
async def register_api(response: Response, username: str = Form(...), password: str = Form(...)):
    if not username or not password:
        return JSONResponse(status_code=400, content={"detail": "Username and password are required"})
    if len(username) < 3:
        return JSONResponse(status_code=400, content={"detail": "Username must be at least 3 characters"})
    if len(password) < 6:
        return JSONResponse(status_code=400, content={"detail": "Password must be at least 6 characters"})
    if username in _registered_users:
        return JSONResponse(status_code=409, content={"detail": "Username already exists"})
    _registered_users[username] = {"username": username, "password": password}
    token = _create_session(username)
    response.set_cookie(
        COOKIE_NAME, token, max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax",
    )
    return {"status": "ok", "username": username}


@app.post("/api/auth/logout", include_in_schema=False)
async def logout_api(response: Response, pufshield_session: str | None = Cookie(None)):
    _destroy_session(pufshield_session)
    response.delete_cookie(COOKIE_NAME)
    return {"status": "ok"}


@app.get("/api/auth/status", include_in_schema=False)
async def auth_status(pufshield_session: str | None = Cookie(None)):
    username = _get_session_username(pufshield_session)
    if username:
        return {"authenticated": True, "username": username}
    return {"authenticated": False}


# ---------------------------------------------------------------------------
# Page routes — public pages (no auth required)
# ---------------------------------------------------------------------------

def _page(filename: str) -> FileResponse:
    return FileResponse(PAGES_DIR / filename)


@app.get("/", include_in_schema=False)
def landing_page() -> FileResponse:
    return _page("landing.html")


@app.get("/about", include_in_schema=False)
def about_page() -> FileResponse:
    return _page("about.html")


@app.get("/features", include_in_schema=False)
def features_page() -> FileResponse:
    return _page("features.html")


@app.get("/how-it-works", include_in_schema=False)
def how_it_works_page() -> FileResponse:
    return _page("how-it-works.html")


@app.get("/architecture", include_in_schema=False)
def architecture_page() -> FileResponse:
    return _page("architecture.html")


@app.get("/demo", include_in_schema=False)
def demo_page() -> FileResponse:
    return _page("demo.html")


@app.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    return _page("login.html")


@app.get("/register", include_in_schema=False)
def register_page() -> FileResponse:
    return _page("register.html")


# ---------------------------------------------------------------------------
# Page routes — PROTECTED console pages (auth required)
# ---------------------------------------------------------------------------

def _serve_dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page(
    request: Request,
    pufshield_session: str | None = Cookie(None),
):
    if _validate_session(pufshield_session):
        return _serve_dashboard()
    return _redirect_to_login(request, "/dashboard")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.app_host, port=settings.app_port)
