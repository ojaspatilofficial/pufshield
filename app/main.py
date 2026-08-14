"""PUFShield FastAPI application entry point."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
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

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.app_host, port=settings.app_port)
