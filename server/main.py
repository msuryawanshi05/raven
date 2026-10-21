"""FastAPI app: /api REST, /ws WebSocket, and the built web UI as static files."""
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from agent import memory
from reporter.builder import _reports_dir
from .api import load_cfg, router as api_router
from .ws import router as ws_router

ROOT = Path(__file__).resolve().parent.parent


def create_app():
    app = FastAPI(title="raven dashboard")
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
        allow_methods=["*"],
        allow_headers=["*"],
    )
    Path(memory.SESSIONS_DIR).mkdir(exist_ok=True)
    _reports_dir(load_cfg()).mkdir(exist_ok=True)

    app.include_router(api_router, prefix="/api")
    app.include_router(ws_router)  # ws route carries its own /ws prefix

    dist = ROOT / "web" / "dist"
    if dist.is_dir():  # only mount when a build exists; keeps API usable without it
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="web")
    return app


app = create_app()
