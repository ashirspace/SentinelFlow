"""SentinelFlow — FastAPI Application Entrypoint."""
import logging
import os
import sys
from pathlib import Path
from contextlib import asynccontextmanager

# Ensure backend directory is in sys.path so modules/sub-packages resolve from any cwd
_BACKEND_DIR = Path(__file__).resolve().parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from fastapi import FastAPI, APIRouter
from starlette.middleware.cors import CORSMiddleware

from core.config import (
    IS_PRODUCTION, CORS_ORIGINS, ADMIN_EMAIL, ADMIN_PASSWORD
)
from core.database import db, mongo_client, init_db_indexes, seed_default_users

# Legacy symbol aliases for backwards compatibility with tests
mongo = mongo_client

# Sub-routers
from routers.auth import router as auth_router
from routers.users import router as users_router
from routers.sources import router as sources_router
from routers.ingest import router as ingest_router, v1_router
from routers.events import router as events_router
from routers.alerts import router as alerts_router
from routers.incidents import router as incidents_router
from routers.reports import router as reports_router
from routers.notifications import router as notifications_router
from routers.dashboard import router as dashboard_router
from routers.rules import router as rules_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("sentinelflow")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycles."""
    # Startup validation
    if IS_PRODUCTION:
        missing = []
        if not ADMIN_EMAIL:
            missing.append("ADMIN_EMAIL")
        if not ADMIN_PASSWORD:
            missing.append("ADMIN_PASSWORD")
        if missing:
            raise RuntimeError(
                "Production startup requires the following environment variables: "
                + ", ".join(missing)
            )

    logger.info("Initializing database indexes...")
    await init_db_indexes()
    await seed_default_users()
    logger.info("SentinelFlow startup complete.")
    yield
    logger.info("Closing MongoDB connection...")
    mongo_client.close()


app = FastAPI(
    title="SentinelFlow",
    description="Explainable, evidence-backed SIEM & SOAR platform.",
    version="2.0.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
    lifespan=lifespan,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Router prefix (/api)
api = APIRouter(prefix="/api")

@api.get("/")
async def api_root():
    return {"service": "SentinelFlow", "status": "ok"}

# Mount all modular sub-routers
api.include_router(auth_router)
api.include_router(users_router)
api.include_router(sources_router)
api.include_router(ingest_router)
api.include_router(events_router)
api.include_router(alerts_router)
api.include_router(incidents_router)
api.include_router(reports_router)
api.include_router(notifications_router)
api.include_router(dashboard_router)
api.include_router(rules_router)

# Mount push-only /api/v1 router
api.include_router(v1_router)

# Also expose v1 router at top-level /api/v1 for backwards compatibility
v1 = v1_router

# Include the main /api router in FastAPI app
app.include_router(api)

# Static frontend serving if build exists
_FRONTEND_BUILD = _BACKEND_DIR.parent / "frontend" / "build"
if _FRONTEND_BUILD.is_dir():
    from starlette.staticfiles import StaticFiles
    from starlette.responses import FileResponse
    from fastapi import HTTPException

    static_path = _FRONTEND_BUILD / "static"
    if static_path.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_path)), name="frontend_static")

    @app.get("/")
    async def serve_root():
        index_file = _FRONTEND_BUILD / "index.html"
        if index_file.is_file():
            return FileResponse(index_file)
        return {"service": "SentinelFlow", "status": "ok"}

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        if full_path.startswith("api") or full_path.startswith("docs") or full_path.startswith("redoc") or full_path.startswith("openapi.json"):
            raise HTTPException(status_code=404, detail="Not found")
        target = _FRONTEND_BUILD / full_path
        if target.is_file():
            return FileResponse(target)
        index_file = _FRONTEND_BUILD / "index.html"
        if index_file.is_file():
            return FileResponse(index_file)
        raise HTTPException(status_code=404, detail="Not found")
else:
    @app.get("/")
    async def root():
        return {"service": "SentinelFlow", "status": "ok"}
