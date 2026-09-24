"""SentinelFlow — FastAPI Application Entrypoint."""
import logging
import os
from contextlib import asynccontextmanager

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

# Root service health check
@app.get("/")
async def root():
    return {"service": "SentinelFlow", "status": "ok"}


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
