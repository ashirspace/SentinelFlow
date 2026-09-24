"""Centralized configuration for SentinelFlow."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from backend directory if present
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

ENVIRONMENT = (os.environ.get("ENVIRONMENT") or os.environ.get("ENV") or "development").strip().lower()
IS_PRODUCTION = ENVIRONMENT == "production"

MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.environ.get("DB_NAME", "test_database")
REDIS_URL = os.environ.get("REDIS_URL", "").strip()

JWT_SECRET = os.environ.get("JWT_SECRET", "8f2c6b1a9d4e7f5c3b2a8e6d1c9f4b7a5e3d2c8b6a4f1e9d7c5b3a2f8e6d4c1b")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")
CORS_ORIGINS = [orig.strip() for orig in os.environ.get("CORS_ORIGINS", "*").split(",") if orig.strip()]
if FRONTEND_URL and FRONTEND_URL not in CORS_ORIGINS and "*" not in CORS_ORIGINS:
    CORS_ORIGINS.append(FRONTEND_URL)

ADMIN_EMAIL = (os.environ.get("ADMIN_EMAIL") or "admin@sentinelflow.io").lower().strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "Admin@12345"

PUBLIC_INGEST_URL = (
    os.environ.get("PUBLIC_INGEST_URL")
    or os.environ.get("BACKEND_PUBLIC_URL")
    or os.environ.get("FRONTEND_URL", "")
).rstrip("/")
