"""Database connection and index initialization for SentinelFlow."""
import os
import logging
from datetime import datetime, timezone
from auth import hash_password, verify_password
from core.config import MONGO_URL, DB_NAME, ADMIN_EMAIL, ADMIN_PASSWORD, IS_PRODUCTION

logger = logging.getLogger("sentinelflow.db")

use_mock = os.getenv("USE_MOCK_DB", "").lower() in ("true", "1") or str(MONGO_URL).startswith("mongomock://")

if use_mock:
    from mongomock_motor import AsyncMongoMockClient
    mongo_client = AsyncMongoMockClient()
    logger.info("Using in-memory AsyncMongoMockClient for database.")
else:
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        mongo_client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=2000)
    except Exception as exc:
        logger.warning("Could not initialize AsyncIOMotorClient, falling back to mock: %s", exc)
        from mongomock_motor import AsyncMongoMockClient
        mongo_client = AsyncMongoMockClient()

db = mongo_client[DB_NAME]


def get_db():
    """Return database instance."""
    return db


async def init_db_indexes():
    """Create all necessary MongoDB indexes and TTL indexes."""
    try:
        await db.users.create_index("email", unique=True)
        await db.login_attempts.create_index("identifier")
        await db.normalized_events.create_index("timestamp")
        await db.normalized_events.create_index("event_id")
        await db.normalized_events.create_index("src_ip")
        await db.normalized_events.create_index("user")
        await db.normalized_events.create_index("source_name")
        await db.normalized_events.create_index("reviewed")
        await db.alerts.create_index("created_at")
        await db.alerts.create_index("status")
        await db.log_sources.create_index("name", unique=True)
        await db.known_devices.create_index([("user", 1), ("src_ip", 1), ("user_agent", 1)], unique=True)
        await db.alert_notifications.create_index("expires_at", expireAfterSeconds=0)
        try:
            existing_idx = await db.raw_logs.index_information()
            if "created_at_bson_1" in existing_idx:
                await db.raw_logs.drop_index("created_at_bson_1")
        except Exception:
            pass
        await db.raw_logs.create_index("expires_at", expireAfterSeconds=0)
        await db.raw_logs.create_index("source_name")
        await db.ip_blocklist.create_index("ip", unique=True)
        await db.incidents.create_index("opened_at")
        await db.response_actions.create_index("alert_id")
        await db.response_actions.create_index("created_at")
        await db.saved_searches.create_index([("owner", 1), ("name", 1)], unique=True)
        logger.info("MongoDB indexes verified.")
    except Exception as exc:
        logger.warning("Index initialization notice: %s", exc)


async def seed_default_users():
    """Seed admin and demo analyst users."""
    existing_admin = await db.users.find_one({"email": ADMIN_EMAIL})
    if not existing_admin:
        await db.users.insert_one({
            "email": ADMIN_EMAIL,
            "password_hash": hash_password(ADMIN_PASSWORD),
            "name": "SentinelFlow Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("Seeded admin user: %s", ADMIN_EMAIL)
    elif not verify_password(ADMIN_PASSWORD, existing_admin["password_hash"]):
        await db.users.update_one(
            {"email": ADMIN_EMAIL},
            {"$set": {"password_hash": hash_password(ADMIN_PASSWORD)}},
        )

    # Ensure mouryar997@gmail.com is also seeded
    user_email = "mouryar997@gmail.com"
    existing_user = await db.users.find_one({"email": user_email})
    if not existing_user:
        await db.users.insert_one({
            "email": user_email,
            "password_hash": hash_password("Admin@12345"),
            "name": "Rohit Mourya",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("Seeded user: %s", user_email)
    elif not verify_password("Admin@12345", existing_user["password_hash"]):
        await db.users.update_one(
            {"email": user_email},
            {"$set": {"password_hash": hash_password("Admin@12345")}},
        )

    if not IS_PRODUCTION:
        analyst_email = "analyst@sentinelflow.io"
        if not await db.users.find_one({"email": analyst_email}):
            await db.users.insert_one({
                "email": analyst_email,
                "password_hash": hash_password("Analyst@123"),
                "name": "Demo Analyst",
                "role": "analyst",
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
            logger.info("Seeded analyst user: %s", analyst_email)
