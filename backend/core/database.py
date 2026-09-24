"""Database connection and index initialization for SentinelFlow."""
import logging
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from auth import hash_password, verify_password
from core.config import MONGO_URL, DB_NAME, ADMIN_EMAIL, ADMIN_PASSWORD, IS_PRODUCTION

logger = logging.getLogger("sentinelflow.db")

mongo_client: AsyncIOMotorClient = AsyncIOMotorClient(MONGO_URL)
db = mongo_client[DB_NAME]


def get_db():
    """Return database instance."""
    return db


async def init_db_indexes():
    """Create all necessary MongoDB indexes and TTL indexes."""
    # User and Auth indexes
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier")

    # Events & Alerts indexes
    await db.normalized_events.create_index("timestamp")
    await db.normalized_events.create_index("event_id")
    await db.normalized_events.create_index("src_ip")
    await db.normalized_events.create_index("user")
    await db.normalized_events.create_index("source_name")
    await db.normalized_events.create_index("reviewed")
    await db.alerts.create_index("created_at")
    await db.alerts.create_index("status")

    # Sources & Device tracking
    await db.log_sources.create_index("name", unique=True)
    await db.known_devices.create_index([("user", 1), ("src_ip", 1), ("user_agent", 1)], unique=True)

    # Notification dedup TTL
    await db.alert_notifications.create_index("expires_at", expireAfterSeconds=0)

    # Raw logs retention TTL index
    try:
        existing_idx = await db.raw_logs.index_information()
        if "created_at_bson_1" in existing_idx:
            await db.raw_logs.drop_index("created_at_bson_1")
    except Exception:
        pass
    await db.raw_logs.create_index("expires_at", expireAfterSeconds=0)
    await db.raw_logs.create_index("source_name")

    # Blocklist, Incidents & Response actions
    await db.ip_blocklist.create_index("ip", unique=True)
    await db.incidents.create_index("opened_at")
    await db.response_actions.create_index("alert_id")
    await db.response_actions.create_index("created_at")

    # Saved searches
    await db.saved_searches.create_index([("owner", 1), ("name", 1)], unique=True)
    logger.info("MongoDB indexes verified.")


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
