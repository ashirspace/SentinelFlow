"""Temporary seed data: sample log sources + sample logs to test detections."""
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any


def sample_events() -> List[Dict[str, Any]]:
    """Return a mixed batch of demo events for the last ~24h that will trigger
    several detection rules on first ingest."""
    now = datetime.now(timezone.utc)
    events: List[Dict[str, Any]] = []

    def add(minutes_ago: int, **fields):
        ts = (now - timedelta(minutes=minutes_ago)).isoformat()
        base = {"timestamp": ts}
        base.update(fields)
        events.append(base)

    # Normal successful logins
    for i in range(20):
        add(minutes_ago=random.randint(30, 700),
            app="auth", action="login",
            user=random.choice(["alice", "bob", "carol", "dave"]),
            src_ip=f"10.0.0.{random.randint(2, 40)}",
            http_status="success", country="US", host="auth-01")

    # Brute-force burst — 8 failed logins from same IP within 3 min
    burst_ip = "203.0.113.99"
    for i in range(8):
        add(minutes_ago=120 + i * (0.3),
            app="auth", action="login",
            user="admin", src_ip=burst_ip,
            http_status="fail", country="RU", host="auth-01")
    # Followed by a success
    add(minutes_ago=118.5, app="auth", action="login", user="admin",
        src_ip=burst_ip, http_status="success", country="RU", host="auth-01")

    # Malicious IP hit (matches static blocklist)
    add(minutes_ago=40, app="web", action="request",
        user=None, src_ip="185.220.101.1", dst_ip="10.0.0.5",
        url="/admin", http_method="GET", http_status="200", host="web-01")

    # R007: Rate anomaly — 150 web requests from the same IP inside 1 minute
    scraper_ip = "203.0.113.77"
    for i in range(150):
        add(minutes_ago=60 - (i / 200.0),
            app="web", action="request", src_ip=scraper_ip,
            url=f"/api/products/{i}", http_method="GET",
            http_status="200", host="web-01",
            user_agent="python-requests/2.31")

    # R008: Injection patterns
    add(minutes_ago=55, app="web", action="request",
        src_ip="198.51.100.7", url="/search?q=' OR 1=1--",
        http_method="GET", http_status="200", host="web-01",
        user_agent="Mozilla/5.0")
    add(minutes_ago=54, app="web", action="request",
        src_ip="198.51.100.8", url="/comment?body=<script>alert(1)</script>",
        http_method="GET", http_status="200", host="web-01",
        user_agent="Mozilla/5.0")
    add(minutes_ago=53, app="web", action="request",
        src_ip="198.51.100.9", url="/files?path=../../etc/passwd",
        http_method="GET", http_status="200", host="web-01",
        user_agent="curl/8.0")

    # R009: New-device admin login (matches seeded admin@sentinelflow.io)
    add(minutes_ago=15, app="auth", action="login",
        user="admin@sentinelflow.io", src_ip="203.0.113.200",
        http_status="success", country="US", host="auth-01",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15")

    # Privilege escalation
    add(minutes_ago=90, app="linux", action="privilege_escalation",
        user="deployer", host="prod-db-01", http_status="success")

    # Off-hours login (03:00 UTC)
    off_hours_dt = now.replace(hour=3, minute=15, second=0, microsecond=0)
    if off_hours_dt > now:
        off_hours_dt -= timedelta(days=1)
    events.append({
        "timestamp": off_hours_dt.isoformat(),
        "app": "auth", "action": "login", "user": "carol",
        "src_ip": "198.51.100.14", "http_status": "success",
        "country": "DE", "host": "auth-01",
    })

    # Some web access noise
    for i in range(15):
        add(minutes_ago=random.randint(10, 900),
            app="web", action="request",
            src_ip=f"10.0.0.{random.randint(50, 90)}",
            url=random.choice(["/", "/api/health", "/dashboard", "/profile"]),
            http_method="GET", http_status="200", host="web-01")

    return events


def demo_sources() -> List[Dict[str, Any]]:
    return [
        {"id": str(uuid.uuid4()), "name": "auth-server-01", "type": "auth",
         "description": "Primary identity provider", "last_event_at": None,
         "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": str(uuid.uuid4()), "name": "web-nginx-01", "type": "web",
         "description": "Public web access logs", "last_event_at": None,
         "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": str(uuid.uuid4()), "name": "linux-prod-db-01", "type": "os",
         "description": "Production database host", "last_event_at": None,
         "created_at": datetime.now(timezone.utc).isoformat()},
    ]
