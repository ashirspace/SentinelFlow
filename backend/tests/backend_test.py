"""SentinelFlow backend API tests."""
import io
import json
import os
import time

import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if "REACT_APP_BACKEND_URL" in os.environ else None
if not BASE_URL:
    # read from frontend/.env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

API = f"{BASE_URL}/api"

ADMIN = {"email": "admin@sentinelflow.io", "password": "Admin@12345"}
ANALYST = {"email": "analyst@sentinelflow.io", "password": "Analyst@123"}


# ---------- Session fixtures ----------
@pytest.fixture(scope="module")
def admin_session():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json=ADMIN, timeout=30)
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    return s


@pytest.fixture(scope="module")
def analyst_session():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json=ANALYST, timeout=30)
    assert r.status_code == 200, f"Analyst login failed: {r.status_code} {r.text}"
    return s


# ---------- Health ----------
def test_health():
    r = requests.get(f"{API}/", timeout=15)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ---------- Auth ----------
def test_login_returns_user_and_sets_cookies():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json=ADMIN, timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert data["email"] == ADMIN["email"]
    assert data["role"] == "admin"
    assert "access_token" in s.cookies
    assert "refresh_token" in s.cookies


def test_me_returns_current_user(admin_session):
    r = admin_session.get(f"{API}/auth/me", timeout=15)
    assert r.status_code == 200
    assert r.json()["email"] == ADMIN["email"]


def test_logout_clears_and_me_401():
    s = requests.Session()
    s.post(f"{API}/auth/login", json=ADMIN, timeout=15)
    r = s.post(f"{API}/auth/logout", timeout=15)
    assert r.status_code == 200
    # After logout new session with no cookies should be 401
    r2 = requests.get(f"{API}/auth/me", timeout=15)
    assert r2.status_code == 401


def test_invalid_password_401():
    r = requests.post(f"{API}/auth/login", json={"email": ADMIN["email"], "password": "wrong"}, timeout=15)
    assert r.status_code == 401


def test_brute_force_lockout_429():
    # Use a random email to not lock the admin
    email = f"lock-test-{int(time.time())}@x.com"
    codes = []
    for _ in range(7):
        r = requests.post(f"{API}/auth/login", json={"email": email, "password": "bad"}, timeout=15)
        codes.append(r.status_code)
    assert 429 in codes, f"Expected 429 in {codes}"


# ---------- RBAC ----------
def test_analyst_forbidden_users(analyst_session):
    r = analyst_session.get(f"{API}/users", timeout=15)
    assert r.status_code == 403


def test_analyst_forbidden_audit(analyst_session):
    r = analyst_session.get(f"{API}/audit", timeout=15)
    assert r.status_code == 403


def test_analyst_forbidden_seed(analyst_session):
    r = analyst_session.post(f"{API}/ingest/seed", timeout=30)
    assert r.status_code == 403


# ---------- Seed (admin) ----------
def test_seed_success(admin_session):
    r = admin_session.post(f"{API}/ingest/seed", timeout=60)
    assert r.status_code == 200
    data = r.json()
    assert data["ingested"] > 0
    assert data["alerts"] > 0


def test_seed_idempotent_second_run(admin_session):
    r = admin_session.post(f"{API}/ingest/seed", timeout=60)
    assert r.status_code == 200
    assert r.json()["ingested"] > 0


# ---------- Users CRUD ----------
def test_users_list_admin(admin_session):
    r = admin_session.get(f"{API}/users", timeout=15)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_create_and_delete_user(admin_session):
    email = f"test_user_{int(time.time())}@x.com"
    r = admin_session.post(f"{API}/users", json={
        "email": email, "password": "Passw0rd!", "name": "Temp", "role": "analyst"
    }, timeout=15)
    assert r.status_code == 200, r.text
    uid = r.json()["id"]
    # List contains it
    users = admin_session.get(f"{API}/users").json()
    assert any(u["email"] == email for u in users)
    # Delete
    r = admin_session.delete(f"{API}/users/{uid}", timeout=15)
    assert r.status_code == 200


def test_delete_self_400(admin_session):
    me = admin_session.get(f"{API}/auth/me").json()
    r = admin_session.delete(f"{API}/users/{me['id']}", timeout=15)
    assert r.status_code == 400


# ---------- Sources ----------
def test_list_sources_has_demo(admin_session):
    r = admin_session.get(f"{API}/sources", timeout=15)
    assert r.status_code == 200
    names = [s["name"] for s in r.json()]
    for expected in ["auth-server-01", "web-nginx-01", "linux-prod-db-01"]:
        assert expected in names


def test_create_source(admin_session):
    name = f"test-source-{int(time.time())}"
    r = admin_session.post(f"{API}/sources", json={
        "name": name, "type": "custom", "description": "test"
    }, timeout=15)
    assert r.status_code == 200
    assert r.json()["name"] == name


# ---------- Ingest file ----------
def test_file_ingest(admin_session):
    payload = [{
        "timestamp": "2026-08-02T10:00:00Z", "user": "eve", "src_ip": "10.0.0.99",
        "http_status": "fail", "app": "auth", "action": "login"
    }]
    files = {"file": ("logs.json", json.dumps(payload), "application/json")}
    r = admin_session.post(f"{API}/ingest?source_name=auth-server-01", files=files, timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ingested"] == 1


# ---------- Alerts ----------
def test_alerts_have_all_rules(admin_session):
    r = admin_session.get(f"{API}/alerts", timeout=15)
    assert r.status_code == 200
    alerts = r.json()
    rule_ids = {a.get("rule_id") for a in alerts}
    for rid in ["R001", "R002", "R003", "R004", "R005"]:
        assert rid in rule_ids, f"Missing {rid} in {rule_ids}"
    # Each alert well-formed
    for a in alerts:
        assert a.get("explanation")
        assert a.get("rule_id")
        assert a.get("severity")
        assert "status" in a
        if a["rule_id"] != "R006":
            assert isinstance(a.get("evidence_event_ids", []), list)


def test_alert_detail_with_evidence(admin_session):
    alerts = admin_session.get(f"{API}/alerts").json()
    # pick one with evidence_event_ids
    target = next((a for a in alerts if a.get("evidence_event_ids")), None)
    assert target, "No alert with evidence"
    r = admin_session.get(f"{API}/alerts/{target['id']}", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert "evidence_events" in data
    assert len(data["evidence_events"]) > 0


def test_alert_lifecycle_patch(admin_session):
    alerts = admin_session.get(f"{API}/alerts").json()
    aid = alerts[0]["id"]
    r = admin_session.patch(f"{API}/alerts/{aid}", json={
        "status": "Under Review", "note": "triaging"
    }, timeout=15)
    assert r.status_code == 200
    # verify
    a = admin_session.get(f"{API}/alerts/{aid}").json()
    assert a["status"] == "Under Review"
    assert any(n.get("note") == "triaging" for n in a.get("notes", []))


# ---------- Events ----------
def test_events_filters(admin_session):
    r = admin_session.get(f"{API}/events?limit=10", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert "events" in data and "total" in data
    assert data["total"] > 0
    ev = data["events"][0]
    # get single event
    r2 = admin_session.get(f"{API}/events/{ev['event_id']}", timeout=15)
    assert r2.status_code == 200
    assert "raw_log" in r2.json()


def test_events_query_filter(admin_session):
    r = admin_session.get(f"{API}/events?q=login&limit=5", timeout=15)
    assert r.status_code == 200


# ---------- Dashboard ----------
def test_dashboard_stats(admin_session):
    r = admin_session.get(f"{API}/dashboard/stats", timeout=20)
    assert r.status_code == 200
    d = r.json()
    for k in ["events_24h", "open_alerts", "critical_alerts", "silent_sources",
              "timeseries", "top_ips", "alerts_by_severity"]:
        assert k in d


# ---------- Rules ----------
def test_rules_six(admin_session):
    r = admin_session.get(f"{API}/rules", timeout=15)
    assert r.status_code == 200
    rules = r.json()
    assert len(rules) == 6
    ids = {r["rule_id"] for r in rules}
    for rid in ["R001", "R002", "R003", "R004", "R005", "R006"]:
        assert rid in ids


# ---------- Audit ----------
def test_audit_admin_visible(admin_session):
    r = admin_session.get(f"{API}/audit", timeout=15)
    assert r.status_code == 200
    logs = r.json()
    actions = {l.get("action") for l in logs}
    # Should have login and seed actions at minimum
    assert "login" in actions
