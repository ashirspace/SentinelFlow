"""Iteration 4 — Push-only v1 ingest tests."""
import os
import time
import uuid
import pytest
import requests
from pathlib import Path
from dotenv import dotenv_values

_fe_env = dotenv_values(Path(__file__).parent.parent.parent / "frontend" / ".env")
BASE = (os.environ.get("REACT_APP_BACKEND_URL") or _fe_env.get("REACT_APP_BACKEND_URL", "")).rstrip("/")
assert BASE, "REACT_APP_BACKEND_URL missing"
API = f"{BASE}/api"
V1 = f"{BASE}/api/v1"

ADMIN = {"email": "admin@sentinelflow.io", "password": "Admin@12345"}
ANALYST = {"email": "analyst@sentinelflow.io", "password": "Analyst@123"}


@pytest.fixture(scope="module")
def admin_sess():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json=ADMIN, timeout=15)
    assert r.status_code == 200, r.text
    return s


@pytest.fixture(scope="module")
def analyst_sess():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json=ANALYST, timeout=15)
    assert r.status_code == 200, r.text
    return s


@pytest.fixture(scope="module")
def src_and_key(admin_sess):
    """Create a temp source; delete at teardown."""
    name = f"TEST_iter4_{uuid.uuid4().hex[:8]}"
    r = admin_sess.post(f"{API}/sources", json={"name": name, "type": "web", "description": "iter4 test"})
    assert r.status_code == 200, r.text
    data = r.json()
    key = data["ingest_api_key"]
    assert key.startswith("sfk_")
    assert "ingest_api_key_hash" not in data
    yield name, key
    admin_sess.delete(f"{API}/sources/{name}?purge_events=true")


def test_create_source_returns_plaintext_key_only_once(src_and_key, admin_sess):
    name, _key = src_and_key
    # GET /sources must not leak plaintext
    r = admin_sess.get(f"{API}/sources")
    assert r.status_code == 200
    row = next((s for s in r.json() if s["name"] == name), None)
    assert row is not None
    assert "ingest_api_key" not in row
    assert "ingest_api_key_hash" not in row
    assert row.get("ingest_api_key_hint", "").startswith("sfk_")
    assert row["ingest_api_key_hint"].endswith("…")


def test_analyst_cannot_create_source(analyst_sess):
    r = analyst_sess.post(f"{API}/sources", json={"name": "TEST_analyst_should_fail", "type": "web"})
    assert r.status_code == 403


def _payload(n=1, src_ip="10.0.0.9"):
    return {"events": [{"timestamp": "2026-01-01T12:00:00Z", "app": "web",
                        "src_ip": src_ip, "user": "alice",
                        "http_method": "GET", "url": "/x", "http_status": 200}
                       for _ in range(n)]}


def test_v1_ingest_with_bearer(src_and_key):
    name, key = src_and_key
    r = requests.post(f"{V1}/ingest", json=_payload(1),
                      headers={"Authorization": f"Bearer {key}"}, timeout=15)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["ingested"] == 1
    assert j["source"] == name
    assert "alerts" in j
    assert "rate_limit" in j
    rl = j["rate_limit"]
    assert rl["limit_per_min"] == 60
    assert isinstance(rl["remaining"], int)
    assert isinstance(rl["reset_seconds"], int)


def test_v1_ingest_with_x_ingest_key_header(src_and_key):
    _, key = src_and_key
    r = requests.post(f"{V1}/ingest", json=_payload(1),
                      headers={"X-Ingest-Key": key}, timeout=15)
    assert r.status_code == 200, r.text


def test_v1_ingest_wrong_key():
    r = requests.post(f"{V1}/ingest", json=_payload(1),
                      headers={"Authorization": "Bearer sfk_this_is_bogus_xyz"}, timeout=15)
    assert r.status_code == 401
    assert "Invalid" in r.json().get("detail", "")


def test_v1_ingest_no_key():
    r = requests.post(f"{V1}/ingest", json=_payload(1), timeout=15)
    assert r.status_code == 401
    assert "Missing" in r.json().get("detail", "") or "malformed" in r.json().get("detail", "")


def test_v1_ingest_paused_returns_423(admin_sess, src_and_key):
    name, key = src_and_key
    admin_sess.patch(f"{API}/sources/{name}", json={"paused": True})
    try:
        r = requests.post(f"{V1}/ingest", json=_payload(1),
                          headers={"Authorization": f"Bearer {key}"}, timeout=15)
        assert r.status_code == 423, r.text
    finally:
        admin_sess.patch(f"{API}/sources/{name}", json={"paused": False})


def test_v1_body_too_large(src_and_key):
    _, key = src_and_key
    big = "x" * 1_000_050
    r = requests.post(f"{V1}/ingest", data=big,
                      headers={"Authorization": f"Bearer {key}",
                               "Content-Type": "application/json"}, timeout=20)
    assert r.status_code == 413, r.status_code


def test_v1_too_many_events(src_and_key):
    _, key = src_and_key
    r = requests.post(f"{V1}/ingest", json=_payload(1001),
                      headers={"Authorization": f"Bearer {key}"}, timeout=20)
    assert r.status_code == 400
    assert "too many" in r.json().get("detail", "").lower()


def test_v1_non_object_event(src_and_key):
    _, key = src_and_key
    r = requests.post(f"{V1}/ingest", json={"events": ["not-an-object"]},
                      headers={"Authorization": f"Bearer {key}"}, timeout=15)
    assert r.status_code == 400


def test_v1_key_cannot_access_other_endpoints(src_and_key):
    _, key = src_and_key
    h = {"Authorization": f"Bearer {key}"}
    # These endpoints depend on cookie auth. With only Bearer sfk_ key (no cookie), must 401.
    r1 = requests.get(f"{API}/events", headers=h, timeout=15)
    r2 = requests.get(f"{API}/sources", headers=h, timeout=15)
    r3 = requests.post(f"{API}/alerts/fake-id/approve", json={"action_type": "block_ip"},
                       headers=h, timeout=15)
    assert r1.status_code == 401, r1.status_code
    assert r2.status_code == 401, r2.status_code
    assert r3.status_code == 401, r3.status_code


def test_rotate_key_invalidates_old(admin_sess, src_and_key):
    name, old_key = src_and_key
    r = admin_sess.post(f"{API}/sources/{name}/rotate-key")
    assert r.status_code == 200
    new_key = r.json()["ingest_api_key"]
    assert new_key.startswith("sfk_")
    assert new_key != old_key
    # old key must now be rejected
    rr = requests.post(f"{V1}/ingest", json=_payload(1),
                       headers={"Authorization": f"Bearer {old_key}"}, timeout=15)
    assert rr.status_code == 401
    # new key works
    rr2 = requests.post(f"{V1}/ingest", json=_payload(1),
                        headers={"Authorization": f"Bearer {new_key}"}, timeout=15)
    assert rr2.status_code == 200
    # stash for next test via module-level
    pytest._iter4_new_key = new_key


def test_revoke_key(admin_sess, src_and_key):
    name, _ = src_and_key
    new_key = getattr(pytest, "_iter4_new_key", None)
    assert new_key, "rotate test must run first"
    r = admin_sess.post(f"{API}/sources/{name}/revoke-key")
    assert r.status_code == 200
    # Ingest with revoked key -> 401
    rr = requests.post(f"{V1}/ingest", json=_payload(1),
                       headers={"Authorization": f"Bearer {new_key}"}, timeout=15)
    assert rr.status_code == 401
    # GET /sources shows source without hint
    row = next(s for s in admin_sess.get(f"{API}/sources").json() if s["name"] == name)
    assert "ingest_api_key_hint" not in row or not row.get("ingest_api_key_hint")


def test_ingest_config(admin_sess):
    r = admin_sess.get(f"{API}/ingest/config")
    assert r.status_code == 200
    j = r.json()
    assert "/api/v1/ingest" in j["endpoint"]
    assert j["rate_limit_per_min"] == 60
    assert j["max_events_per_request"] == 1000
    assert j["max_body_bytes"] == 1_000_000


def test_v1_ping():
    r = requests.get(f"{V1}/ping", timeout=15)
    assert r.status_code == 200
    assert r.json() == {"ok": True, "service": "SentinelFlow", "ingest": "v1"}


def test_detection_over_v1(admin_sess):
    """Ingest a malicious IP via v1 and confirm R005 alert."""
    name = f"TEST_iter4_detect_{uuid.uuid4().hex[:6]}"
    r = admin_sess.post(f"{API}/sources", json={"name": name, "type": "web"})
    key = r.json()["ingest_api_key"]
    try:
        payload = {"events": [{"timestamp": "2026-01-01T12:34:56Z", "app": "web",
                               "src_ip": "185.220.101.1", "user": "eve",
                               "http_method": "GET", "url": "/login",
                               "http_status": 200}]}
        rr = requests.post(f"{V1}/ingest", json=payload,
                           headers={"Authorization": f"Bearer {key}"}, timeout=20)
        assert rr.status_code == 200, rr.text
        # allow slight time for detection + notifier
        time.sleep(1.0)
        alerts = admin_sess.get(f"{API}/alerts").json()
        # Look for an R005 alert with our IP in evidence key_fields
        found = any(a.get("rule_id") == "R005" and
                    (a.get("key_fields", {}).get("src_ip") == "185.220.101.1")
                    for a in alerts)
        assert found, "R005 alert not created for malicious IP via v1"
    finally:
        admin_sess.delete(f"{API}/sources/{name}?purge_events=true")


def test_audit_records_source_lifecycle(admin_sess):
    name = f"TEST_iter4_audit_{uuid.uuid4().hex[:6]}"
    admin_sess.post(f"{API}/sources", json={"name": name, "type": "web"})
    admin_sess.post(f"{API}/sources/{name}/rotate-key")
    admin_sess.post(f"{API}/sources/{name}/revoke-key")
    try:
        aud = admin_sess.get(f"{API}/audit?limit=500").json()
        actions = {(a["action"], a["target"]) for a in aud if a.get("target") == name}
        assert ("create_source", name) in actions
        assert ("rotate_source_key", name) in actions
        assert ("revoke_source_key", name) in actions
        # actor is admin email
        rows = [a for a in aud if a.get("target") == name and a["action"] in
                ("create_source", "rotate_source_key", "revoke_source_key")]
        assert all(a["actor"] == ADMIN["email"] for a in rows)
    finally:
        admin_sess.delete(f"{API}/sources/{name}")


def test_rate_limit_429(admin_sess):
    """Isolated fresh source; burn 62 calls."""
    name = f"TEST_iter4_rl_{uuid.uuid4().hex[:6]}"
    r = admin_sess.post(f"{API}/sources", json={"name": name, "type": "web"})
    key = r.json()["ingest_api_key"]
    got_429 = False
    retry_after = None
    try:
        headers = {"Authorization": f"Bearer {key}"}
        body = _payload(1)
        for i in range(65):
            resp = requests.post(f"{V1}/ingest", json=body, headers=headers, timeout=15)
            if resp.status_code == 429:
                got_429 = True
                retry_after = resp.headers.get("Retry-After")
                break
        assert got_429, "Never received 429"
        assert retry_after is not None and int(retry_after) > 0
    finally:
        admin_sess.delete(f"{API}/sources/{name}?purge_events=true")
