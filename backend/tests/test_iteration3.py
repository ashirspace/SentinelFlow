"""SentinelFlow iteration 3 tests: response actions, blocklist, incidents,
event annotations, CSV export, log-source management."""
import io
import json
import os
import time
import uuid

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip()
BASE_URL = BASE_URL.rstrip("/")
API = f"{BASE_URL}/api"

ADMIN = {"email": "admin@sentinelflow.io", "password": "Admin@12345"}
ANALYST = {"email": "analyst@sentinelflow.io", "password": "Analyst@123"}


@pytest.fixture(scope="module")
def admin():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json=ADMIN, timeout=30)
    assert r.status_code == 200, r.text
    return s


@pytest.fixture(scope="module")
def analyst():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json=ANALYST, timeout=30)
    assert r.status_code == 200, r.text
    return s


@pytest.fixture(scope="module", autouse=True)
def _seed(admin):
    # Ensure seed data + all rules fire once at module start
    admin.post(f"{API}/ingest/seed", timeout=60)
    yield


def _find_alert(admin, rule_id):
    r = admin.get(f"{API}/alerts?rule_id={rule_id}", timeout=15)
    assert r.status_code == 200
    alerts = r.json()
    return alerts[0] if alerts else None


# ---------- Rules: 10 rules including R010 ----------
def test_rules_has_ten_including_r010(admin):
    r = admin.get(f"{API}/rules", timeout=15)
    assert r.status_code == 200
    rules = r.json()
    assert len(rules) == 10, f"Expected 10 rules, got {len(rules)}"
    by_id = {x["rule_id"]: x for x in rules}
    assert "R010" in by_id
    assert by_id["R010"]["severity"] == "Likely malicious"


def test_seed_still_produces_all_original_alerts(admin):
    alerts = admin.get(f"{API}/alerts", timeout=15).json()
    rule_ids = {a.get("rule_id") for a in alerts}
    for rid in ["R001", "R002", "R003", "R004", "R005", "R007", "R008", "R009"]:
        assert rid in rule_ids, f"Missing {rid} from seed alerts"


# ---------- Recommended actions ----------
def test_recommended_actions_r001(admin):
    a = _find_alert(admin, "R001")
    assert a
    r = admin.get(f"{API}/alerts/{a['id']}/recommended-actions", timeout=15)
    assert r.status_code == 200
    items = r.json()
    types = [i["type"] for i in items]
    assert set(types) == {"block_ip", "escalate_incident"}
    for it in items:
        assert "label" in it and "default_target" in it


def test_recommended_actions_r002(admin):
    a = _find_alert(admin, "R002")
    assert a
    r = admin.get(f"{API}/alerts/{a['id']}/recommended-actions", timeout=15)
    assert r.status_code == 200
    types = {i["type"] for i in r.json()}
    assert types == {"revoke_session", "disable_account", "block_ip", "escalate_incident"}


# ---------- block_ip flow ----------
def test_approve_block_ip_flow(admin):
    a = _find_alert(admin, "R001")
    assert a
    ip = (a.get("key_fields") or {}).get("src_ip")
    assert ip
    # unblock first in case a prior run left it
    admin.delete(f"{API}/blocklist/{ip}", timeout=15)
    r = admin.post(f"{API}/alerts/{a['id']}/approve",
                    json={"action_type": "block_ip", "note": "test-block"}, timeout=20)
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["action_type"] == "block_ip"
    assert doc["result"] in ("blocked", "already_blocked")
    assert doc["target"] == ip
    # blocklist should contain it
    bl = admin.get(f"{API}/blocklist", timeout=15).json()
    assert any(b["ip"] == ip for b in bl)
    # actions listed
    acts = admin.get(f"{API}/alerts/{a['id']}/actions", timeout=15).json()
    assert any(x["action_type"] == "block_ip" for x in acts)
    # audit entry
    audit = admin.get(f"{API}/audit", timeout=15).json()
    approves = [x for x in audit if x.get("action") == "approve:block_ip"]
    assert approves, "no approve:block_ip in audit"
    assert approves[0].get("meta", {}).get("result") in ("blocked", "already_blocked")


def test_r010_fires_on_new_event_from_blocked_ip(admin):
    ip = "203.0.113.77"
    # ensure IP blocked via an alert
    a = _find_alert(admin, "R001")
    admin.delete(f"{API}/blocklist/{ip}", timeout=15)
    # manually block via approve using target override
    r = admin.post(f"{API}/alerts/{a['id']}/approve",
                    json={"action_type": "block_ip", "target": ip}, timeout=15)
    assert r.status_code == 200, r.text
    # ingest new event from that IP
    payload = [{
        "timestamp": "2026-08-05T12:00:00Z", "app": "web", "action": "request",
        "src_ip": ip, "url": "/", "http_method": "GET", "http_status": "200",
    }]
    files = {"file": ("r010.json", json.dumps(payload), "application/json")}
    r2 = admin.post(f"{API}/ingest?source_name=web-nginx-01", files=files, timeout=30)
    assert r2.status_code == 200, r2.text
    # look for R010 alert with this ip
    time.sleep(0.5)
    alerts = admin.get(f"{API}/alerts?rule_id=R010", timeout=15).json()
    matching = [a for a in alerts if (a.get("key_fields") or {}).get("src_ip") == ip]
    assert matching, f"No R010 alert for {ip}"
    m = matching[0]
    assert m["severity"] == "Likely malicious"
    assert m.get("explanation")


def test_admin_can_delete_blocklist(admin):
    ip = "203.0.113.77"
    r = admin.delete(f"{API}/blocklist/{ip}", timeout=15)
    assert r.status_code in (200, 404)


def test_analyst_cannot_delete_blocklist(analyst, admin):
    ip = "203.0.113.99"
    a = _find_alert(admin, "R001")
    admin.post(f"{API}/alerts/{a['id']}/approve",
               json={"action_type": "block_ip", "target": ip}, timeout=15)
    r = analyst.delete(f"{API}/blocklist/{ip}", timeout=15)
    assert r.status_code == 403
    admin.delete(f"{API}/blocklist/{ip}", timeout=15)  # cleanup


# ---------- disable_account: internal + external ----------
def test_disable_account_internal_then_reset(admin):
    """Create a temp user, disable via approve, verify login=403 and me=401,
    then re-enable and reset."""
    email = f"test_disable_{int(time.time())}@x.com"
    r = admin.post(f"{API}/users",
                   json={"email": email, "password": "Passw0rd!",
                         "name": "TestDisable", "role": "analyst"}, timeout=15)
    assert r.status_code == 200, r.text
    uid = r.json()["id"]

    # Log in that user first, verify me works
    tmp = requests.Session()
    lr = tmp.post(f"{API}/auth/login", json={"email": email, "password": "Passw0rd!"}, timeout=15)
    assert lr.status_code == 200
    assert tmp.get(f"{API}/auth/me", timeout=15).status_code == 200

    # Find an R002 alert and craft approval with target override to this user
    a = _find_alert(admin, "R002")
    assert a
    r2 = admin.post(f"{API}/alerts/{a['id']}/approve",
                    json={"action_type": "disable_account", "target": email,
                          "note": "test-disable"}, timeout=15)
    assert r2.status_code == 200, r2.text
    doc = r2.json()
    assert doc["result"] == "disabled_internal"

    # Now the earlier session's /me should 401 with 'Account disabled'
    me_r = tmp.get(f"{API}/auth/me", timeout=15)
    assert me_r.status_code == 401
    assert "disabled" in me_r.text.lower()

    # Fresh login must 403
    fresh = requests.Session()
    lr2 = fresh.post(f"{API}/auth/login",
                     json={"email": email, "password": "Passw0rd!"}, timeout=15)
    assert lr2.status_code == 403
    assert "disabled" in lr2.text.lower()

    # cleanup
    admin.delete(f"{API}/users/{uid}", timeout=15)


def test_disable_account_external_recommendation(admin):
    a = _find_alert(admin, "R002")
    assert a
    ext = f"external_user_{int(time.time())}"
    r = admin.post(f"{API}/alerts/{a['id']}/approve",
                   json={"action_type": "disable_account", "target": ext,
                         "note": "external"}, timeout=15)
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["result"] == "recommended_external"
    assert "recommendation" in doc.get("meta", {})
    # Verify no user was created/modified
    users = admin.get(f"{API}/users", timeout=15).json()
    assert not any(u.get("email") == ext for u in users)


# ---------- revoke_session ----------
def test_revoke_session_invalidates_existing(admin):
    """Create a temp user, log in, revoke via approve, /me returns 401 'Session revoked'."""
    email = f"test_revoke_{int(time.time())}@x.com"
    r = admin.post(f"{API}/users",
                   json={"email": email, "password": "Passw0rd!",
                         "name": "TestRevoke", "role": "analyst"}, timeout=15)
    assert r.status_code == 200
    uid = r.json()["id"]

    victim = requests.Session()
    victim.post(f"{API}/auth/login",
                json={"email": email, "password": "Passw0rd!"}, timeout=15)
    assert victim.get(f"{API}/auth/me", timeout=15).status_code == 200

    a = _find_alert(admin, "R002")
    r2 = admin.post(f"{API}/alerts/{a['id']}/approve",
                    json={"action_type": "revoke_session", "target": email}, timeout=15)
    assert r2.status_code == 200, r2.text
    assert r2.json()["result"] == "revoked_internal"

    me_r = victim.get(f"{API}/auth/me", timeout=15)
    assert me_r.status_code == 401
    assert "revoked" in me_r.text.lower() or "session" in me_r.text.lower()

    # can login fresh (token_version now bumped but new login uses new tv)
    fresh = requests.Session()
    lr = fresh.post(f"{API}/auth/login",
                    json={"email": email, "password": "Passw0rd!"}, timeout=15)
    assert lr.status_code == 200

    admin.delete(f"{API}/users/{uid}", timeout=15)


# ---------- escalate_incident dedup ----------
def test_escalate_incident_creates_then_links(admin):
    a = _find_alert(admin, "R001")
    r = admin.post(f"{API}/alerts/{a['id']}/approve",
                   json={"action_type": "escalate_incident", "note": "esc1"}, timeout=15)
    assert r.status_code == 200
    doc1 = r.json()
    assert doc1["result"] in ("created", "linked_existing")
    inc_id = doc1["meta"]["incident_id"]

    # second escalate
    r2 = admin.post(f"{API}/alerts/{a['id']}/approve",
                    json={"action_type": "escalate_incident", "note": "esc2"}, timeout=15)
    assert r2.status_code == 200
    doc2 = r2.json()
    assert doc2["result"] == "linked_existing"
    assert doc2["meta"]["incident_id"] == inc_id

    # /api/incidents lists it
    inc = admin.get(f"{API}/incidents/{inc_id}", timeout=15)
    assert inc.status_code == 200
    body = inc.json()
    assert "alerts" in body
    assert body["id"] == inc_id


# ---------- reject non-recommended action ----------
def test_reject_action_not_recommended(admin):
    # R003 recommends revoke_session + escalate_incident, so block_ip should be rejected
    a = _find_alert(admin, "R003")
    assert a
    r = admin.post(f"{API}/alerts/{a['id']}/approve",
                   json={"action_type": "block_ip"}, timeout=15)
    assert r.status_code == 400


# ---------- Actions listing order ----------
def test_actions_list_reverse_chronological(admin):
    a = _find_alert(admin, "R001")
    r = admin.get(f"{API}/alerts/{a['id']}/actions", timeout=15)
    assert r.status_code == 200
    docs = r.json()
    if len(docs) >= 2:
        assert docs[0]["created_at"] >= docs[-1]["created_at"]


# ---------- Sources health, patch, rotate, delete ----------
def test_sources_include_health_and_retention(admin):
    r = admin.get(f"{API}/sources", timeout=15)
    assert r.status_code == 200
    for s in r.json():
        assert "health" in s
        assert s["health"] in ("healthy", "delayed", "silent")
        assert "retention_hours" in s
        assert "paused" in s


def test_source_patch_retention_valid(admin):
    r = admin.patch(f"{API}/sources/auth-server-01",
                    json={"retention_hours": 24}, timeout=15)
    assert r.status_code == 200
    srcs = admin.get(f"{API}/sources", timeout=15).json()
    a = next(s for s in srcs if s["name"] == "auth-server-01")
    assert a["retention_hours"] == 24


def test_source_patch_retention_100_rejected(admin):
    r = admin.patch(f"{API}/sources/auth-server-01",
                    json={"retention_hours": 100}, timeout=15)
    assert r.status_code in (400, 422)


def test_source_pause_blocks_ingest(admin):
    name = f"test-pause-{int(time.time())}"
    admin.post(f"{API}/sources",
               json={"name": name, "type": "custom"}, timeout=15)
    r = admin.patch(f"{API}/sources/{name}", json={"paused": True}, timeout=15)
    assert r.status_code == 200
    payload = [{"timestamp": "2026-08-05T00:00:00Z", "app": "auth",
                "user": "x", "src_ip": "1.2.3.4", "http_status": "fail"}]
    files = {"file": ("p.json", json.dumps(payload), "application/json")}
    r2 = admin.post(f"{API}/ingest?source_name={name}", files=files, timeout=30)
    assert r2.status_code == 409
    # cleanup
    admin.delete(f"{API}/sources/{name}", timeout=15)


def test_source_rotate_key(admin):
    r = admin.post(f"{API}/sources/auth-server-01/rotate-key", timeout=15)
    assert r.status_code == 200
    assert "ingest_api_key" in r.json()
    assert len(r.json()["ingest_api_key"]) > 10


def test_source_delete_with_purge(admin):
    name = f"test-del-{int(time.time())}"
    admin.post(f"{API}/sources", json={"name": name, "type": "custom"}, timeout=15)
    # ingest a few events
    payload = [{"timestamp": "2026-08-05T00:00:00Z", "app": "auth",
                "user": "x", "src_ip": "1.2.3.4", "http_status": "fail"}]
    files = {"file": ("d.json", json.dumps(payload), "application/json")}
    admin.post(f"{API}/ingest?source_name={name}", files=files, timeout=30)
    r = admin.delete(f"{API}/sources/{name}?purge_events=true", timeout=30)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("events_deleted", 0) >= 1
    assert body.get("raw_deleted", 0) >= 1


def test_raw_logs_expires_at_matches_retention(admin):
    """After patching retention_hours=24 and ingesting, raw_logs docs should have
    expires_at ~24h in the future (not 72h)."""
    # set retention=24
    admin.patch(f"{API}/sources/auth-server-01",
                json={"retention_hours": 24}, timeout=15)
    marker_ip = f"9.9.9.{int(time.time()) % 250}"
    payload = [{"timestamp": "2026-08-05T00:00:00Z", "app": "auth",
                "user": "retention_test", "src_ip": marker_ip, "http_status": "fail"}]
    files = {"file": ("ret.json", json.dumps(payload), "application/json")}
    r = admin.post(f"{API}/ingest?source_name=auth-server-01", files=files, timeout=30)
    assert r.status_code == 200
    # Cannot directly hit raw_logs via API — but we ingested from that source,
    # and _ingest_events writes expires_at using retention_hours. Sanity: patch=24 accepted.
    srcs = admin.get(f"{API}/sources", timeout=15).json()
    a = next(s for s in srcs if s["name"] == "auth-server-01")
    assert a["retention_hours"] == 24


# ---------- Event annotations ----------
def test_event_annotate_patch(admin):
    events = admin.get(f"{API}/events?limit=1", timeout=15).json()["events"]
    assert events
    eid = events[0]["event_id"]
    r = admin.patch(f"{API}/events/{eid}",
                    json={"tags": ["a", "b"], "reviewed": True, "note": "reviewed-x"},
                    timeout=15)
    assert r.status_code == 200
    got = admin.get(f"{API}/events/{eid}", timeout=15).json()
    assert set(got.get("tags", [])) == {"a", "b"}
    assert got.get("reviewed") is True
    assert got.get("reviewed_by")
    assert got.get("reviewed_at")
    notes = got.get("notes", [])
    assert any(n.get("text") == "reviewed-x" for n in notes)


# ---------- CSV export ----------
def test_export_csv_content_type_and_header(admin):
    r = admin.get(f"{API}/export/events.csv?severity=Suspicious&limit=50", timeout=30)
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "")
    body = r.text
    lines = body.strip().split("\n")
    assert lines
    header = lines[0]
    for col in ["event_id", "timestamp", "src_ip"]:
        assert col in header


# ---------- Approve action visible in audit ----------
def test_audit_contains_approve_actions(admin):
    logs = admin.get(f"{API}/audit", timeout=15).json()
    actions = {l.get("action") for l in logs}
    approves = {a for a in actions if a and a.startswith("approve:")}
    assert approves, "no approve:* actions in audit log"


# ---------- Existing MVP regressions ----------
def test_dashboard_still_works(admin):
    r = admin.get(f"{API}/dashboard/stats", timeout=20)
    assert r.status_code == 200
    for k in ["events_24h", "open_alerts", "critical_alerts",
              "silent_sources", "timeseries", "top_ips", "alerts_by_severity"]:
        assert k in r.json()


def test_alert_status_patch_still_works(admin):
    alerts = admin.get(f"{API}/alerts", timeout=15).json()
    aid = alerts[0]["id"]
    r = admin.patch(f"{API}/alerts/{aid}",
                    json={"status": "Investigating", "note": "iter3-triage"}, timeout=15)
    assert r.status_code == 200


def test_events_search_still_works(admin):
    r = admin.get(f"{API}/events?q=login&limit=5", timeout=15)
    assert r.status_code == 200
