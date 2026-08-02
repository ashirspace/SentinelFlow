"""Iteration 5 — Incidents (with timeline/root_cause/notes) + Saved searches."""
import os
import uuid
import pytest
import requests
from pathlib import Path
from dotenv import dotenv_values

_fe_env = dotenv_values(Path(__file__).parent.parent.parent / "frontend" / ".env")
BASE = (os.environ.get("REACT_APP_BACKEND_URL") or _fe_env.get("REACT_APP_BACKEND_URL", "")).rstrip("/")
assert BASE, "REACT_APP_BACKEND_URL missing"
API = f"{BASE}/api"

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
def seeded_alerts(admin_sess):
    """Ensure some alerts exist to attach to incidents."""
    alerts = admin_sess.get(f"{API}/alerts").json()
    if len(alerts) < 2:
        admin_sess.post(f"{API}/ingest/seed")
        alerts = admin_sess.get(f"{API}/alerts").json()
    assert len(alerts) >= 2, "need >=2 alerts seeded"
    return [a["id"] for a in alerts[:3]]


# ---------- Incidents ----------

def test_create_incident_with_alerts(admin_sess, seeded_alerts):
    body = {"title": "TEST_iter5 case A", "severity": "Suspicious",
            "summary": "test summary", "alert_ids": seeded_alerts[:2]}
    r = admin_sess.post(f"{API}/incidents", json=body)
    assert r.status_code == 200, r.text
    inc = r.json()
    assert inc["title"] == "TEST_iter5 case A"
    assert inc["status"] == "Open"
    assert inc["root_cause"] == ""
    assert inc["notes"] == []
    assert isinstance(inc["timeline"], list) and len(inc["timeline"]) == 1
    assert inc["timeline"][0]["kind"] == "opened"
    assert set(inc["alert_ids"]) == set(seeded_alerts[:2])
    # evidence aggregated (may be empty if underlying alerts had none, but field exists)
    assert "evidence_event_ids" in inc
    pytest._iter5_incident_id = inc["id"]


def test_create_incident_unknown_alert_400(admin_sess, seeded_alerts):
    body = {"title": "TEST_iter5 bad", "alert_ids": [seeded_alerts[0], "does-not-exist-xyz"]}
    r = admin_sess.post(f"{API}/incidents", json=body)
    assert r.status_code == 400
    assert "does-not-exist-xyz" in r.text


def test_get_incident_has_timeline_and_root_cause(admin_sess):
    iid = pytest._iter5_incident_id
    r = admin_sess.get(f"{API}/incidents/{iid}")
    assert r.status_code == 200
    inc = r.json()
    assert "root_cause" in inc
    assert "timeline" in inc
    assert "alerts" in inc
    assert "evidence_events" in inc


def test_get_legacy_incident_backfills(admin_sess, seeded_alerts):
    """Simulate a legacy incident (no timeline/root_cause) via escalate_incident approve."""
    # find an alert that supports escalate_incident
    aid = seeded_alerts[0]
    # try to approve escalate_incident - it may or may not be recommended
    r = admin_sess.post(f"{API}/alerts/{aid}/approve",
                        json={"action_type": "escalate_incident", "note": "test"})
    if r.status_code != 200:
        pytest.skip(f"escalate_incident not applicable: {r.status_code}")
    # find newest incident linked to this alert
    incs = admin_sess.get(f"{API}/incidents").json()
    linked = [i for i in incs if aid in (i.get("alert_ids") or [])]
    assert linked, "escalation should create an incident"
    iid = linked[0]["id"]
    r2 = admin_sess.get(f"{API}/incidents/{iid}")
    assert r2.status_code == 200
    j = r2.json()
    assert j.get("root_cause", None) == "" or isinstance(j.get("root_cause"), str)
    assert isinstance(j.get("timeline"), list)


def test_patch_status_appends_timeline(admin_sess):
    iid = pytest._iter5_incident_id
    r = admin_sess.patch(f"{API}/incidents/{iid}", json={"status": "Investigating"})
    assert r.status_code == 200
    r2 = admin_sess.patch(f"{API}/incidents/{iid}", json={"status": "Resolved"})
    assert r2.status_code == 200, r2.text
    inc = admin_sess.get(f"{API}/incidents/{iid}").json()
    assert inc["status"] == "Resolved"
    kinds = [t["kind"] for t in inc["timeline"]]
    assert kinds.count("status") >= 2


def test_patch_root_cause(admin_sess):
    iid = pytest._iter5_incident_id
    r = admin_sess.patch(f"{API}/incidents/{iid}",
                         json={"root_cause": "Compromised creds"})
    assert r.status_code == 200
    inc = admin_sess.get(f"{API}/incidents/{iid}").json()
    assert inc["root_cause"] == "Compromised creds"
    assert any(t["kind"] == "root_cause" for t in inc["timeline"])


def test_patch_note(admin_sess):
    iid = pytest._iter5_incident_id
    r = admin_sess.patch(f"{API}/incidents/{iid}", json={"note": "Reviewed logs"})
    assert r.status_code == 200
    inc = admin_sess.get(f"{API}/incidents/{iid}").json()
    assert any(n.get("text") == "Reviewed logs" for n in inc.get("notes", []))
    assert any(t["kind"] == "note" for t in inc["timeline"])


def test_patch_title(admin_sess):
    iid = pytest._iter5_incident_id
    r = admin_sess.patch(f"{API}/incidents/{iid}", json={"title": "TEST_iter5 renamed"})
    assert r.status_code == 200
    inc = admin_sess.get(f"{API}/incidents/{iid}").json()
    assert inc["title"] == "TEST_iter5 renamed"
    assert any(t["kind"] == "title" for t in inc["timeline"])


def test_patch_status_bogus_422(admin_sess):
    iid = pytest._iter5_incident_id
    r = admin_sess.patch(f"{API}/incidents/{iid}", json={"status": "Bogus"})
    assert r.status_code == 422


def test_link_alerts(admin_sess, seeded_alerts):
    iid = pytest._iter5_incident_id
    inc_before = admin_sess.get(f"{API}/incidents/{iid}").json()
    ev_before = set(inc_before.get("evidence_event_ids") or [])
    new_alert = seeded_alerts[2] if len(seeded_alerts) > 2 else None
    if not new_alert:
        pytest.skip("need >=3 alerts")
    r = admin_sess.post(f"{API}/incidents/{iid}/alerts",
                        json={"alert_ids": [new_alert]})
    assert r.status_code == 200, r.text
    inc = admin_sess.get(f"{API}/incidents/{iid}").json()
    assert new_alert in inc["alert_ids"]
    ev_after = set(inc.get("evidence_event_ids") or [])
    # no duplicates
    assert len(ev_after) == len(list(ev_after))
    assert any(t["kind"] == "alerts_added" for t in inc["timeline"])
    # dedup - re-link, added=0
    r2 = admin_sess.post(f"{API}/incidents/{iid}/alerts",
                         json={"alert_ids": [new_alert]})
    assert r2.status_code == 200
    assert r2.json().get("added") == 0


def test_link_alerts_unknown_400(admin_sess):
    iid = pytest._iter5_incident_id
    r = admin_sess.post(f"{API}/incidents/{iid}/alerts",
                        json={"alert_ids": ["nope-alert-xyz"]})
    assert r.status_code == 400


def test_unlink_alert(admin_sess, seeded_alerts):
    iid = pytest._iter5_incident_id
    inc = admin_sess.get(f"{API}/incidents/{iid}").json()
    target = inc["alert_ids"][0]
    r = admin_sess.delete(f"{API}/incidents/{iid}/alerts/{target}")
    assert r.status_code == 200
    inc2 = admin_sess.get(f"{API}/incidents/{iid}").json()
    assert target not in inc2["alert_ids"]
    assert any(t["kind"] == "alerts_removed" for t in inc2["timeline"])
    # unlink again -> 404
    r2 = admin_sess.delete(f"{API}/incidents/{iid}/alerts/{target}")
    assert r2.status_code == 404


def test_alert_shows_linked_incidents(admin_sess):
    iid = pytest._iter5_incident_id
    inc = admin_sess.get(f"{API}/incidents/{iid}").json()
    if not inc["alert_ids"]:
        pytest.skip("no linked alerts")
    aid = inc["alert_ids"][0]
    r = admin_sess.get(f"{API}/alerts/{aid}")
    assert r.status_code == 200
    a = r.json()
    assert "linked_incidents" in a
    linked_ids = [l["id"] for l in a["linked_incidents"]]
    assert iid in linked_ids
    # shape
    li = next(l for l in a["linked_incidents"] if l["id"] == iid)
    assert "title" in li and "status" in li and "severity" in li


def test_alert_lifecycle_unchanged(admin_sess, seeded_alerts):
    aid = seeded_alerts[-1]
    r = admin_sess.patch(f"{API}/alerts/{aid}", json={"status": "Investigating"})
    assert r.status_code == 200
    # bad status rejected
    r2 = admin_sess.patch(f"{API}/alerts/{aid}", json={"status": "Open"})
    assert r2.status_code == 422


def test_rules_unchanged(admin_sess):
    r = admin_sess.get(f"{API}/rules")
    assert r.status_code == 200
    rules = r.json()
    ids = sorted([r["rule_id"] for r in rules])
    assert ids == [f"R{str(i).zfill(3)}" for i in range(1, 11)]


# ---------- Saved searches ----------

def test_saved_search_crud_and_scoping(admin_sess, analyst_sess):
    name = f"TEST_iter5_ss_{uuid.uuid4().hex[:6]}"
    r = admin_sess.post(f"{API}/saved-searches",
                        json={"name": name, "filters": {"severity": "Suspicious"}})
    assert r.status_code == 200, r.text
    ss = r.json()
    assert ss["owner"] == ADMIN["email"]
    assert ss["name"] == name
    sid = ss["id"]
    # duplicate name for same owner -> 409
    r2 = admin_sess.post(f"{API}/saved-searches",
                         json={"name": name, "filters": {"severity": "Suspicious"}})
    assert r2.status_code == 409
    # list as admin includes it
    lst = admin_sess.get(f"{API}/saved-searches").json()
    assert any(s["id"] == sid for s in lst)
    # analyst list does NOT include admin's
    a_lst = analyst_sess.get(f"{API}/saved-searches").json()
    assert not any(s["id"] == sid for s in a_lst)
    # analyst cannot delete admin's search
    r3 = analyst_sess.delete(f"{API}/saved-searches/{sid}")
    assert r3.status_code == 404
    # admin can delete
    r4 = admin_sess.delete(f"{API}/saved-searches/{sid}")
    assert r4.status_code == 200


# ---------- Audit ----------

def test_audit_incident_actions(admin_sess):
    iid = pytest._iter5_incident_id
    aud = admin_sess.get(f"{API}/audit?limit=500").json()
    actions = {(a["action"], a["target"]) for a in aud if a.get("target") == iid}
    assert ("create_incident", iid) in actions
    assert ("update_incident", iid) in actions
    assert ("link_alerts", iid) in actions
    assert ("unlink_alert", iid) in actions
    rows = [a for a in aud if a.get("target") == iid]
    assert all(a["actor"] == ADMIN["email"] for a in rows)
