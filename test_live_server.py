import requests
import urllib3
import json
import time

urllib3.disable_warnings()

BASE = "https://siem.abpplus.com/api"
s = requests.Session()
s.verify = False

results = []

def record(cat, name, ok, detail):
    status = "PASS" if ok else "FAIL"
    results.append((cat, name, status, detail))
    print(f"[{status}] {cat} -> {name}: {detail}")

print("=== STARTING LIVE SERVER AUDIT ON https://siem.abpplus.com ===")

# 1. Root Service Health
try:
    r = s.get(f"{BASE}/", timeout=10)
    record("Core", "Root Health (/api/)", r.status_code == 200, f"Status {r.status_code}: {r.text[:60]}")
except Exception as e:
    record("Core", "Root Health (/api/)", False, str(e))

# 2. Login as Admin
try:
    r = s.post(f"{BASE}/auth/login", json={"email": "admin@sentinelflow.io", "password": "Admin@12345"}, timeout=10)
    data = r.json() if r.status_code == 200 else {}
    record("Auth", "Admin Login", r.status_code == 200, f"Role: {data.get('role')}, Name: {data.get('name')}")
except Exception as e:
    record("Auth", "Admin Login", False, str(e))

# 3. Session Validation (/auth/me)
try:
    r = s.get(f"{BASE}/auth/me", timeout=10)
    data = r.json() if r.status_code == 200 else {}
    record("Auth", "Session Verification (/auth/me)", r.status_code == 200, f"Email: {data.get('email')}")
except Exception as e:
    record("Auth", "Session Verification (/auth/me)", False, str(e))

# 4. Dashboard Stats Aggregation
try:
    r = s.get(f"{BASE}/dashboard/stats", timeout=10)
    data = r.json() if r.status_code == 200 else {}
    record("Dashboard", "Stats Aggregation (/dashboard/stats)", r.status_code == 200, 
           f"24h Events: {data.get('events_24h')}, Open Alerts: {data.get('open_alerts')}, Top IPs: {len(data.get('top_ips', []))}")
except Exception as e:
    record("Dashboard", "Stats Aggregation (/dashboard/stats)", False, str(e))

# 5. Detection Rules
try:
    r = s.get(f"{BASE}/rules", timeout=10)
    rules = r.json() if r.status_code == 200 else []
    record("Detection", "Detection Rules Listing (/rules)", r.status_code == 200 and len(rules) >= 9,
           f"{len(rules)} rules configured: {rules[0].get('id')} to {rules[-1].get('id')}")
except Exception as e:
    record("Detection", "Detection Rules Listing (/rules)", False, str(e))

# 6. Log Sources Listing
try:
    r = s.get(f"{BASE}/sources", timeout=10)
    sources = r.json() if r.status_code == 200 else []
    names = [s.get("name") for s in sources]
    record("Sources", "Log Sources Management (/sources)", r.status_code == 200, f"{len(sources)} sources active: {names}")
except Exception as e:
    record("Sources", "Log Sources Management (/sources)", False, str(e))

# 7. Log Explorer Events Search & Pagination
try:
    r = s.get(f"{BASE}/events?limit=5", timeout=10)
    data = r.json() if r.status_code == 200 else {}
    record("Log Explorer", "Normalized Events Search (/events)", r.status_code == 200,
           f"Total Events: {data.get('total')}, Page count: {len(data.get('events', []))}")
except Exception as e:
    record("Log Explorer", "Normalized Events Search (/events)", False, str(e))

# 8. Alerts Listing
sample_alert_id = None
try:
    r = s.get(f"{BASE}/alerts?limit=5", timeout=10)
    data = r.json() if r.status_code == 200 else []
    alerts = data if isinstance(data, list) else data.get("alerts", [])
    if alerts:
        sample_alert_id = alerts[0].get("id")
    record("Alerts", "Alerts Queue (/alerts)", r.status_code == 200,
           f"Total Alerts: {len(alerts)}, Active Alert ID: {sample_alert_id}")
except Exception as e:
    record("Alerts", "Alerts Queue (/alerts)", False, str(e))

# 9. Alert Details with Evidence Link
try:
    if sample_alert_id:
        r = s.get(f"{BASE}/alerts/{sample_alert_id}", timeout=10)
        data = r.json() if r.status_code == 200 else {}
        record("Alerts", "Alert Evidence Drilldown", r.status_code == 200,
               f"Rule: {data.get('rule_id')}, Severity: {data.get('severity')}, Evidence items: {len(data.get('evidence', []))}")
    else:
        record("Alerts", "Alert Evidence Drilldown", False, "No sample alert found")
except Exception as e:
    record("Alerts", "Alert Evidence Drilldown", False, str(e))

# 10. Incidents Management
sample_inc_id = None
try:
    r = s.get(f"{BASE}/incidents", timeout=10)
    incs = r.json() if r.status_code == 200 else []
    if incs:
        sample_inc_id = incs[0].get("id")
    record("Incidents", "Incidents Queue (/incidents)", r.status_code == 200,
           f"Incidents count: {len(incs)}, Sample Incident: {incs[0].get('title') if incs else 'None'}")
except Exception as e:
    record("Incidents", "Incidents Queue (/incidents)", False, str(e))

# 11. Reports Summary
try:
    r = s.get(f"{BASE}/reports/summary", timeout=10)
    data = r.json() if r.status_code == 200 else {}
    record("Reports", "Reports Metric Summary (/reports/summary)", r.status_code == 200,
           f"Alerts in Range: {data.get('total_alerts')}, Incidents in Range: {data.get('total_incidents')}")
except Exception as e:
    record("Reports", "Reports Metric Summary (/reports/summary)", False, str(e))

# 12. PDF Compliance Report Export
try:
    r = s.get(f"{BASE}/reports/combined.pdf", timeout=15)
    record("Reports", "PDF Report Generation (/reports/combined.pdf)",
           r.status_code == 200 and r.headers.get("content-type") == "application/pdf",
           f"Size: {len(r.content)} bytes, Content-Type: {r.headers.get('content-type')}")
except Exception as e:
    record("Reports", "PDF Report Generation (/reports/combined.pdf)", False, str(e))

# 13. CSV Export
try:
    r = s.get(f"{BASE}/reports/alerts.csv", timeout=10)
    lines = r.text.strip().splitlines()
    record("Reports", "CSV Export (/reports/alerts.csv)", r.status_code == 200, f"Exported {len(lines)} rows")
except Exception as e:
    record("Reports", "CSV Export (/reports/alerts.csv)", False, str(e))

# 14. Audit Trail (Admin Only)
try:
    r = s.get(f"{BASE}/audit?limit=5", timeout=10)
    logs = r.json() if r.status_code == 200 else []
    record("Audit", "SOC Audit Trail (/audit)", r.status_code == 200, f"{len(logs)} audit entries retrieved")
except Exception as e:
    record("Audit", "SOC Audit Trail (/audit)", False, str(e))

# 15. User Management (Admin Only)
try:
    r = s.get(f"{BASE}/users", timeout=10)
    users = r.json() if r.status_code == 200 else []
    record("Users", "User Management (/users)", r.status_code == 200, f"{len(users)} registered users")
except Exception as e:
    record("Users", "User Management (/users)", False, str(e))

# 16. Ingest Config & Snippets API
try:
    r = s.get(f"{BASE}/ingest/config", timeout=10)
    data = r.json() if r.status_code == 200 else {}
    record("Ingest", "Ingest Config & Snippets (/ingest/config)", r.status_code == 200, f"Endpoint: {data.get('endpoint')}")
except Exception as e:
    record("Ingest", "Ingest Config & Snippets (/ingest/config)", False, str(e))

# 17. Akamai Integration Ingest Route
try:
    # Test probe to akamai integration endpoint
    r = s.post(f"{BASE}/integrations/akamai/akamai-abpplus/logs", json={}, timeout=10)
    # Expected: 401 without key or 200 with key (route exists and handled by FastAPI)
    record("Akamai", "Akamai Integration Route Availability", r.status_code in (200, 401, 400),
           f"Route active, returns HTTP {r.status_code} (as expected for auth validation)")
except Exception as e:
    record("Akamai", "Akamai Integration Route Availability", False, str(e))

# 18. Frontend Static Assets Availability
try:
    r_front = requests.get("https://siem.abpplus.com/login", verify=False, timeout=10)
    has_bundle = "/static/js/main." in r_front.text
    record("Frontend", "Login Page & Static Bundle Loading", r_front.status_code == 200 and has_bundle,
           f"HTTP {r_front.status_code}, Contains React bundle: {has_bundle}")
except Exception as e:
    record("Frontend", "Login Page & Static Bundle Loading", False, str(e))

print("=== AUDIT COMPLETE ===")
