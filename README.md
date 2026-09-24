# SentinelFlow — Explainable SIEM & SOAR Platform

SentinelFlow is an evidence-backed Security Information & Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform. It normalizes security event logs, runs 10 rule-based detection engines, produces explainable alerts linked directly to raw log evidence, and provides human-approved response workflows.

---

## 🚀 Quick Start

### 1. Launch All Services
Double click `start_all.bat` or run the following from PowerShell:
```powershell
.\start_all.bat
```
This automatically starts:
- **MongoDB** on `mongodb://127.0.0.1:27017` (data saved to `.runtime/mongo-data`)
- **FastAPI Backend** on `http://127.0.0.1:8000`
- **React Frontend** on `http://localhost:3000`

### 2. Access the Application
- **Frontend Web UI**: [http://localhost:3000](http://localhost:3000)
- **Backend API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health Check**: [http://localhost:8000/api/](http://localhost:8000/api/)

### 3. Default Credentials
| Role | Email | Password |
|------|-------|----------|
| **Admin** | `admin@sentinelflow.io` | `Admin@12345` |
| **Analyst** | `analyst@sentinelflow.io` | `Analyst@123` |

---

## 🛑 Stopping Services
Double click `stop_all.bat` or run:
```powershell
.\stop_all.bat
```

---

## 🏗️ Architecture & Features

### Core Engine
1. **Multi-Source Log Ingestion**:
   - Web / JSON & CSV upload
   - Syslog (RFC-5424 and RFC-3164 BSD formats)
   - Akamai DataStream 2 integration
   - Push API (`POST /api/v1/ingest`) with hashed, scoped API keys (`sfk_...`)
2. **Canonical Normalization**:
   - Normalizes disparate log schemas into: `event_id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `user`, `user_agent`, `host`, `app`, `url`, `http_method`, `http_status`, `severity`, `risk_score`, `rule_id`, `correlation_id`, `action`, `country`, `raw_log`.
3. **10 Detection Rules**:
   - **R001**: Brute-force authentication attempts
   - **R002**: Successful login after multiple failed attempts
   - **R003**: Off-hours / anomalous country login
   - **R004**: Privilege escalation
   - **R005**: Malicious IP blocklist match
   - **R006**: Silent log source detection
   - **R007**: Excessive API request rate anomaly
   - **R008**: Web injection patterns (SQLi, XSS, Path Traversal)
   - **R009**: New device admin login
   - **R010**: Dynamically blocked IP match
4. **Human-in-the-Loop SOAR**:
   - No blind auto-blocking.
   - 4 approved actions: `block_ip`, `disable_account`, `revoke_session`, `escalate_incident`.
   - Immutable audit trail of every action and approver.
5. **Incidents & Reporting**:
   - Complete incident lifecycle (Open -> Investigating -> Resolved -> Closed).
   - Interactive timeline, alert linking/unlinking, and root-cause analysis.
   - One-click CSV and styled PDF compliance reports.
   - Slack & Microsoft Teams webhook dispatch.

---

## 🧪 Testing

To run the complete automated test suite (125 tests across all modules):
```powershell
cd backend
$env:REACT_APP_BACKEND_URL="http://127.0.0.1:8000"
python -m pytest tests/ -q
```
