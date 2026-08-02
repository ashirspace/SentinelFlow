# SentinelFlow — Product Requirements Document

## Original problem statement
Build the MVP of SentinelFlow, an explainable SIEM (Security Information & Event Management) platform. The system ingests security logs, normalizes them into a common schema, runs 6 rule-based detections (no ML), and produces evidence-backed alerts. No auto-blocking — every response is a human-approved recommendation.

## Architecture (as delivered)
- **Backend**: FastAPI + Motor (async MongoDB). Single-process, /api-prefixed routes.
- **DB**: MongoDB. Collections: `users`, `login_attempts`, `log_sources`, `raw_logs` (72h TTL index on `created_at_bson`), `normalized_events`, `alerts`, `audit_logs`.
- **Auth**: JWT (PyJWT), bcrypt, httpOnly cookies (`access_token`, `refresh_token`), SameSite=None, Secure. RBAC: `admin`, `analyst`. Brute-force lockout (5 fails / 15 min).
- **Detection engine**: Pure Python rules module — R001 brute-force, R002 success-after-fail, R003 off-hours/unusual-country, R004 privilege escalation, R005 malicious-IP blocklist, R006 silent source.
- **Normalization**: Field aliasing → common schema (event_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, user, host, app, url, http_method, http_status, severity, risk_score, rule_id, correlation_id, action, country, raw_log).
- **Frontend**: React + Tailwind + Shadcn UI + Recharts + Sonner. IBM Plex Sans + JetBrains Mono. Dark tactical theme.

## Personas
- **Admin** — manages users, ingests logs, seeds demo data, views audit log.
- **Analyst** — triages alerts, explores logs, ingests logs (cannot manage users/audit).

## Core requirements (from problem statement)
- Admin-created users, login, RBAC (admin/analyst) — ✅
- Log ingestion via JSON/CSV upload — ✅ (also NDJSON)
- Normalization to canonical schema — ✅
- Log explorer with search + filters — ✅
- Dashboard: event volume, top IPs, alerts by severity — ✅
- 6 detection rules with explainable output — ✅
- Alerts list with 6-status lifecycle — ✅
- Audit log — ✅
- Every alert traceable to raw log evidence — ✅
- No auto-blocking (recommended action + human approval) — ✅
- `raw_logs` 72h auto-purge — ✅ (MongoDB TTL index)

## What's been implemented — 2026-02-02 (MVP v1)
- FastAPI backend with 22 endpoints under `/api/*`
- Startup seed: admin + analyst users, indexes, TTL
- 6 detection rules with evidence linkage and human-readable explanations
- 7 frontend pages: Login, Dashboard, Alerts, Log Explorer, Ingestion, Rules, Users, Audit
- Right drawer log/alert inspector with syntax-highlighted raw JSON
- Recharts: 24h event volume, top source IPs, alerts-by-severity donut
- Toast notifications via sonner
- 25/25 backend pytest passed; frontend E2E flows all green

## Iteration 2 — 2026-02-02
- **Syslog ingestion**: RFC-5424 + RFC-3164 (BSD) parser in `syslog_parser.py`.
  - File upload with `.log`/`.syslog` extension auto-routes to the syslog parser.
  - New endpoint `POST /api/ingest/syslog` accepts `{source_name, text}` for paste/curl.
  - New "Paste syslog" tab on the Ingest page (uses shadcn Tabs).
- **3 new detection rules** (RULES_META now = 9):
  - `R007` Excessive API requests: ≥120 web requests from same `src_ip` inside 1 min → Suspicious.
  - `R008` Injection patterns in URL: SQLi / XSS / directory-traversal regex matches → Likely malicious.
  - `R009` New-device admin login: successful admin login from an unseen `(src_ip, user_agent)` fingerprint → Suspicious. Backed by `known_devices` collection with unique index.
- **Email notifications** (`notifier.py`):
  - Standard-library SMTP with STARTTLS. Env-driven (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_USE_TLS`, `ALERT_EMAIL_TO`).
  - Dedup via new `alert_notifications` MongoDB collection keyed `{rule_id}:{fingerprint}:{hour}` with TTL (`ALERT_EMAIL_DEDUP_HOURS`).
  - Severity floor via `ALERT_EMAIL_MIN_SEVERITY` (default `Suspicious`).
  - `GET /api/notifier/status` returns config + enable state. Dashboard shows `Email · on/off` pill.
  - Safe when unconfigured: pipeline runs, send is skipped, no exceptions.
- **Normalize schema**: added `user_agent` canonical field with aliases (`user-agent`, `ua`, `useragent`).
- **Testing**: 33/33 backend pytest passed; frontend E2E for the 3 new features (notifier-pill, 9 rule cards, syslog paste) green.

## Iteration 3 — 2026-02-02
- **Response Actions (human-approved)** — `responses.py` executors, endpoint `POST /api/alerts/{id}/approve`. All 4 action types with per-rule allow-list (`RECOMMENDED_BY_RULE`), each writing a `response_actions` row AND an `audit_logs` row with approver + result:
  - `block_ip` → writes to `ip_blocklist`. **R010** rule appended (auto-fires on future events from the blocked IP), Likely malicious.
  - `disable_account` → SentinelFlow-managed users set `disabled=true` + `token_version` bumped; external accounts get result `recommended_external` with copy-paste recommendation text.
  - `revoke_session` → bumps `users.token_version`; JWT `tv` claim mismatch immediately invalidates existing sessions.
  - `escalate_incident` → creates row in new `incidents` collection with alert evidence prefilled. Repeat call on same alert links instead of duplicating.
- **Log Management**:
  - `GET /api/sources` includes computed `health` (healthy / delayed / silent), `retention_hours`, `paused`.
  - `PATCH /api/sources/{name}` for pause + retention override (1–72h).
  - `POST /api/sources/{name}/rotate-key` returns a fresh `ingest_api_key`.
  - `DELETE /api/sources/{name}?purge_events=true|false`.
  - **Per-source raw retention** enforced via new per-doc `expires_at` field + TTL index on `raw_logs.expires_at` (replaces the old fixed-72h index).
- **Log Explorer additions**:
  - `PATCH /api/events/{event_id}` for tags / note / reviewed.
  - `GET /api/export/events.csv?...` streams filtered events as CSV.
- **Auth updates**: JWT carries `tv` (token_version); `get_current_user` rejects `Session revoked` and `Account disabled`.
- **New frontend pages**: **Log Sources** (health, retention dialog, rotate-key dialog), **Incidents** (list + drawer with linked alerts + evidence). Alerts drawer now has a Response Actions panel with an "Approve" button per allowed action + Approvals history. Log Explorer has Export CSV + annotations panel.
- **Testing**: 60/60 backend pytest passed (27 new + 33 regression); frontend E2E all green after fixing an initial `exportCsv` undef in Explorer.jsx.

## Iteration 4 — 2026-02-02
- **Push-only live ingestion path**: new `POST /api/v1/ingest` endpoint authenticated ONLY by a scoped, write-only API key (`sfk_...` prefix). Per-request:
  - `Authorization: Bearer sfk_...` or `X-Ingest-Key` header.
  - Rate limit: **60 req/min per key** (in-memory sliding window in `ingest_v1.py`).
  - Max **1000 events/req** and **1 MB body**.
  - Reuses the existing `_ingest_events` pipeline → normalization, R001–R010 detection, notifier.
  - Returns `{ingested, alerts, source, rate_limit: {remaining, reset_seconds, limit_per_min}}`.
- **Keys are hashed at rest** — only sha256 hash stored (`ingest_api_key_hash`) plus a 12-char hint. Plaintext returned exactly once at create/rotate. `GET /api/sources` never returns the hash.
- **Admin ops**: `POST /api/sources` (create + reveal), `POST /api/sources/{name}/rotate-key`, new `POST /api/sources/{name}/revoke-key` (unset hash, ingest disabled until next rotate). Every op writes to audit_logs.
- **Cross-endpoint isolation**: an ingest key on any other endpoint (`GET /api/events`, `/api/sources`, etc.) is rejected with 401 — it is only valid for `POST /api/v1/ingest`.
- **`GET /api/ingest/config`**: returns endpoint URL and quotas so the UI can render live snippets.
- **Frontend**:
  - Sources page: **Add source** button opens a create dialog; on submit a one-time **Connect** dialog reveals the API key with copyable **curl**, **Fluent Bit**, **Vector**, and **Node** snippets pre-filled with the endpoint + key.
  - Per-row **Revoke** button next to Rotate.
  - Push-only endpoint info card at the top of the Sources page.
- **Testing**: 18/18 iteration-4 pytest + full frontend E2E green after fixing (a) sha256 hash leak in `GET /api/sources`, (b) `copy-endpoint` data-testid on the reveal dialog.

## Iteration 5 — 2026-02-02
- **Manual incident creation**: `POST /api/incidents` accepts title/severity/summary + `alert_ids[]`; aggregates evidence, starts a timeline.
- **Timeline**: every incident change (status, root_cause, note, title, alerts_added, alerts_removed) appends a typed entry `{at, kind, by, text, meta}`. Backfilled `[]` on legacy incidents in responses.
- **Root cause** field on incidents; PATCH persists + records a `root_cause` timeline entry.
- **Lifecycle now Open → Investigating → Resolved → Closed** (Resolved is new; validated in the Pydantic pattern).
- **Link / unlink alerts**: `POST /api/incidents/{id}/alerts` and `DELETE /api/incidents/{id}/alerts/{alert_id}`. Recomputes evidence on unlink. `GET /api/alerts/{id}` now returns `linked_incidents`.
- **Saved searches** (Log Explorer): `saved_searches` collection with unique `(owner, name)` index. `GET/POST/DELETE /api/saved-searches`. Per-user visibility.
- **Frontend**: Incidents page adds a **New incident** button + status filter, and the drawer now has a lifecycle updater with Resolved, a root-cause editor, an animated timeline (icons per kind, reverse-chronological), per-alert unlink buttons. Alerts drawer adds a **Link to existing incident** picker + a `linked_incidents` chip. Log Explorer adds a **Save search** dialog and a saved-searches chip strip (click to apply, × to delete).
- **Alert lifecycle + detection rules untouched** (verified in tests).
- **Testing**: 17/17 iteration-5 pytest + frontend E2E green after adding the initially-missed `new-incident-btn` and `incident-status-filter` render (test agent flagged, patched).

## Prioritized backlog (deferred for follow-up prompts, per problem statement)
### P1
- Event correlation across multiple rules → incidents (group related alerts under one incident id)
- Additional log formats (Syslog RFC-5424, Windows Event XML, CloudTrail, GCP audit)
- Reports (weekly digest PDF/CSV export)

### P2
- Notification integrations (Slack, PagerDuty, email via SES/Resend)
- Rule editor UI (allow admins to tune thresholds & windows)
- MFA / SSO
- IP geolocation lookup (currently trusts `country` field)
- Live tail / WebSocket streaming for the Log Explorer

## Next actions
See finish summary.
