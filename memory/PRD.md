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
