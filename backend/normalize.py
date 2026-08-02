"""Normalize incoming log records into SentinelFlow's common schema."""
import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

CANONICAL_FIELDS = [
    "event_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "user", "host", "app", "url", "http_method", "http_status",
    "severity", "risk_score", "rule_id", "correlation_id", "action",
    "country", "user_agent", "raw_log",
]

# Simple key aliases so common auth-log / web-access-log formats work out of the box.
FIELD_ALIASES = {
    "ip": "src_ip", "source_ip": "src_ip", "client_ip": "src_ip", "remote_addr": "src_ip",
    "destination_ip": "dst_ip", "target_ip": "dst_ip",
    "username": "user", "userid": "user", "account": "user",
    "status": "http_status", "code": "http_status", "response_code": "http_status",
    "hostname": "host", "server": "host",
    "method": "http_method",
    "path": "url", "uri": "url", "endpoint": "url",
    "time": "timestamp", "ts": "timestamp", "@timestamp": "timestamp", "datetime": "timestamp",
    "application": "app", "service": "app",
    "operation": "action", "event_type": "action", "event": "action",
    "geo_country": "country", "src_country": "country",
    "protocol_name": "protocol",
    "source_port": "src_port", "destination_port": "dst_port",
    "user-agent": "user_agent", "useragent": "user_agent", "ua": "user_agent",
}


def _parse_ts(v: Any) -> str:
    """Return ISO-8601 UTC string. Fallback to now()."""
    if v is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(v, (int, float)):
        # epoch seconds or ms
        try:
            if v > 1e12:
                v = v / 1000
            return datetime.fromtimestamp(float(v), tz=timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
    if isinstance(v, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
            try:
                dt = datetime.strptime(v, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat()
            except Exception:
                continue
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass
    return datetime.now(timezone.utc).isoformat()


def normalize_record(raw: Dict[str, Any], source_name: str) -> Dict[str, Any]:
    # Copy + apply aliases
    flat: Dict[str, Any] = {}
    for k, v in raw.items():
        canonical = FIELD_ALIASES.get(k.lower(), k.lower())
        flat[canonical] = v

    event = {f: None for f in CANONICAL_FIELDS}
    event["event_id"] = str(uuid.uuid4())
    event["timestamp"] = _parse_ts(flat.get("timestamp"))
    event["src_ip"] = flat.get("src_ip")
    event["dst_ip"] = flat.get("dst_ip")
    event["src_port"] = _to_int(flat.get("src_port"))
    event["dst_port"] = _to_int(flat.get("dst_port"))
    event["protocol"] = flat.get("protocol")
    event["user"] = flat.get("user")
    event["host"] = flat.get("host")
    event["app"] = flat.get("app") or _infer_app(flat, source_name)
    event["url"] = flat.get("url")
    event["http_method"] = flat.get("http_method")
    event["http_status"] = _norm_status(flat.get("http_status"))
    event["severity"] = flat.get("severity") or "Informational"
    event["risk_score"] = _to_int(flat.get("risk_score")) or 0
    event["rule_id"] = flat.get("rule_id")
    event["correlation_id"] = flat.get("correlation_id")
    event["action"] = flat.get("action") or flat.get("event")
    event["country"] = (flat.get("country") or "").upper() or None
    event["user_agent"] = flat.get("user_agent")
    event["source_name"] = source_name
    event["raw_log"] = raw
    return event


def _infer_app(flat: Dict[str, Any], source_name: str) -> str:
    if flat.get("http_method") or flat.get("url"):
        return "web"
    if "login" in str(flat.get("action") or "").lower() or "auth" in source_name.lower():
        return "auth"
    return source_name or "unknown"


def _norm_status(v: Any) -> Any:
    if v is None:
        return None
    s = str(v).lower().strip()
    if s in {"200", "ok", "success", "succeeded", "successful"}:
        return "success"
    if s in {"401", "403", "fail", "failed", "failure", "denied", "invalid_credentials"}:
        return "fail"
    return v


def _to_int(v: Any):
    try:
        if v is None or v == "":
            return None
        return int(v)
    except Exception:
        return None


def parse_upload(filename: str, content: bytes) -> List[Dict[str, Any]]:
    """Return raw records list from JSON, NDJSON, CSV, or Syslog file bytes."""
    from syslog_parser import parse_syslog, looks_like_syslog
    name = (filename or "").lower()
    text = content.decode("utf-8", errors="replace")

    if name.endswith((".syslog", ".log")) or looks_like_syslog(text):
        records = parse_syslog(text)
        if records:
            return records
        # fall through to other parsers if syslog didn't match any line

    if name.endswith(".json") or text.lstrip().startswith(("[", "{")):
        data = json.loads(text)
        if isinstance(data, dict):
            # allow { "events": [...] } or single record
            if "events" in data and isinstance(data["events"], list):
                return data["events"]
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError("Unsupported JSON structure")
    if name.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(text))
        return [dict(row) for row in reader]
    # try newline-delimited JSON
    lines = [ln for ln in text.splitlines() if ln.strip()]
    try:
        return [json.loads(ln) for ln in lines]
    except Exception:
        raise ValueError("Unsupported file format. Use JSON, NDJSON, CSV, or Syslog.")
