"""Akamai DataStream 2 ingestion helpers.

DataStream can POST bundled JSON logs to a custom HTTPS endpoint. This module
keeps the Akamai-specific shape out of the generic SentinelFlow ingest path.
"""
import gzip
import ipaddress
import json
from typing import Any, Dict, List, Optional

# Official Akamai DataStream & Edge Server CIDR blocks allowed for log delivery
AKAMAI_INGEST_CIDRS = [
    "23.64.0.0/14",
    "23.72.0.0/13",
    "69.192.0.0/16",
    "72.246.0.0/15",
    "88.221.0.0/16",
    "92.122.0.0/15",
    "96.6.0.0/15",
    "96.16.0.0/15",
    "104.64.0.0/10",
    "118.214.0.0/16",
    "172.224.0.0/12",
    "172.232.0.0/13",
    "173.222.0.0/15",
    "184.50.0.0/15",
    "184.84.0.0/14",
]

_AKAMAI_NETWORKS = [ipaddress.ip_network(cidr) for cidr in AKAMAI_INGEST_CIDRS]


def is_akamai_ip(ip_str: Optional[str]) -> bool:
    """Check if an IP address belongs to the official Akamai edge / egress CIDRs."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
        return any(ip in net for net in _AKAMAI_NETWORKS)
    except ValueError:
        return False


def parse_akamai_payload(raw: bytes) -> List[Dict[str, Any]]:
    """Parse DataStream JSON/NDJSON payloads into event dictionaries."""
    if not raw or not raw.strip():
        return []

    # Auto-detect and decompress gzip payloads from Akamai
    if raw.startswith(b"\x1f\x8b"):
        try:
            raw = gzip.decompress(raw)
        except Exception as exc:
            raise ValueError(f"failed to decompress gzip Akamai payload: {exc}") from exc

    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return []

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for i, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {i + 1}: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"line {i + 1} must be a JSON object")
            records.append(item)
        if not records:
            raise ValueError("no Akamai records found")
        return [_to_sentinelflow_event(r) for r in records]

    records = _extract_records(payload)
    return [_to_sentinelflow_event(r) for r in records]


def _extract_records(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        for key in ("events", "logs", "records"):
            if isinstance(payload.get(key), list):
                records = payload[key]
                break
        else:
            records = [payload]
    else:
        raise ValueError("Akamai payload must be a JSON object, array, or NDJSON")

    if not records:
        raise ValueError("no Akamai records found")
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"Akamai record #{i} must be a JSON object")
    return records


def _to_sentinelflow_event(record: Dict[str, Any]) -> Dict[str, Any]:
    http_message = record.get("httpMessage") if isinstance(record.get("httpMessage"), dict) else {}
    attack_data = record.get("attackData") if isinstance(record.get("attackData"), dict) else {}
    geo = record.get("geo") if isinstance(record.get("geo"), dict) else {}

    event = dict(record)
    event.update({
        "timestamp": _epoch_or_value(_first(record, http_message, "reqTimeSec", "timeStamp", "start", "reqTime", "timestamp")),
        "src_ip": _first(record, attack_data, "cliIP", "clientIP", "clientIp", "client_ip"),
        "dst_ip": _first(record, "edgeIP", "edge_ip"),
        "dst_port": _first(record, http_message, "reqPort", "port"),
        "protocol": _first(record, http_message, "proto", "protocol"),
        "host": _first(record, http_message, "reqHost", "host"),
        "http_method": _first(record, http_message, "reqMethod", "method"),
        "url": _akamai_url(record, http_message),
        "http_status": _first(record, http_message, "statusCode", "status"),
        "user_agent": _first(record, "UA", "userAgent", "user_agent", "user-agent"),
        "country": _first(record, geo, "country"),
        "app": "web",
        "action": _akamai_action(record, attack_data),
        "correlation_id": _first(record, http_message, "reqId", "requestId"),
    })

    severity = _security_severity(attack_data)
    if severity:
        event["severity"] = severity
    return event


def _akamai_url(record: Dict[str, Any], http_message: Dict[str, Any]) -> Any:
    path = _first(record, http_message, "reqPath", "path")
    query = _first(record, "queryStr", "queryString")
    if path and query and query != "-":
        sep = "&" if "?" in str(path) else "?"
        return f"{path}{sep}{query}"
    return path


def _akamai_action(record: Dict[str, Any], attack_data: Dict[str, Any]) -> str:
    action = _first(record, attack_data, "ruleActions", "action")
    if action:
        return f"akamai_{action}"
    if record.get("type") == "akamai_siem":
        return "akamai_security_event"
    return "akamai_edge_request"


def _security_severity(attack_data: Dict[str, Any]) -> str:
    action = str(attack_data.get("ruleActions") or "").lower()
    rules = str(attack_data.get("rules") or attack_data.get("ruleMessages") or "")
    if "deny" in action or "block" in action:
        return "Likely malicious"
    if action or rules:
        return "Suspicious"
    return ""


def _first(*items: Any) -> Any:
    maps = [item for item in items if isinstance(item, dict)]
    keys = [item for item in items if isinstance(item, str)]
    for mapping in maps:
        lowered = {str(k).lower(): v for k, v in mapping.items()}
        for key in keys:
            value = lowered.get(key.lower())
            if value not in (None, "", "-"):
                return value
    return None


def _epoch_or_value(value: Any) -> Any:
    if isinstance(value, str):
        s = value.strip()
        if s.replace(".", "", 1).isdigit():
            try:
                return float(s)
            except ValueError:
                return value
    return value
