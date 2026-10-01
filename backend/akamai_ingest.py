"""Akamai DataStream 2 ingestion helpers.

DataStream can POST bundled JSON logs to a custom HTTPS endpoint. This module
keeps the Akamai-specific shape out of the generic SentinelFlow ingest path.
"""
import gzip
import ipaddress
import json
import urllib.parse
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
    """Parse DataStream JSON/NDJSON or Space-delimited payloads into event dictionaries."""
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

    # Test probes or validation pings from Akamai
    if text.lower() in ("test", "ping", "ok", "health", "healthcheck") or ("akamai" in text.lower() and len(text) < 120 and not text.startswith(("{", "["))):
        return []

    try:
        payload = json.loads(text)
        records = _extract_records(payload)
        return [_to_sentinelflow_event(r) for r in records]
    except json.JSONDecodeError:
        pass

    records = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue

        # Try line-delimited JSON
        if line.startswith("{") and line.endswith("}"):
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(_to_sentinelflow_event(item))
                    continue
            except json.JSONDecodeError:
                pass

        # Try Akamai space- or tab-delimited format (standard DataStream 2 Delivery format)
        delimited_event = _parse_akamai_delimited_line(line)
        if delimited_event:
            records.append(delimited_event)
            continue

    if not records:
        if len(text) < 256:
            return []
        raise ValueError("no Akamai records found in payload")

    return records


def _parse_akamai_delimited_line(line: str) -> Optional[Dict[str, Any]]:
    tokens = line.split("\t") if "\t" in line else line.split(" ")
    if len(tokens) < 8:
        return None

    HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

    # Check for standard 67-column Akamai DataStream 2 Delivery schema
    if len(tokens) >= 16 and tokens[14].upper() in HTTP_METHODS and tokens[11].isdigit():
        req_id = tokens[3] if len(tokens) > 3 and tokens[3] != "-" else None

        ts_val = None
        if len(tokens) > 4 and tokens[4] != "-":
            try:
                ts_val = float(tokens[4])
            except ValueError:
                ts_val = tokens[4]

        src_ip = tokens[10] if tokens[10] != "-" else None

        status_code = None
        try:
            status_code = int(tokens[11])
        except ValueError:
            pass

        proto = tokens[12] if tokens[12] != "-" else "HTTP/2"
        host = tokens[13] if tokens[13] != "-" else None
        method = tokens[14].upper()

        raw_path = tokens[15] if tokens[15] != "-" else "/"
        if not raw_path.startswith("/") and not raw_path.startswith("http"):
            raw_path = "/" + raw_path

        port = 443
        if len(tokens) > 16 and tokens[16].isdigit():
            port = int(tokens[16])

        content_type = tokens[18] if len(tokens) > 18 and tokens[18] != "-" else None

        ua = None
        if len(tokens) > 19 and tokens[19] != "-":
            ua = urllib.parse.unquote(tokens[19])

        referer = None
        if len(tokens) > 38 and tokens[38] != "-":
            referer = urllib.parse.unquote(tokens[38])

        country = None
        if len(tokens) > 58 and tokens[58] != "-" and len(tokens[58]) == 2:
            country = tokens[58].upper()

        action = "akamai_edge_request"
        severity = "Informational"

        line_upper = line.upper()
        if "ERR_FORWARDING_DENIED" in line_upper or status_code == 502:
            action = "akamai_origin_error"
            severity = "Suspicious"
        elif "DENY" in line_upper or "BLOCK" in line_upper:
            action = "akamai_deny"
            severity = "Likely malicious"
        elif "WAF" in line_upper or "ATTACK" in line_upper:
            action = "akamai_security_event"
            severity = "Suspicious"
        elif status_code and status_code in (401, 403):
            action = "akamai_blocked"
            severity = "Suspicious"

        event = {
            "timestamp": _epoch_or_value(ts_val),
            "src_ip": src_ip,
            "dst_ip": None,
            "dst_port": port,
            "protocol": proto,
            "host": host,
            "http_method": method,
            "url": raw_path,
            "http_status": status_code,
            "user_agent": ua,
            "referer": referer,
            "country": country,
            "app": "web",
            "action": action,
            "severity": severity,
            "correlation_id": req_id,
            "raw_log": line,
        }
        return event

    return _parse_akamai_delimited_heuristic(tokens, line)


def _parse_akamai_delimited_heuristic(tokens: List[str], raw_line: str) -> Optional[Dict[str, Any]]:
    HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
    method = None
    path = None
    host = None
    status = None
    ip = None
    ts = None
    country = None

    for idx, tok in enumerate(tokens):
        if tok.upper() in HTTP_METHODS and not method:
            method = tok.upper()
            if idx + 1 < len(tokens):
                path = tokens[idx + 1]
                if not path.startswith("/") and not path.startswith("http"):
                    path = "/" + path
            if idx > 0 and "." in tokens[idx - 1]:
                host = tokens[idx - 1]
        if not ip and ("." in tok or ":" in tok):
            try:
                ipaddress.ip_address(tok)
                ip = tok
            except ValueError:
                pass
        if not status and tok.isdigit() and len(tok) == 3 and tok.startswith(("1", "2", "3", "4", "5")):
            try:
                status = int(tok)
            except ValueError:
                pass
        if not ts and tok.replace(".", "", 1).isdigit() and len(tok.split(".")[0]) == 10:
            try:
                ts = float(tok)
            except ValueError:
                pass
        if not country and len(tok) == 2 and tok.isalpha() and tok.isupper():
            country = tok

    if not ip and not path and not method:
        return None

    return {
        "timestamp": _epoch_or_value(ts),
        "src_ip": ip,
        "dst_port": 443,
        "protocol": "HTTP/2",
        "host": host,
        "http_method": method or "GET",
        "url": path or "/",
        "http_status": status or 200,
        "country": country,
        "app": "web",
        "action": "akamai_edge_request",
        "severity": "Informational",
        "raw_log": raw_line,
    }


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
    query = _first(record, http_message, "queryStr", "queryString", "query")
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
