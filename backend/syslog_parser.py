"""RFC-5424 and RFC-3164 (BSD) syslog line parsers.

Returns a list of dicts compatible with normalize.normalize_record.
No external deps.
"""
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SEVERITY_MAP = {
    0: "Likely malicious",  # emergency
    1: "Likely malicious",  # alert
    2: "Likely malicious",  # critical
    3: "Suspicious",        # error
    4: "Suspicious",        # warning
    5: "Informational",     # notice
    6: "Informational",     # info
    7: "Informational",     # debug
}

# RFC-5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+"
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<rest>.*)$"
)

# RFC-3164 (BSD): <PRI>MMM DD HH:MM:SS HOSTNAME TAG: MSG
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)


def _pri_to_sev(pri_int: int) -> str:
    sev = pri_int & 0x07
    return SEVERITY_MAP.get(sev, "Informational")


def _parse_rfc5424_ts(s: str) -> str:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _parse_rfc3164_ts(s: str) -> str:
    # BSD format has no year; assume current
    year = datetime.now(timezone.utc).year
    try:
        dt = datetime.strptime(f"{year} {s}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


# Pull common name=value pairs out of MSG (e.g., user=alice src_ip=1.2.3.4)
_KV_RE = re.compile(r"(\w+)=([\"']?)([^\"'\s]+)\2")


def _extract_kv(msg: str) -> Dict[str, str]:
    return {k.lower(): v for k, _, v in _KV_RE.findall(msg or "")}


def _infer_status(msg: str, kv: Dict[str, str]) -> Optional[str]:
    ml = (msg or "").lower()
    if kv.get("status"):
        return kv["status"]
    if any(t in ml for t in ("accepted password", "authentication succeeded", "login successful", " success", "opened for user")):
        return "success"
    if any(t in ml for t in ("failed password", "authentication failure", "invalid user", "login failed", "auth fail")):
        return "fail"
    return None


def _infer_action(msg: str) -> Optional[str]:
    ml = (msg or "").lower()
    if "sudo" in ml:
        return "sudo"
    if "session opened" in ml:
        return "login"
    if "session closed" in ml:
        return "logout"
    if "accepted" in ml or "authentication" in ml or "login" in ml:
        return "login"
    return None


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    m = _RFC5424_RE.match(line)
    if m:
        pri = int(m.group("pri"))
        rest = m.group("rest")
        # strip optional structured-data block [id key="val"]
        msg = rest
        if rest.startswith("["):
            depth = 0
            for i, ch in enumerate(rest):
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        msg = rest[i + 1:].strip()
                        break
        kv = _extract_kv(msg)
        return {
            "timestamp": _parse_rfc5424_ts(m.group("ts")),
            "host": m.group("host"),
            "app": m.group("app"),
            "action": _infer_action(msg),
            "severity": _pri_to_sev(pri),
            "user": kv.get("user") or kv.get("username"),
            "src_ip": kv.get("src_ip") or kv.get("ip") or kv.get("client_ip"),
            "dst_ip": kv.get("dst_ip"),
            "http_status": _infer_status(msg, kv),
            "user_agent": kv.get("user_agent") or kv.get("ua"),
            "url": kv.get("url") or kv.get("path"),
            "http_method": kv.get("method"),
            "country": kv.get("country"),
            "raw_message": msg,
            "syslog_format": "rfc5424",
        }
    m = _RFC3164_RE.match(line)
    if m:
        pri = int(m.group("pri"))
        msg = m.group("msg")
        kv = _extract_kv(msg)
        # sshd-style "Failed password for admin from 1.2.3.4 port ..."
        src_ip = kv.get("src_ip") or kv.get("ip")
        user = kv.get("user") or kv.get("username")
        if not src_ip:
            mm = re.search(r"from\s+([0-9a-fA-F:\.]+)", msg)
            if mm:
                src_ip = mm.group(1)
        if not user:
            mm = re.search(r"(?:for(?:\s+invalid\s+user)?)\s+(\S+)", msg)
            if mm:
                user = mm.group(1)
        return {
            "timestamp": _parse_rfc3164_ts(m.group("ts")),
            "host": m.group("host"),
            "app": m.group("tag"),
            "action": _infer_action(msg),
            "severity": _pri_to_sev(pri),
            "user": user,
            "src_ip": src_ip,
            "http_status": _infer_status(msg, kv),
            "user_agent": kv.get("user_agent") or kv.get("ua"),
            "url": kv.get("url"),
            "http_method": kv.get("method"),
            "country": kv.get("country"),
            "raw_message": msg,
            "syslog_format": "rfc3164",
        }
    return None


def parse_syslog(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed:
            out.append(parsed)
    return out


def looks_like_syslog(text: str) -> bool:
    head = text.lstrip()[:200]
    if not head.startswith("<"):
        return False
    return bool(_RFC5424_RE.match(head.splitlines()[0]) or _RFC3164_RE.match(head.splitlines()[0]))
