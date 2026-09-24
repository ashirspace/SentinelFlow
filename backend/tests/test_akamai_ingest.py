import pytest

from akamai_ingest import parse_akamai_payload, is_akamai_ip, AKAMAI_INGEST_CIDRS


def test_parse_akamai_datastream_json_record():
    raw = b"""{
      "version": "1",
      "streamId": "12345",
      "reqId": "abc123",
      "reqTimeSec": "1573840000",
      "cliIP": "128.147.28.68",
      "statusCode": "206",
      "proto": "HTTPS",
      "reqHost": "www.example.com",
      "reqMethod": "GET",
      "reqPath": "/login",
      "queryStr": "a=1",
      "reqPort": "443",
      "UA": "curl/8.0",
      "country": "IN"
    }"""

    [event] = parse_akamai_payload(raw)

    assert event["timestamp"] == 1573840000.0
    assert event["src_ip"] == "128.147.28.68"
    assert event["host"] == "www.example.com"
    assert event["http_method"] == "GET"
    assert event["url"] == "/login?a=1"
    assert event["http_status"] == "206"
    assert event["protocol"] == "HTTPS"
    assert event["dst_port"] == "443"
    assert event["user_agent"] == "curl/8.0"
    assert event["country"] == "IN"
    assert event["app"] == "web"
    assert event["action"] == "akamai_edge_request"
    assert event["correlation_id"] == "abc123"


def test_parse_akamai_siem_security_record():
    raw = b"""{
      "type": "akamai_siem",
      "attackData": {
        "clientIP": "192.0.2.82",
        "ruleActions": "deny",
        "ruleMessages": "SQL injection detected"
      },
      "httpMessage": {
        "requestId": "r-1",
        "start": "1517337032",
        "protocol": "HTTP/1.1",
        "method": "POST",
        "host": "www.example.com",
        "port": "80",
        "path": "/search?q='",
        "status": "403"
      },
      "geo": { "country": "US" }
    }"""

    [event] = parse_akamai_payload(raw)

    assert event["timestamp"] == 1517337032.0
    assert event["src_ip"] == "192.0.2.82"
    assert event["http_method"] == "POST"
    assert event["http_status"] == "403"
    assert event["severity"] == "Likely malicious"
    assert event["action"] == "akamai_deny"


def test_parse_akamai_ndjson():
    raw = b'{"cliIP":"1.1.1.1","reqPath":"/a"}\n{"cliIP":"2.2.2.2","reqPath":"/b"}'

    events = parse_akamai_payload(raw)

    assert [event["src_ip"] for event in events] == ["1.1.1.1", "2.2.2.2"]


def test_parse_akamai_rejects_invalid_payload():
    with pytest.raises(ValueError):
        parse_akamai_payload(b"not json")


def test_akamai_ip_validation():
    # Test valid sample IPs within the configured CIDR blocks
    assert is_akamai_ip("23.64.10.5") is True
    assert is_akamai_ip("69.192.1.1") is True
    assert is_akamai_ip("72.246.100.2") is True
    assert is_akamai_ip("88.221.50.1") is True
    assert is_akamai_ip("92.122.3.4") is True
    assert is_akamai_ip("104.64.0.1") is True
    assert is_akamai_ip("118.214.20.30") is True
    assert is_akamai_ip("172.224.5.6") is True
    assert is_akamai_ip("184.84.12.34") is True

    # Test non-Akamai IPs
    assert is_akamai_ip("8.8.8.8") is False
    assert is_akamai_ip("1.1.1.1") is False
    assert is_akamai_ip("192.168.1.1") is False
    assert is_akamai_ip("") is False
    assert is_akamai_ip(None) is False
