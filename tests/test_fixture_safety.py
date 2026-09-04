"""Fails if any fixture looks like it contains a key, a private IP or a hostname.

Cheap to write, and it prevents the classic accident. It runs even with an empty
directory - and it is born together with the first fixture, not after it.
"""

import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

KEY_PATTERN = re.compile(r"\b[A-Fa-f0-9]{32,}\b")

# NO left \b, and from 16 characters up: the first version of this test let
# `"schedule_uuid": "template-01df1e4e-be08-...-fc947e0b74a80cbae7b9..."` through,
# because the identifier has a prefix and the \b never matched. An opaque tenant
# identifier does not need UUID shape to be tenant data.
LONG_HEX_PATTERN = re.compile(r"[0-9a-f]{16,}", re.I)

# Any IPv4 that is not from the RFC 5737 documentation ranges. The previous
# version only looked at private ranges and let 31.0.0.148 and 32.0.0.101
# through, which are real sandbox asset addresses.
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOCUMENTATION_IP = re.compile(r"^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$")
PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
HOSTNAME_PATTERN = re.compile(
    r"\b[\w-]+\.(?:local|corp|internal|lan|tenablesecurity\.com)\b", re.I
)
UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
)

# UUIDs sanitised on purpose: all zeros, or the declared prefix.
ALLOWED_UUID = re.compile(r"^(0{8}-0{4}-0{4}-0{4}-[0-9a-f]{12}|fixture-.*)$", re.I)


def _files():
    if not FIXTURES.is_dir():
        return []
    return sorted(p for p in FIXTURES.rglob("*") if p.is_file())


@pytest.mark.parametrize("path", _files(), ids=lambda p: p.name)
def test_fixture_contains_no_secret_nor_tenant_data(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = path.relative_to(FIXTURES)

    found = KEY_PATTERN.search(text)
    assert found is None, (
        f"{rel}: this looks like an API key ({found.group()[:8]}...). "
        "A fixture never carries a credential."
    )

    for ip in IP_PATTERN.findall(text):
        if all(0 <= int(o) <= 255 for o in ip.split(".")):
            assert DOCUMENTATION_IP.match(ip), (
                f"{rel}: real IP address ({ip}). Only the RFC 5737 documentation "
                "ranges are accepted."
            )

    for h in LONG_HEX_PATTERN.findall(text):
        assert set(h) == {"0"}, (
            f"{rel}: opaque tenant identifier ({h[:12]}...). Zero it before committing."
        )

    found = HOSTNAME_PATTERN.search(text)
    assert found is None, f"{rel}: tenant hostname ({found.group()})."

    for uuid in UUID_PATTERN.findall(text):
        assert ALLOWED_UUID.match(uuid), (
            f"{rel}: a UUID that looks real ({uuid}). Sanitise it before committing."
        )


def test_the_patterns_actually_catch_things():
    """A guard for the guard itself: a broken regex would pass everything in
    silence, and the test would stay green while protecting nothing."""
    assert KEY_PATTERN.search("key=0123456789abcdef0123456789abcdef")
    assert PRIVATE_IP_PATTERN.search("host 192.168.1.10 up")
    assert not DOCUMENTATION_IP.match("31.0.0.148")     # the one that got through
    assert DOCUMENTATION_IP.match("203.0.113.1")
    # the exact case that escaped: UUID shape with a prefix and a tail
    assert LONG_HEX_PATTERN.search("template-01df1e4e-be08-f5f8-8a71-fc947e0b74a80cbae7b9b9a52612")
    assert HOSTNAME_PATTERN.search("srv-01.corp responded")
    assert UUID_PATTERN.search("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    assert not ALLOWED_UUID.match("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    assert ALLOWED_UUID.match("00000000-0000-0000-0000-000000000001")
