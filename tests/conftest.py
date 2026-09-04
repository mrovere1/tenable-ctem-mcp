"""Replays the recorded sandbox responses in place of the API.

Allows `pytest` with no tenant at all: no network call leaves here, and no key
is read. The fixture is `tests/fixtures/sandbox_2026-09-03.json`, sanitised
structurally.
"""

import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_2026-09-03.json"


def _signature(method, path, body, params):
    return json.dumps([method, path, body, params], sort_keys=True,
                      ensure_ascii=False)


@pytest.fixture
def sandbox(monkeypatch):
    """Replaces client.call and client.paginate with the recorded responses.

    Fails loudly when the signature does not exist: a test asking for an
    unrecorded query must break, never receive an empty result and turn into a
    wrong number.
    """
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))

    from tenable_ctem_mcp import client
    from tenable_ctem_mcp.indicators import discovery, scoping
    from tenable_ctem_mcp import plugins

    def call(method, path, body=None, params=None, **kw):
        a = _signature(method, path, body, params)
        if a not in recorded:
            raise AssertionError(f"query not recorded in the fixture: {a[:180]}")
        return recorded[a]

    def paginate(method, path, body=None, params=None, field="data",
                 page_size=200, ceiling=100_000):
        items, offset = [], 0
        while len(items) < ceiling:
            p = dict(params or {}, limit=page_size, offset=offset)
            batch = client._extract_list(call(method, path, params=p), field)
            if not batch:
                break
            items.extend(batch)
            if len(batch) < page_size:
                break
            offset += page_size
        return items

    for module in (client, discovery, scoping, plugins):
        if hasattr(module, "call"):
            monkeypatch.setattr(module, "call", call)
        if hasattr(module, "paginate"):
            monkeypatch.setattr(module, "paginate", paginate)

    client.CACHE.clear()
    yield
    client.CACHE.clear()
