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

    from tenable_ctem_mcp import cadence, client, mttr, plugins, preflight
    from tenable_ctem_mcp.indicators import (discovery, mobilization,
                                             prioritization, scoping,
                                             validation)

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

    # EVERY module that binds `call` or `paginate` at import. Leaving one out
    # is invisible while it happens to be imported after this patch - and
    # sends the test to the live tenant when another test imports it first.
    for module in (client, discovery, scoping, plugins, prioritization,
                   validation, mobilization, preflight, cadence, mttr):
        if hasattr(module, "call"):
            monkeypatch.setattr(module, "call", call)
        if hasattr(module, "paginate"):
            monkeypatch.setattr(module, "paginate", paginate)

    client.CACHE.clear()
    yield
    client.CACHE.clear()
