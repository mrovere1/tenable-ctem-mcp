"""ctem_diagnostics reports the key's role and a partial tag catalog.

Written after 2026-09-08/09, when a production key went through three roles in
two days and each one closed a different set of indicators.
"""

from tenable_ctem_mcp import server


def _fake(session, categories_total, values_total, listed=0):
    def call(method, path, body=None, params=None, **kw):
        if path == "/session":
            return session
        if path == "/tags/categories":
            return {"categories": [], "pagination": {"total": categories_total}}
        if path == "/tags/values":
            return {"values": [{"category_name": "c", "value": "v"}] * listed,
                    "pagination": {"total": values_total}}
        raise AssertionError(path)
    return call


def _run(monkeypatch, call):
    from tenable_ctem_mcp import client
    from tenable_ctem_mcp.indicators import discovery
    monkeypatch.setenv("TIO_ACCESS_KEY", "fixture-access")
    monkeypatch.setenv("TIO_SECRET_KEY", "fixture-secret")
    monkeypatch.setattr(client, "call", call)
    monkeypatch.setattr(discovery, "call", call)
    return server.ctem_diagnostics()


def test_basic_role_warns_about_d3_and_a_partial_catalog(monkeypatch):
    d = _run(monkeypatch, _fake({"permissions": 16}, 13, 47))
    assert d["verdict"] == "ok"
    assert d["api_key_role"] == {"permissions": 16, "name": "Basic"}
    text = " ".join(d["permission_warnings"])
    assert "D3" in text and "Scan Manager [40]" in text
    assert d["tag_catalog"]["complete"] is False
    assert "Can View" in text


def test_administrator_with_a_complete_catalog_has_no_warning(monkeypatch):
    d = _run(monkeypatch, _fake({"permissions": 64}, 0, 2, listed=2))
    assert d["api_key_role"]["name"] == "Administrator"
    assert d["permission_warnings"] == []
    assert d["tag_catalog"]["complete"] is True
