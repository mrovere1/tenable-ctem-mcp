#!/usr/bin/env python3
"""Records into the sandbox fixture the asset counts the golden tests ask for
and the fixture does not hold yet.

Why it exists: the licensed-base denominator (see
_docs/pendencia-denominador-licenciado-2026-09-08.md) sends asset searches with
`asset_class` + `is_licensed` filters that did not exist when the fixture was
recorded on 2026-09-03. A fixture is a recorded response, so those answers
cannot be written by hand - they have to come from the laboratory tenant.

What it does, in order:

  1. Runs the whole `pytest` suite against the fixture. Every query the fixture
     already holds is answered from it. A query it does not hold is sent to the
     tenant ONLY if it is a `POST /api/v1/t1/inventory/assets/search` with
     `limit=1` - a read-only count. Anything else stays a test failure.
  2. Re-sends every asset count ALREADY in the fixture and compares the totals.
     If any differs, the tenant has moved since 2026-09-03 and mixing today's
     licensed counts with that day's corpus would make a golden test out of
     numbers that never coexisted. In that case NOTHING is written, unless the
     drift is accepted by property with --accept-drift.
  3. Only with zero drift, merges the new responses into the fixture.

Sanitisation: only `pagination.total` is read from these responses, so `data`
is recorded empty and the entry carries `_reduced` saying so. No asset id or
name enters the fixture.

Credentials come from TIO_ACCESS_KEY / TIO_SECRET_KEY / TIO_URL, like the
server. They are never printed.

Usage, from the repository root, with the LABORATORY tenant's keys exported:

    .venv/bin/python _ferramentas/record-fixture/record_missing_queries.py          # dry run
    .venv/bin/python _ferramentas/record-fixture/record_missing_queries.py --write
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from tenable_ctem_mcp import client  # noqa: E402
from tenable_ctem_mcp.client import total_of  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "sandbox_2026-09-03.json"
ASSETS_SEARCH = "/api/v1/t1/inventory/assets/search"
REAL_CALL = client.call  # captured before any test fixture patches it


def _signature(method, path, body, params):
    return json.dumps([method, path, body, params], sort_keys=True,
                      ensure_ascii=False)


def _is_count(method, path, params) -> bool:
    return (method == "POST" and path == ASSETS_SEARCH
            and (params or {}).get("limit") == 1)


def _sanitise(resp: dict) -> dict:
    return {"data": [], "pagination": resp.get("pagination", {}),
            "_reduced": ("data dropped at recording: only pagination.total "
                         "is read from an asset count")}


class Recorder:
    def __init__(self):
        self.new: dict[str, dict] = {}

    @pytest.fixture(autouse=True)
    def _live_for_missing_counts(self, request, monkeypatch):
        if "sandbox" not in request.fixturenames:
            yield
            return
        request.getfixturevalue("sandbox")
        from tenable_ctem_mcp import cadence, mttr, plugins, preflight
        from tenable_ctem_mcp.indicators import (discovery, mobilization,
                                                 prioritization, scoping,
                                                 validation)
        replay = client.call

        def call(method, path, body=None, params=None, **kw):
            sig = _signature(method, path, body, params)
            if sig in self.new:
                return self.new[sig]
            try:
                return replay(method, path, body=body, params=params, **kw)
            except AssertionError:
                if not _is_count(method, path, params):
                    raise
                self.new[sig] = _sanitise(
                    REAL_CALL(method, path, body=body, params=params))
                return self.new[sig]

        for m in (client, discovery, scoping, plugins, prioritization,
                  validation, mobilization, preflight, cadence, mttr):
            if hasattr(m, "call"):
                monkeypatch.setattr(m, "call", call)
        yield


def _drift(recorded: dict) -> list[tuple[str, int | None, int | None]]:
    out = []
    for sig, resp in recorded.items():
        method, path, body, params = json.loads(sig)
        if not _is_count(method, path, params):
            continue
        then = total_of(resp)
        now = total_of(REAL_CALL(method, path, body=body, params=params))
        if then != now:
            out.append((sig, then, now))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="merge into the fixture (only if there is no drift)")
    ap.add_argument("--accept-drift", nargs="+", default=[], metavar="PROPERTY",
                    help=("tolerate drift on counts whose filters use ONLY these "
                          "properties - a deliberate decision, to be recorded in "
                          "the pendencia document"))
    args = ap.parse_args()

    client._keys()  # fails early, without printing anything, if keys are absent
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))

    rec = Recorder()
    code = pytest.main(["-q", "-p", "no:cacheprovider", str(ROOT / "tests")],
                       plugins=[rec])

    print("\n=== New counts from the tenant ===")
    for sig, resp in rec.new.items():
        filters = json.loads(sig)[2].get("filters")
        print(f"  total={total_of(resp):>6}  {json.dumps(filters, ensure_ascii=False)}")
    if not rec.new:
        print("  none - the fixture already answers every count")

    print("\n=== Drift of the counts already recorded on 2026-09-03 ===")
    drift = _drift(recorded)
    for sig, then, now in drift:
        filters = json.loads(sig)[2].get("filters")
        print(f"  {then} -> {now}  {json.dumps(filters, ensure_ascii=False)}")
    if not drift:
        print("  none - the tenant still matches the fixture")

    # Diagnostic only, never recorded. The sandbox's WAS asset carries
    # asset_class=APPLICATION, which is not in LICENSED_CLASSES - if it is
    # licensed, the base is missing it.
    app = total_of(REAL_CALL("POST", ASSETS_SEARCH, params={"limit": 1}, body={
        "filters": [{"property": "asset_class", "operator": "=", "value": ["APPLICATION"]},
                    {"property": "is_licensed", "operator": "=", "value": ["true"]}]}))
    print(f"\n=== Diagnostic (not recorded) ===\n  asset_class=APPLICATION AND is_licensed=true: {app}")

    print(f"\npytest exit code with live counts: {code}")

    accepted = set(args.accept_drift)

    def _props(sig):
        return {f["property"] for f in (json.loads(sig)[2].get("filters") or [])}

    blocking = [d for d in drift if not accepted or not _props(d[0]) <= accepted]
    if drift and not blocking:
        print(f"\nDrift accepted on {sorted(accepted)}: those counts stay as "
              "recorded on 2026-09-03.")
    if blocking:
        print("\nNOT WRITTEN: the tenant moved since the recording. Golden numbers "
              "built from two different days would never have coexisted.")
        return 2
    if not args.write:
        print("\nDry run. Re-run with --write to merge.")
        return 0
    recorded.update(rec.new)
    FIXTURE.write_text(json.dumps(recorded, indent=1, ensure_ascii=False),
                       encoding="utf-8")
    print(f"\nWritten: {len(rec.new)} entries merged into {FIXTURE.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
