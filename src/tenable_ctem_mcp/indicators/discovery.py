"""Stage 2 - Discovery (D1, D2, D3, D4) and the Step 0 tenant discovery.

`discover_tenant()` lives here, rather than in a module of its own, because it
collects exactly the raw material D1, D2 and D3 consume: the scans with history
(D1), the exposure_classes present (D2) and the agents against the DEVICE assets
(D3). One module, one shared cache, and the query does not go out twice.

It replaces the ~10 calls of Phase A of the skill's Step 0 with a single one.

Endpoints, confirmed on developer.tenable.com on 2026-09-03:
  POST /api/v1/t1/inventory/assets/search   (Exposure Management, BETA)
  GET  /tags/categories                     (Vulnerability Management)
  GET  /tags/values                         (Vulnerability Management)
  GET  /scans                               (Vulnerability Management)
  GET  /scans/{scan_id}/history             (Vulnerability Management)
  GET  /scanners/null/agents                (Vulnerability Management)

The Exposure Management endpoints are in BETA and the response structure may
change - which is why the reading is defensive and the shape is never presumed.
"""

from __future__ import annotations

import json
from typing import Any

from datetime import datetime, timezone

from .. import Indicator, now_utc
from ..client import CACHE, ApiError, call, paginate, total_of
from ..plugins import CENSUS_LIMIT, sample_with_details, rate

# Possible values of exposure_classes. CAUTION: asset_class is NOT
# exposure_classes. In the sandbox there are assets with asset_class = IDENTITY,
# but exposure_classes = IDENTITY returns zero - the identity assets are in the
# inventory without carrying Identity Exposure findings. D2 uses exposure_classes.
EXPOSURE_CLASSES = ("VM", "WAS", "CLOUD", "IDENTITY", "OT", "AI", "CODE")

ASSET_CLASSES = ("DEVICE", "IDENTITY", "ACCOUNT", "GROUP", "WEB_APPLICATION",
                 "CLOUD_RESOURCE")

ASSETS_SEARCH = "/api/v1/t1/inventory/assets/search"


def _count_assets(filters: list[dict] | None = None) -> int | None:
    """Counts assets reading only the `total` field. limit=1 on purpose: the
    preflight is cheap because only the total matters."""
    body: dict[str, Any] = {}
    if filters:
        body["filters"] = filters
    resp = call("POST", ASSETS_SEARCH, body=body, params={"limit": 1, "offset": 0})
    return total_of(resp)


def _literal_filter(filters: list[dict] | None) -> str:
    return json.dumps(filters, separators=(",", ":"), ensure_ascii=False) if filters else "no filter"


def _categories_and_values() -> dict[str, Any]:
    cats = call("GET", "/tags/categories").get("categories", []) or []
    vals = call("GET", "/tags/values").get("values", []) or []
    by_category: dict[str, list[str]] = {}
    for c in cats:
        name = c.get("name")
        if name:
            by_category.setdefault(name, [])
    for v in vals:
        name = v.get("category_name")
        if name is None:
            continue
        by_category.setdefault(name, []).append(v.get("value"))
    return {
        "count": len(by_category),
        "categories": {k: sorted(x for x in v if x) for k, v in sorted(by_category.items())},
    }


def _scans_with_history() -> dict[str, Any]:
    """Lists the scans and, for each, how many runs it has.

    It does not collapse runs here: collapsing into distinct assessment days is
    `scan_cadence`'s job (milestone M4), and it is what separates a median of
    1.42 days from a median of 21 days in M1.
    """
    scans = call("GET", "/scans").get("scans") or []
    summary = []
    for s in scans:
        sid = s.get("id")
        if sid is None:
            continue
        item = {
            "scan_id": sid,
            "name": s.get("name"),
            "status": s.get("status"),
            "last_modification_epoch": s.get("last_modification_date"),
            "runs": None,
        }
        try:
            # Paginated. Without this, a recurring scan with many runs comes
            # back truncated at the page size - a wrong count wearing the
            # appearance of a right one, which is exactly what this project
            # forbids. Measured in the sandbox: scan 13 has more than 200 runs.
            runs = paginate("GET", f"/scans/{sid}/history", field="history")
            item["runs"] = len(runs)
            item["runs_completed"] = sum(1 for r in runs if r.get("status") == "completed")
        except ApiError as e:
            # A per-scan failure does not contaminate the rest: it becomes a
            # named cause on the item.
            item["runs"] = None
            item["cause"] = str(e)
        summary.append(item)
    with_history = [s for s in summary if (s.get("runs") or 0) > 0]
    return {"total_scans": len(summary), "with_history": len(with_history),
            "scans": summary}


def _agents() -> dict[str, Any]:
    ags = paginate("GET", "/scanners/null/agents", field="agents")
    active = [a for a in ags if str(a.get("status", "")).lower() == "on"]
    return {"total": len(ags), "active": len(active),
            "by_status": _count_by(ags, "status")}


def _count_by(items: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        v = str(i.get(key, "unknown"))
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def discover_tenant(use_cache: bool = True) -> dict[str, Any]:
    """Snapshot of the tenant in one call. Result cached with a short TTL.

    The cache is mandatory (CLAUDE.md): several indicators consult this
    snapshot, and without a cache the same query goes out four times.
    """
    key = "ctem_discover_tenant/v1"
    if use_cache:
        found, value = CACHE.get(key)
        if found:
            return dict(value, served_from_cache=True)

    total_assets = _count_assets()

    by_asset_class = {}
    for cls in ASSET_CLASSES:
        f = [{"property": "asset_class", "operator": "=", "value": [cls]}]
        n = _count_assets(f)
        if n:
            by_asset_class[cls] = n

    # One query per class, with limit=1, reading only the total. It is the way
    # to know which surfaces actually exist - there is no endpoint listing that.
    exposure = {}
    for cls in EXPOSURE_CLASSES:
        f = [{"property": "exposure_classes", "operator": "=", "value": [cls]}]
        exposure[cls] = _count_assets(f)

    snapshot = {
        "tags": _categories_and_values(),
        "assets": {
            "total": total_assets,
            "by_asset_class": by_asset_class,
            "literal_filter_total": _literal_filter(None),
        },
        "exposure_classes": exposure,
        "scans": _scans_with_history(),
        "agents": _agents(),
        "collected_at_utc": now_utc(),
        "served_from_cache": False,
        "warning": ("The Exposure Management endpoints are in BETA in Tenable's "
                    "documentation; the response structure may change."),
    }
    CACHE.set(key, snapshot)
    return snapshot


# ----------------------------------------------------------------------------
# Indicators D1 to D4
# ----------------------------------------------------------------------------

INDICATORS = ("D1", "D2", "D3", "D4")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _latest_run(snapshot: dict) -> tuple[int | None, int]:
    """Returns (epoch of the most recent run, number of scans consulted).

    Reads the history of every scan that has one. `time_start` is the real start
    of the run - the correct source, because a date filter on findings is
    ignored and the workbenches `age` parameter is recency, not age.
    """
    latest = None
    consulted = 0
    for s in snapshot["scans"]["scans"]:
        if not (s.get("runs") or 0):
            continue
        consulted += 1
        try:
            hist = paginate("GET", f"/scans/{s['scan_id']}/history", field="history")
        except ApiError:
            continue
        for r in hist:
            ts = r.get("time_start")
            if isinstance(ts, int) and (latest is None or ts > latest):
                latest = ts
    return latest, consulted


def compute(indicators: list[str] | None = None,
            licensed_surfaces: list[str] | None = None,
            sample_vpr_cutoff: float = 7.0,
            sample_n: int = 30,
            weight_by: str = "by_detection",
            plugin_mode: str = "auto",
            census_limit: int = CENSUS_LIMIT,
            snapshot: dict | None = None,
            now: datetime | None = None) -> list[dict]:
    """D1 to D4. `indicators=None` computes all four.

    `now` exists so the golden test can freeze the clock: D1 is a difference
    against the instant of collection, so without a fixed clock no regression
    test is possible.
    """
    requested = [i.upper() for i in (indicators or INDICATORS)]
    licensed = [s.upper() for s in (licensed_surfaces or ["VM"])]
    now = now or _now()
    snapshot = snapshot or discover_tenant()
    out: list[Indicator] = []

    # --- D1: days since the last assessment (inverted) ------------------
    if "D1" in requested:
        ts, consulted = _latest_run(snapshot)
        if ts is None:
            out.append(Indicator.declared_gap(
                "D1", cause="no scan with execution history in the tenant.",
                literal_filter=f"scan_history of {consulted} scans"))
        else:
            start = datetime.fromtimestamp(ts, timezone.utc)
            days = round((now - start).total_seconds() / 86400.0, 2)
            out.append(Indicator.ok(
                "D1", days, n=consulted,
                literal_filter=(f"scan_history of {consulted} scans with history; "
                                f"most recent run at {start.strftime('%Y-%m-%dT%H:%M:%SZ')}"),
                preflight_verdict="ok",
                context={"most_recent_run_utc": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "inverted": True}))

    # --- D2: coverage of the licensed surfaces --------------------------
    if "D2" in requested:
        present = [c for c, n in snapshot["exposure_classes"].items() if (n or 0) > 0]
        covered = [c for c in licensed if c in present]
        pct = round(100.0 * len(covered) / len(licensed), 1) if licensed else None
        unlicensed = [c for c in present if c not in licensed]
        out.append(Indicator.ok(
            "D2", pct, n=len(licensed),
            literal_filter=("exposure_classes with total > 0, one query per class "
                            f"with limit=1; licensed={licensed}"),
            preflight_verdict="ok",
            context={"present": present, "covered": covered,
                     "licensed": licensed,
                     "present_not_licensed": unlicensed,
                     "note": ("asset_class is not exposure_classes: a tenant may "
                              "have assets with asset_class=IDENTITY and "
                              "exposure_classes=IDENTITY at zero.")}))

    # --- D3: % of DEVICE assets with an agent ---------------------------
    if "D3" in requested:
        devices = snapshot["assets"]["by_asset_class"].get("DEVICE", 0)
        active = snapshot["agents"]["active"]
        if not devices:
            out.append(Indicator.declared_gap(
                "D3", cause="no asset with asset_class=DEVICE; denominator zero.",
                literal_filter="asset_class=DEVICE"))
        else:
            out.append(Indicator.ok(
                "D3", round(100.0 * active / devices, 1), n=devices,
                literal_filter=("agents with status=on over "
                                "[{\"property\":\"asset_class\",\"operator\":\"=\","
                                "\"value\":[\"DEVICE\"]}]"),
                preflight_verdict="ok",
                context={"active_agents": active, "devices": devices}))

    # --- D4: % of the set detected by a local plugin --------------------
    if "D4" in requested:
        try:
            pkg = sample_with_details(n=sample_n, vpr_cutoff=sample_vpr_cutoff,
                                      mode=plugin_mode, census_limit=census_limit)
            census, sel, details = pkg["census"], pkg["sample"], pkg["details"]
            r = rate(sel, details,
                     lambda d: str(d.get("scan_type", "")).lower() == "local",
                     base=weight_by)
            out.append(Indicator.ok(
                "D4", round(100.0 * r["weighted_rate"], 1), n=r["n"],
                literal_filter=(
                    f"CENSUS of the {sel['n']} critical plugins"
                    if sel["mode"] == "census" else
                    f"stratified sample of {sel['n']} over "
                    f"{census['distinct_plugins']} critical plugins, proportional "
                    f"allocation, VPR cutoff {sample_vpr_cutoff}, "
                    f"seed {sel['seed']}"),
                preflight_verdict="ok",
                context={
                    "mode": sel["mode"], "population": sel["population"],
                    "set_note": sel["note"],
                    "strata": sel["strata"], "by_stratum": r["by_stratum"],
                    "weight_base": r["weight_base"],
                    "ci95_whole_sample": r["ci95_whole_sample"],
                    "stratum_b_floor_triggered": sel["stratum_b_floor_triggered"],
                    "plugins_without_detail": pkg["gaps"],
                    "declared_proxy": ("a plugin of type `local` only returns a "
                                       "result with a valid credential or an agent. "
                                       "It is not a reading of credential status. "
                                       "The workbenches `authenticated` parameter "
                                       "is ignored."),
                }))
        except (ApiError, ValueError) as e:
            out.append(Indicator.declared_gap(
                "D4", cause=str(e), literal_filter="critical census + sample"))

    return [i.to_dict() for i in out]
