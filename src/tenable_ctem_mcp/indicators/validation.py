"""Stage 4 - Validation (V1, V2, V3, V4).

Official criterion: Risk Detection.

V1 is INFORMATIONAL. A high percentage of available exploits may indicate a bad
backlog or merely an environment built on a popular stack, which concentrates
exploit research. Without a customer premise, turning it into a stage would be
interpretation.

V2 is the strongest indicator of the set and the only one with a citable
external anchor: the 14- and 30-day cutoffs derive from the remediation tiers of
CISA BOD 26-04. The report states that the directive applies to US federal
agencies and that here it is a recognised deadline reference, not a regulatory
obligation of the customer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .. import Indicator
from ..client import ApiError, call, total_of
from ..plugins import CENSUS_LIMIT, sample_with_details, rate, wilson
from ..preflight import validate_filters, verdict

FINDINGS_SEARCH = "/api/v1/t1/inventory/findings/search"

INDICATORS = ("V1", "V2", "V3", "V4")

# Text search is the valid path: `unsupported_by_vendor` exists in the API but
# is not reachable, and `query_text`/`finding_name contains` is an applied filter.
EOL_TERMS = ("Unsupported Version Detection", "SEoL")


def _count(filters: list[dict] | None) -> int | None:
    body = {"filters": validate_filters(filters)} if filters else {}
    return total_of(call("POST", FINDINGS_SEARCH, body=body, params={"limit": 1}))


def _search(filters: list[dict], limit: int = 500) -> list[dict]:
    body = {"filters": validate_filters(filters)}
    resp = call("POST", FINDINGS_SEARCH, body=body, params={"limit": limit})
    d = resp.get("data")
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        for k in ("items", "findings", "results"):
            if isinstance(d.get(k), list):
                return d[k]
    return []


def _literal(filters: list[dict] | None) -> str:
    return (json.dumps(filters, separators=(",", ":"), ensure_ascii=False)
            if filters else "no filter (corpus)")


def _state(v: str) -> dict:
    return {"property": "state", "operator": "=", "value": [v]}


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    v = sorted(values)
    mid = len(v) // 2
    return v[mid] if len(v) % 2 else (v[mid - 1] + v[mid]) / 2


def _days_since(kev_date: str, now: datetime) -> float | None:
    """CISA-KNOWN-EXPLOITED dates come as YYYY/MM/DD."""
    try:
        d = datetime.strptime(kev_date.strip(), "%Y/%m/%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
    return (now - d).total_seconds() / 86400.0


def compute(mapping: dict | None = None, indicators: list[str] | None = None,
            sample_vpr_cutoff: float = 7.0, sample_n: int = 30,
            weight_by: str = "by_detection",
            plugin_mode: str = "auto",
            census_limit: int = CENSUS_LIMIT,
            snapshot: dict | None = None,
            now: datetime | None = None) -> list[dict]:
    """V1 to V4. `indicators=None` computes all four.

    `now` exists so the golden test can freeze the clock: V2 is a difference
    against the instant of collection and grows on its own every day.

    `weight_by` is `by_detection` (the skill's default) or `by_plugin`. The
    choice changes the number: on the sandbox's n=20 sample, V1 gives 59.3% by
    detection and 54.6% by plugin. That is why the base is declared in the
    context - a weighted rate without a declared base is not verifiable.
    """
    requested = [i.upper() for i in (indicators or INDICATORS)]
    now = now or datetime.now(timezone.utc)
    out: list[Indicator] = []

    from .discovery import discover_tenant
    snapshot = snapshot or discover_tenant()

    # --- V1 and V2 come from the same set -------------------------------
    if {"V1", "V2"} & set(requested):
        try:
            pkg = sample_with_details(n=sample_n, vpr_cutoff=sample_vpr_cutoff,
                                      mode=plugin_mode, census_limit=census_limit)
            sel, details = pkg["sample"], pkg["details"]
        except (ApiError, ValueError) as e:
            for ind in ("V1", "V2"):
                if ind in requested:
                    out.append(Indicator.declared_gap(
                        ind, cause=str(e), literal_filter="critical census + sample"))
            sel = None

        if sel is not None and "V1" in requested:
            r = rate(sel, details, lambda d: bool(d.get("exploit_available")),
                     base=weight_by)
            out.append(Indicator.ok(
                "V1", round(100.0 * r["weighted_rate"], 1), n=r["n"],
                literal_filter=(
                    f"CENSUS of the {sel['n']} critical plugins"
                    if sel["mode"] == "census" else
                    f"stratified sample of {sel['n']} out of {sel['population']}, "
                    f"proportional allocation, VPR cutoff {sample_vpr_cutoff}, "
                    f"seed {sel['seed']}"),
                preflight_verdict="ok",
                context={
                    "informational": True,
                    "mode": sel["mode"], "population": sel["population"],
                    "set_note": sel["note"],
                    "weight_base": r["weight_base"],
                    "by_stratum": r["by_stratum"],
                    "ci95_whole_sample": r["ci95_whole_sample"],
                    "why_informational": (
                        "A high percentage of available exploits may indicate a bad "
                        "backlog or merely an environment on a popular stack, which "
                        "concentrates exploit research. Without a customer premise, "
                        "turning it into a stage would be interpretation."),
                }))

        if sel is not None and "V2" in requested:
            days = []
            with_kev = 0
            for p in sel["sample"]:
                d = details.get(p["plugin_id"])
                if not d or not d.get("cisa_known_exploited"):
                    continue
                with_kev += 1
                values = [x for x in (_days_since(k, now)
                                      for k in d["cisa_known_exploited"]) if x is not None]
                if values:
                    days.append(max(values))   # min(date) => max(days)
            n_sel = sel["n"]
            if not days:
                out.append(Indicator.declared_gap(
                    "V2", cause=("no plugin in the set has a CISA-KNOWN-EXPLOITED "
                                 "date."),
                    literal_filter=f"{sel['mode']} of {n_sel} plugins", n=n_sel))
            else:
                out.append(Indicator.ok(
                    "V2", round(_median(days), 1), n=len(days),
                    literal_filter=(f"median of (now - earliest CISA-KNOWN-EXPLOITED "
                                    f"date) over {len(days)} of {n_sel} plugins "
                                    f"({sel['mode']})"),
                    preflight_verdict="ok",
                    context={
                        "mode": sel["mode"],
                        "plugins_with_kev": with_kev,
                        "plugins_in_set": n_sel,
                        "proportion_with_kev": round(with_kev / n_sel, 3) if n_sel else None,
                        "ci95_proportion_with_kev": (None if sel["mode"] == "census"
                                                     else wilson(with_kev, n_sel)),
                        "inverted": True,
                        "threshold_origin": (
                            "The 14- and 30-day cutoffs derive from the remediation "
                            "tiers of CISA BOD 26-04. The directive applies to US "
                            "federal agencies; here it is a recognised deadline "
                            "reference, not a regulatory obligation of the customer."),
                    }))

    # --- V3: recurrence rate --------------------------------------------
    if "V3" in requested:
        f_r, f_f = [_state("RESURFACED")], [_state("FIXED")]
        try:
            n_r, n_f = _count(f_r), _count(f_f)
            den = (n_r or 0) + (n_f or 0)
            if not den:
                out.append(Indicator.declared_gap(
                    "V3", cause="no RESURFACED nor FIXED finding; denominator zero.",
                    literal_filter=f"{_literal(f_r)} and {_literal(f_f)}", n=0))
            else:
                out.append(Indicator.ok(
                    "V3", round(100.0 * n_r / den, 1), n=den,
                    literal_filter=f"{_literal(f_r)} over ({_literal(f_r)} + {_literal(f_f)})",
                    preflight_verdict="ok",
                    context={
                        "resurfaced": n_r, "fixed": n_f, "inverted": True,
                        "unit": ("PERCENTAGE, like every rate cutoff in the skill. "
                                 "The cutoffs are [25, 15, 8, 3], not [0.25, 0.15, "
                                 "0.08, 0.03] - comparing 18.0 against 0.25 drops "
                                 "V3 into the worst bucket every time."),
                        "reading": ("`state` is the record's state, not a "
                                    "computation. High recurrence indicates a fix "
                                    "that does not hold: a reverted patch, an "
                                    "uncorrected base image, reprovisioning from a "
                                    "vulnerable template."),
                    }))
        except ApiError as e:
            out.append(Indicator.declared_gap("V3", cause=str(e),
                                              literal_filter=_literal(f_r)))

    # --- V4: % of DEVICE with out-of-support software -------------------
    if "V4" in requested:
        devices = snapshot["assets"]["by_asset_class"].get("DEVICE", 0)
        if not devices:
            out.append(Indicator.declared_gap(
                "V4", cause="no DEVICE asset; denominator zero.",
                literal_filter="asset_class=DEVICE", n=0))
        else:
            f_device = {"property": "asset_class", "operator": "=", "value": ["DEVICE"]}
            eol_assets: set[str] = set()
            by_term: dict[str, int] = {}
            used = []
            try:
                for term in EOL_TERMS:
                    f = [{"property": "finding_name", "operator": "contains",
                          "value": [term]}, f_device]
                    used.append(_literal(f))
                    items = _search(f)
                    ids = {i.get("asset_id") for i in items if i.get("asset_id")}
                    by_term[term] = len(ids)
                    eol_assets |= ids
                out.append(Indicator.ok(
                    "V4", round(100.0 * len(eol_assets) / devices, 1), n=devices,
                    literal_filter=" UNION ".join(used),
                    preflight_verdict=verdict(devices, len(eol_assets)),
                    context={
                        "devices_with_eol": len(eol_assets), "devices": devices,
                        "distinct_assets_per_term": by_term,
                        "inverted": True,
                        "denominator": ("DEVICE, not the total of assets: the "
                                        "inventory includes IDENTITY, ACCOUNT and "
                                        "GROUP, which have no software installed. In "
                                        "the sandbox the difference is two stages - "
                                        "7/30 gives 23%, 7/8 gives 87.5%."),
                        "path": ("`unsupported_by_vendor` exists in the API but is "
                                 "not reachable. A text search on finding_name is a "
                                 "provably applied filter."),
                    }))
            except ApiError as e:
                out.append(Indicator.declared_gap(
                    "V4", cause=str(e), literal_filter=" UNION ".join(used)))

    return [i.to_dict() for i in out]
