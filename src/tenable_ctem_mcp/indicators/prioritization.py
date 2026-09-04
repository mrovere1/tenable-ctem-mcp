"""Stage 3 - Prioritization (P1, P2, P3).

Official criteria: Prioritization and Scoring Methodology.

P1 was REDEFINED on 2026-09-02. The previous version was
`findings(VPR >= 9) / findings(CRITICAL)`, which is the agreement between two
score models and has no defensible direction of maturity - it would classify as
Ad Hoc a tenant where the two models simply agree.

The new definition measures what prioritisation maturity actually is: does
business context reach the decision layer? Of all the backlog the queue treats
as critical by VPR, how much sits on an asset with declared criticality.

It differs from S2, and the difference is informative: S2 measures tag coverage
over the whole inventory; P1 measures coverage weighted by where the critical
risk is. A customer with 27% of assets tagged and 100% of the critical backlog
on tagged assets TAGGED THE RIGHT ASSETS - that is more mature than the reverse.
"""

from __future__ import annotations

import json
from typing import Any

from .. import Indicator
from ..client import ApiError, call, total_of
from ..preflight import validate_filters, verdict

FINDINGS_SEARCH = "/api/v1/t1/inventory/findings/search"

INDICATORS = ("P1", "P2", "P3")

# The `exists` operator answers 400 on finding_vpr_score. The valid path is
# `>= 0.1`, which is applied and monotonic: 0.1 -> 4,462 - 7.0 -> 1,254 - 9.0 -> 586.
VPR_MINIMUM_TO_EXIST = "0.1"


def _count(filters: list[dict] | None) -> int | None:
    body = {"filters": validate_filters(filters)} if filters else {}
    return total_of(call("POST", FINDINGS_SEARCH, body=body, params={"limit": 1}))


def _literal(filters: list[dict] | None) -> str:
    return (json.dumps(filters, separators=(",", ":"), ensure_ascii=False)
            if filters else "no filter (corpus)")


def _vpr(op: str, v: str) -> dict:
    return {"property": "finding_vpr_score", "operator": op, "value": [str(v)]}


def _cvss3(op: str, v: str) -> dict:
    return {"property": "finding_cvss3_base_score", "operator": op, "value": [str(v)]}


def _state(v: str) -> dict:
    return {"property": "state", "operator": "=", "value": [v]}


def queues(cutoff: float = 7.0) -> dict[str, Any]:
    """The three queues compared: CVSS >= cutoff, VPR >= cutoff, and the overlap.

    Returned alongside P3 because they are what supports the criterion
    recommendation - and the recommendation has to be measured, not preferred.
    """
    f_cvss = [_cvss3(">=", cutoff)]
    f_vpr = [_vpr(">=", cutoff)]
    f_both = [_cvss3(">=", cutoff), _vpr(">=", cutoff)]
    n_cvss, n_vpr, n_both = _count(f_cvss), _count(f_vpr), _count(f_both)
    n_cvss_with_vpr = _count([_cvss3(">=", cutoff), _vpr(">=", VPR_MINIMUM_TO_EXIST)])
    return {
        "cutoff": cutoff,
        "cvss3_gte_cutoff": n_cvss,
        "vpr_gte_cutoff": n_vpr,
        "overlap": n_both,
        "cvss_only": (n_cvss - n_both) if None not in (n_cvss, n_both) else None,
        "vpr_only": (n_vpr - n_both) if None not in (n_vpr, n_both) else None,
        "vpr_coverage_in_high_slice_pct": (
            round(100.0 * n_cvss_with_vpr / n_cvss, 1) if n_cvss else None),
        "literal_filter": {"cvss": _literal(f_cvss), "vpr": _literal(f_vpr),
                           "overlap": _literal(f_both)},
        "note": ("The VPR coverage that matters for recommending a criterion is not "
                 "that of the whole backlog (P2), it is that of the slice a CVSS "
                 "criterion would select. Where that coverage is low, the "
                 "recommendation becomes composite: VPR primary, CVSS or severity as "
                 "fallback, plus an exception rule for CISA KEV and available "
                 "exploits."),
    }


def compute(mapping: dict, indicators: list[str] | None = None,
            customer_priority_cutoff: dict | None = None,
            p2_value: float | None = None,
            snapshot: dict | None = None) -> list[dict]:
    """P1 to P3. `indicators=None` computes all three.

    `customer_priority_cutoff` = {"metric": "vpr"|"cvss3", "value": 7.0,
    "confirmed": bool}. With no declared metric, P3 is a gap - not a number,
    because "the customer does not know which criterion they use" is stage 1
    itself.
    """
    requested = [i.upper() for i in (indicators or INDICATORS)]
    out: list[Indicator] = []
    cutoff_cfg = customer_priority_cutoff or {}

    from .discovery import discover_tenant
    snapshot = snapshot or discover_tenant()
    categories = snapshot["tags"]["categories"]

    # --- P1: business context in the critical backlog -------------------
    if "P1" in requested:
        crit_name = mapping.get("criticality_category")
        values = categories.get(crit_name) if crit_name else None
        if not values:
            out.append(Indicator.declared_gap(
                "P1",
                cause=("the mapping did not provide `criticality_category`, or the "
                       "category does not exist. Categories: "
                       + ", ".join(sorted(categories))),
                literal_filter="not executed"))
        else:
            f_denominator = [_vpr(">=", "9")]
            f_numerator = f_denominator + [
                {"property": "tag_names", "operator": "=", "value": list(values)}]
            try:
                den = _count(f_denominator)
                num = _count(f_numerator)
                if not den:
                    out.append(Indicator.declared_gap(
                        "P1", cause="no finding with VPR >= 9; denominator zero.",
                        literal_filter=_literal(f_denominator), n=0))
                else:
                    by_value = {v: _count(f_denominator + [
                        {"property": "tag_names", "operator": "=", "value": [v]}])
                        for v in values}
                    out.append(Indicator.ok(
                        "P1", round(100.0 * num / den, 1), n=den,
                        literal_filter=f"{_literal(f_numerator)} over {_literal(f_denominator)}",
                        preflight_verdict=verdict(den, num),
                        context={
                            "backlog_vpr_gte_9": den,
                            "on_asset_with_criticality": num,
                            "by_tag_value": by_value,
                            "category": crit_name,
                            "difference_from_s1_and_s2": (
                                "S2 measures tag coverage over the whole inventory; "
                                "P1 measures coverage weighted by where the critical "
                                "risk is. Low coverage in S2 with high P1 means the "
                                "customer tagged the right assets."),
                        }))
            except ApiError as e:
                out.append(Indicator.declared_gap("P1", cause=str(e),
                                                  literal_filter=_literal(f_numerator)))

    # --- P2: % of the backlog with VPR available ------------------------
    if "P2" in requested:
        f_den = [_state("ACTIVE")]
        f_num = [_state("ACTIVE"), _vpr(">=", VPR_MINIMUM_TO_EXIST)]
        try:
            den, num = _count(f_den), _count(f_num)
            if not den:
                out.append(Indicator.declared_gap(
                    "P2", cause="no ACTIVE finding; denominator zero.",
                    literal_filter=_literal(f_den), n=0))
            else:
                out.append(Indicator.ok(
                    "P2", round(100.0 * num / den, 1), n=den,
                    literal_filter=f"{_literal(f_num)} over {_literal(f_den)}",
                    preflight_verdict=verdict(den, num),
                    context={
                        "active": den, "active_with_vpr": num,
                        "operator_note": (
                            "`exists` on finding_vpr_score answers HTTP 400. The "
                            f"valid path is >= {VPR_MINIMUM_TO_EXIST}, which is "
                            "applied and monotonic."),
                    }))
        except ApiError as e:
            out.append(Indicator.declared_gap("P2", cause=str(e),
                                              literal_filter=_literal(f_num)))

    # --- P3: fitness of the prioritisation criterion --------------------
    if "P3" in requested:
        metric = str(cutoff_cfg.get("metric") or "").lower()
        cutoff_value = cutoff_cfg.get("value")
        if metric not in ("vpr", "cvss3") or cutoff_value is None:
            out.append(Indicator.declared_gap(
                "P3",
                cause=("the customer's prioritisation criterion was not declared. "
                       "P3 does not become a number without it: 'the customer does "
                       "not know which criterion they use' is the Ad Hoc stage "
                       "itself, and classifying that is the skill's job."),
                literal_filter="not executed"))
        else:
            try:
                q = queues(float(cutoff_value))
                customer_queue = (q["cvss3_gte_cutoff"] if metric == "cvss3"
                                  else q["vpr_gte_cutoff"])
                vpr_queue = q["vpr_gte_cutoff"]
                opportunity = (max(0.0, 1 - vpr_queue / customer_queue)
                               if customer_queue else None)
                out.append(Indicator.ok(
                    "P3", round(opportunity, 4) if opportunity is not None else None,
                    n=customer_queue,
                    literal_filter=(f"declared metric={metric} cutoff={cutoff_value}; "
                                    f"{q['literal_filter']['cvss']} vs "
                                    f"{q['literal_filter']['vpr']}"),
                    preflight_verdict="ok",
                    context={
                        "declared_criterion": metric,
                        "declared_cutoff": cutoff_value,
                        "confirmed_by_operator": bool(cutoff_cfg.get("confirmed")),
                        "queues": q,
                        "p2_vpr_coverage_pct": p2_value,
                        "composite": (
                            "P3 does not score on the raw delta. The VPR x CVSS delta "
                            "measures OPPORTUNITY in the environment, not customer "
                            "behaviour: promoting it to an indicator would punish a "
                            "customer for having an old Windows estate, which is not "
                            "a process choice. The stage comes from combining the "
                            "declared criterion with the measured opportunity, and it "
                            "depends on P2."),
                        "dependency": "P3 requires P2 computed. P2 in gap => P3 gap.",
                    }))
            except ApiError as e:
                out.append(Indicator.declared_gap("P3", cause=str(e),
                                                  literal_filter="queues"))

    return [i.to_dict() for i in out]
