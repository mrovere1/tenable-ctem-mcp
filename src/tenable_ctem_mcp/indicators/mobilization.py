"""Stage 5 - Mobilization (M1, M2, M3, M4).

Official criteria: Mobilization and Metrics | Reporting.

M1 and M2 require the operator to DECLARE which scans represent the assessment
cadence. The server does not choose, and the reason is measured: in the sandbox,
the recurring scan alone gives a median of 21 days and a maximum of 140; adding
every scan with history gives a median of 1.0 and a maximum of 89, because one
of the scans runs almost daily and does not represent the assessment of the
assets in scope. Two stages of difference coming out of a choice nobody declared
is the worst kind of number.

M4 is the only indicator that does not come from the Exposure Management API,
and it stays that way after M3: `last_fixed`, `time_taken_to_fix` and
`severity_modification_type` are not among the 44 findings properties.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .. import Indicator
from ..cadence import scan_cadence
from ..client import ApiError
from ..mttr import mttr_cadence_guard, mttr_collect
from ..plugins import CENSUS_LIMIT, sample_with_details

INDICATORS = ("M1", "M2", "M3", "M4")

# M4 cutoffs, for context reading only. The STAGE is computed by the skill:
# what goes here is the number plus the fact that M4 is the LOWER of the two.
M4_CUTOFFS = {"critical": [90, 30, 15, 7], "high": [180, 60, 30, 14]}


def _median(v: list[float]) -> float | None:
    if not v:
        return None
    s = sorted(v)
    m = len(s) // 2
    return float(s[m]) if len(s) % 2 else (s[m - 1] + s[m]) / 2


def _days_since_publication(date: str, now: datetime) -> float | None:
    """`Published` comes as YYYY/MM/DD."""
    try:
        d = datetime.strptime(str(date).strip(), "%Y/%m/%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
    return (now - d).total_seconds() / 86400.0


def compute(mapping: dict | None = None, indicators: list[str] | None = None,
            sample_vpr_cutoff: float = 7.0, sample_n: int = 30,
            plugin_mode: str = "auto", census_limit: int = CENSUS_LIMIT,
            mttr_days: int = 180,
            mttr_severities: list[str] | None = None,
            mttr_max_wait_s: int = 240,
            mttr_export_uuid: str | None = None,
            batch_cutoff: int = 2, max_batch_pct: float = 40.0,
            snapshot: dict | None = None,
            now: datetime | None = None) -> list[dict]:
    """M1 to M4. `indicators=None` computes all four.

    `mapping["recurring_scans"]` is mandatory for M1 and M2.
    """
    requested = [i.upper() for i in (indicators or INDICATORS)]
    mapping = mapping or {}
    now = now or datetime.now(timezone.utc)
    out: list[Indicator] = []

    from .discovery import discover_tenant
    snapshot = snapshot or discover_tenant()

    # --- M1 and M2 come from the same cadence reading -------------------
    if {"M1", "M2"} & set(requested):
        scans = mapping.get("recurring_scans") or []
        if not scans:
            with_hist = [s["scan_id"] for s in snapshot["scans"]["scans"]
                         if (s.get("runs") or 0) > 0]
            cause = ("the mapping did not provide `recurring_scans`. The server does "
                     "not choose: in the sandbox, the recurring scan alone gives a "
                     "median of 21 days and a maximum of 140, and adding every scan "
                     "with history gives a median of 1.0 and a maximum of 89, because "
                     "one of them runs almost daily. Scans with history in this "
                     f"tenant: {with_hist}.")
            for ind in ("M1", "M2"):
                if ind in requested:
                    out.append(Indicator.declared_gap(
                        ind, cause=cause, literal_filter="not executed"))
        else:
            try:
                cad = scan_cadence(scans)
                intervals = cad["intervals_days"]
                literal = (f"scan_ids={scans}, runs collapsed into "
                           f"{cad['distinct_assessment_days']} distinct assessment "
                           f"days; intervals {intervals}")
                if "M1" in requested:
                    if not intervals:
                        out.append(Indicator.declared_gap(
                            "M1", cause=("fewer than two distinct assessment days: "
                                         "there is no interval to measure."),
                            literal_filter=literal, n=cad["distinct_assessment_days"]))
                    else:
                        out.append(Indicator.ok(
                            "M1", cad["median_days"], n=len(intervals),
                            literal_filter=literal, preflight_verdict="ok",
                            context={
                                "inverted": True,
                                "distinct_days": cad["distinct_assessment_days"],
                                "intervals_days": intervals,
                                "median_without_collapse_days": {
                                    k: v["median_without_collapse_days"]
                                    for k, v in cad["scans"].items()},
                                "why_collapse": (
                                    "A scan relaunched minutes later is the SAME "
                                    "assessment. Without the collapse the sandbox "
                                    "median is 1.42 days; with it, 21 - Standardized "
                                    "instead of Optimized, two stages apart."),
                                "gaps": cad["gaps"],
                            }))
                if "M2" in requested:
                    if not intervals:
                        out.append(Indicator.declared_gap(
                            "M2", cause="fewer than two distinct assessment days.",
                            literal_filter=literal))
                    else:
                        out.append(Indicator.ok(
                            "M2", float(cad["max_days"]), n=len(intervals),
                            literal_filter=literal, preflight_verdict="ok",
                            context={"inverted": True,
                                     "note": ("M2 does not change with the run "
                                              "collapse: the largest interval is the "
                                              "same."),
                                     "gaps": cad["gaps"]}))
            except ApiError as e:
                for ind in ("M1", "M2"):
                    if ind in requested:
                        out.append(Indicator.declared_gap(
                            ind, cause=str(e), literal_filter=f"scan_ids={scans}"))

    # --- M3: age of the available fix, from the set ---------------------
    if "M3" in requested:
        try:
            pkg = sample_with_details(n=sample_n, vpr_cutoff=sample_vpr_cutoff,
                                      mode=plugin_mode, census_limit=census_limit)
            days, without_date = [], 0
            for p in pkg["sample"]["sample"]:
                d = pkg["details"].get(p["plugin_id"])
                v = _days_since_publication(d.get("published"), now) if d else None
                if v is None:
                    without_date += 1
                else:
                    days.append(v)
            n_sel = pkg["sample"]["n"]
            if not days:
                out.append(Indicator.declared_gap(
                    "M3", cause="no plugin in the set has a publication date.",
                    literal_filter=f"set of {n_sel} plugins", n=n_sel))
            else:
                out.append(Indicator.ok(
                    "M3", round(_median(days), 1), n=len(days),
                    literal_filter=(
                        f"median of (now - Published) over {len(days)} of {n_sel} "
                        + ("critical plugins (CENSUS)" if pkg["sample"]["mode"] == "census"
                           else f"plugins of the stratified sample, "
                                f"seed {pkg['sample']['seed']}")),
                    preflight_verdict="ok",
                    context={
                        "inverted": True,
                        "mode": pkg["sample"]["mode"],
                        "population": pkg["sample"]["population"],
                        "plugins_without_date": without_date,
                        "declared_proxy": (
                            "`Published` is the publication date of the DETECTION "
                            "PLUGIN, not of the vendor's patch - a difference of "
                            "days. Label it as a proxy in the report. "
                            "`patch_publication_date` is reachable through the direct "
                            "API, but plugin_details_batch exposes five fields by a "
                            "closed rule; swapping the proxy for the real datum is "
                            "the skill's decision. See docs/limitacoes.md."),
                    }))
        except (ApiError, ValueError) as e:
            out.append(Indicator.declared_gap(
                "M3", cause=str(e), literal_filter="critical census + sample"))

    # --- M4: MTTR, with the cadence guard -------------------------------
    if "M4" in requested:
        try:
            r = mttr_collect(days=mttr_days,
                             severities=mttr_severities or ["critical", "high"],
                             max_wait_s=mttr_max_wait_s, export_uuid=mttr_export_uuid,
                             batch_cutoff=batch_cutoff)
            if r.get("status") == "pending":
                out.append(Indicator.declared_gap(
                    "M4",
                    cause=(f"export still running ({r.get('job_status')}). This is "
                           "recoverable: call again passing "
                           f"mttr_export_uuid='{r['export_uuid']}'. Opening another "
                           "export would answer 409."),
                    literal_filter=f"POST /vulns/export, {mttr_days} days"))
            else:
                mttr_cad = r["scan_cadence"]
                scan_dates = None
                scans = (mapping or {}).get("recurring_scans")
                if scans:
                    try:
                        scan_dates = scan_cadence(scans)["dates"]
                    except ApiError:
                        scan_dates = None
                guard = mttr_cadence_guard(mttr_cad["windows"], scan_dates,
                                           max_batch_pct)
                sev = r["mttr_by_severity"]
                p50c = (sev.get("critical") or {}).get("mttr_days_p50")
                p50h = (sev.get("high") or {}).get("mttr_days_p50")
                context = {
                    "inverted": True,
                    "p50_critical": p50c, "p50_high": p50h,
                    # Per-severity evidence. The skill requires `n`, the origin of
                    # the datum (native vs derived) and the reopened count in order
                    # to declare the method in the report; without it the skill
                    # would demand a methodological conclusion the server did not
                    # deliver.
                    "by_severity": sev,
                    "cutoffs": M4_CUTOFFS,
                    "how_to_score": (
                        "M4 is the LOWER of the two stages - mature mobilisation "
                        "closes both severities, it does not offset one with the "
                        "other. The stage is computed by the skill; what goes here "
                        "are the two p50s."),
                    "cadence_guard": guard,
                    "percentile_method": r["percentile_method"],
                    "states_included": r["states_included_in_mttr"],
                    "modified_severity_other_than_none":
                        r["modified_severity_other_than_none"],
                    "export_uuid": r["export_uuid"],
                }
                if guard["verdict"] == "gap":
                    out.append(Indicator.declared_gap(
                        "M4",
                        cause=("the MTTR here measures assessment cadence, not time "
                               "to fix: " + "; ".join(guard["reasons"]) +
                               ". With cadence dominating, M4 would measure the same "
                               "thing as M1 and M2 - counting cadence twice while "
                               "calling remediation maturity what is in fact "
                               "assessment maturity."),
                        literal_filter=(f"POST /vulns/export, {mttr_days} days, "
                                        f"batch cutoff {batch_cutoff}"),
                        n=mttr_cad["findings_with_mttr"]))
                    out[-1].context = context
                else:
                    out.append(Indicator.ok(
                        "M4", {"p50_critical": p50c, "p50_high": p50h},
                        n=mttr_cad["findings_with_mttr"],
                        literal_filter=(f"POST /vulns/export, {mttr_days} days, "
                                        f"batch cutoff {batch_cutoff}"),
                        preflight_verdict="ok", context=context))
        except (ApiError, ValueError) as e:
            out.append(Indicator.declared_gap(
                "M4", cause=str(e), literal_filter="POST /vulns/export"))

    return [i.to_dict() for i in out]
