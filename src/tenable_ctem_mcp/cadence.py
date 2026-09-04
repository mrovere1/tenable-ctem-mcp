"""Collapsing scan runs into DISTINCT ASSESSMENT DAYS.

This module exists because of a wrong number that went unnoticed.

The original M1 formula was "median interval between consecutive `completed`
runs". A scan relaunched minutes later is the SAME assessment, not a new cadence
cycle. In the sandbox, the 12 runs of the recurring scan include four same-day
pairs, and the median of the 11 raw intervals came out at 1.42 DAYS - a number
with no meaning for a tenant that assessed on 9 days across 12 months.

Collapsed into distinct days: intervals of 140, 40, 2, 89, 1, 1, 85 and 1 days,
median 21 DAYS. Standardized instead of Optimized - two stages apart.

The collapse happens ON THE SERVER, always. Never on the client: it was exactly
because it lived on the client that the error survived a whole execution.

M2 (largest gap) does NOT change with the collapse - the largest interval is the
same either way.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .client import ApiError, paginate


def _distinct_days(runs: list[dict], completed_only: bool = True) -> list[str]:
    """Distinct UTC dates on which an assessment happened, in order."""
    days = set()
    for r in runs:
        if completed_only and r.get("status") != "completed":
            continue
        ts = r.get("time_start")
        if isinstance(ts, int) and ts > 0:
            days.add(datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d"))
    return sorted(days)


def _intervals(days: list[str]) -> list[int]:
    ds = [datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc) for d in days]
    return [int((ds[i + 1] - ds[i]).total_seconds() // 86400) for i in range(len(ds) - 1)]


def _median(v: list[float]) -> float | None:
    if not v:
        return None
    s = sorted(v)
    m = len(s) // 2
    return float(s[m]) if len(s) % 2 else (s[m - 1] + s[m]) / 2


def scan_cadence(scan_ids: list[str | int], collapse_same_day_runs: bool = True,
                 completed_only: bool = True) -> dict[str, Any]:
    """Collapses runs into distinct days and returns intervals, median and max.

    `collapse_same_day_runs=False` exists so the report can SHOW the difference,
    never to be the default. Turning it off requires declaring it - the output
    carries `median_without_collapse` alongside, always, so the contrast stays
    visible.
    """
    per_scan: dict[str, Any] = {}
    all_days: set = set()
    gaps: list[dict] = []

    for sid in scan_ids:
        try:
            runs = paginate("GET", f"/scans/{sid}/history", field="history")
        except ApiError as e:
            gaps.append({"scan_id": sid, "cause": str(e)[:200]})
            continue

        used = [r for r in runs
                if not completed_only or r.get("status") == "completed"]
        days = _distinct_days(runs, completed_only)
        all_days |= set(days)

        # Raw intervals: between consecutive runs, without collapsing. This is
        # what produces the meaningless median, and it travels along for contrast.
        marks = sorted(r["time_start"] for r in used
                       if isinstance(r.get("time_start"), int))
        raw = [round((marks[i + 1] - marks[i]) / 86400.0, 2)
               for i in range(len(marks) - 1)]
        collapsed = _intervals(days)

        per_scan[str(sid)] = {
            "runs": len(runs),
            "runs_considered": len(used),
            "distinct_days": len(days),
            "dates": days,
            "collapsed_intervals_days": collapsed,
            "median_days": _median(collapsed),
            "max_days": max(collapsed) if collapsed else None,
            "raw_intervals_days": raw,
            "median_without_collapse_days": _median(raw),
            "runs_relaunched_same_day": len(used) - len(days),
        }

    overall_days = sorted(all_days)
    overall_intervals = _intervals(overall_days)
    chosen = overall_intervals if collapse_same_day_runs else None
    if not collapse_same_day_runs:
        overall_raw: list[float] = []
        for v in per_scan.values():
            overall_raw.extend(v["raw_intervals_days"])
        chosen = overall_raw

    return {
        "scans": per_scan,
        "collapse_same_day_runs": collapse_same_day_runs,
        "distinct_assessment_days": len(overall_days),
        "dates": overall_days,
        "intervals_days": overall_intervals,
        "median_days": _median(chosen or []),
        "max_days": max(overall_intervals) if overall_intervals else None,
        "gaps": gaps,
        "warning": (None if collapse_same_day_runs else
                    "COLLAPSE DISABLED. A scan relaunched minutes later counts as a "
                    "new cadence cycle, which is not true. Declare this in the "
                    "report."),
        "note": ("The collapse happens on the server, always. Without it the M1 "
                 "median in the sandbox is 1.42 days; with it, 21 days - two "
                 "stages apart. M2 (largest gap) does not change with the collapse."),
    }
