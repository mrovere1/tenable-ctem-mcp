"""MTTR through POST /vulns/export.

PORTED from _ferramentas/mttr-export/tenable_mttr_export.py 1.1.0. It was not
rewritten from scratch: the interpolated percentile, the semantic filter
comparison, the batch detection and the wording of the notes were already solved
and checked against the reference CSV.

What CHANGES in the port to the server, and it is the reason the port exists:
`wait_for` does not block until completion. A tool that holds the connection for
ten minutes blows the MCP client's timeout. On exceeding `max_wait_s` it returns
`{status: "pending", export_uuid}` so the next call can resume - asking for a
new export would answer 409.

This is the only path to MTTR, and it remains so after M3: `last_fixed`,
`time_taken_to_fix` and `severity_modification_type` are not among the 44
findings properties of the Exposure Management API. It is not a missing wrapper.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from .client import ApiError, TlsError, base_url, call, log

COLLECTOR_VERSION = "1.1.0 (ported)"

VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")
VALID_STATES = ("OPEN", "REOPENED", "FIXED")


class FilterMismatchError(ApiError):
    """The slice the job applied is not the one that was asked for.

    Becomes a structured error, NEVER a number: an MTTR computed over a
    different slice looks right and carries no signal that it is wrong.
    """


# ----------------------------------------------------------------------------
# Export  (ported: abrir_export 436, aguardar 475)
# ----------------------------------------------------------------------------

def open_export(days: int | None, severities: list[str], states: list[str],
                num_assets: int, tags: dict) -> tuple[str, dict, bool]:
    filters: dict[str, Any] = {"state": states}
    if severities:
        filters["severity"] = severities
    if days:
        # `since` with state=FIXED returns what was fixed from that date on;
        # with OPEN/REOPENED it returns what was seen from that date on.
        # The spec forbids combining `since` with first_found/last_found/last_fixed.
        filters["since"] = int(time.time()) - days * 86400
    for key, values in (tags or {}).items():
        filters[f"tag.{key}"] = values

    body = {
        "num_assets": num_assets,
        "include_unlicensed": False,
        "include_plugin_output": False,   # cuts the volume drastically
        "filters": filters,
    }
    resp = call("POST", "/vulns/export", body=body)

    if "_conflict" in resp:
        conflict = resp["_conflict"]
        active_uuid = conflict.get("active_job_id")
        if not active_uuid:
            raise ApiError(f"409 without active_job_id: {conflict}", cause="conflict")
        log(f"An export is already running; reusing job {active_uuid}. Its filters "
            "may differ from the ones requested; the summary records the real ones.")
        return active_uuid, filters, True

    uuid = resp.get("export_uuid")
    if not uuid:
        raise ApiError(f"Response without export_uuid: {resp}", cause="unexpected_response")
    return uuid, filters, False


def wait_for(uuid: str, max_wait_s: int) -> tuple[list[dict], dict, bool]:
    """Downloads chunks as they become ready. Returns (findings, status, pending).

    The central difference from the command-line collector: here a timeout is
    NOT an exception nor a longer wait - it is a return with `pending=True`,
    which the caller turns into {status: "pending", export_uuid}.
    """
    deadline = time.time() + max_wait_s
    downloaded: set = set()
    findings: list[dict] = []
    status: dict = {}
    interval = 5
    while True:
        status = call("GET", f"/vulns/export/{uuid}/status")
        state = status.get("status", "?")
        available = list(status.get("chunks_available") or [])
        for cid in available:
            if cid in downloaded:
                continue
            raw = call("GET", f"/vulns/export/{uuid}/chunks/{cid}", raw=True)
            try:
                batch = json.loads(raw)
            except json.JSONDecodeError as e:
                raise ApiError(f"chunk {cid} is not valid JSON: {e}",
                               cause="invalid_chunk")
            if isinstance(batch, list):
                findings.extend(batch)
            downloaded.add(cid)

        if status.get("chunks_failed"):
            log(f"  WARNING: failed chunks: {status['chunks_failed']}.")

        if state == "FINISHED":
            return findings, status, False
        if state == "ERROR":
            raise ApiError(f"Export ended in ERROR. Reason: {status.get('reason')}",
                           cause="export_error")
        if state == "CANCELLED":
            raise ApiError("Export was cancelled.", cause="export_cancelled")
        if time.time() > deadline:
            return findings, status, True

        time.sleep(interval)
        interval = min(interval + 5, 30)


# ----------------------------------------------------------------------------
# Normalisation  (ported: iso_para_epoch 529, epoch_para_iso 558, normalizar 564)
# ----------------------------------------------------------------------------

def iso_to_epoch(value) -> int | None:
    """Accepts ISO 8601 or epoch (int/str). Returns an int epoch or None."""
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    text = text.replace("Z", "+00:00")
    if "." in text:   # truncate a sub-second fraction longer than 6 digits
        head, rest = text.split(".", 1)
        digits = ""
        for ch in rest:
            if ch.isdigit():
                digits += ch
            else:
                rest = rest[len(digits):]
                break
        else:
            rest = ""
        text = f"{head}.{digits[:6]}{rest}"
    try:
        return int(datetime.fromisoformat(text).timestamp())
    except ValueError:
        return None


def epoch_to_iso(epoch) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def normalise(f: dict, now: int) -> dict:
    asset = f.get("asset") or {}
    plugin = f.get("plugin") or {}
    cves = plugin.get("cve") or []
    if isinstance(cves, str):
        cves = [cves]

    first = iso_to_epoch(f.get("first_found"))
    last = iso_to_epoch(f.get("last_found"))
    fixed = iso_to_epoch(f.get("last_fixed"))
    native = f.get("time_taken_to_fix")

    days, source = None, ""
    if isinstance(native, (int, float)) and native > 0:
        days, source = round(native / 86400.0, 2), "native"
    elif fixed and first and fixed >= first:
        days, source = round((fixed - first) / 86400.0, 2), "derived"

    state = (f.get("state") or "").upper()
    open_age = None
    if state in ("OPEN", "REOPENED") and first:
        open_age = round((now - first) / 86400.0, 2)

    ipv4 = asset.get("ipv4")
    ip_name = (ipv4 or [""])[0] if isinstance(ipv4, list) else (ipv4 or "")
    return {
        "finding_id": f.get("finding_id", ""),
        "asset_uuid": asset.get("uuid") or asset.get("id") or "",
        "asset_name": (asset.get("hostname") or asset.get("name")
                       or asset.get("fqdn") or ip_name or ""),
        "plugin_id": plugin.get("id", ""),
        "plugin_name": plugin.get("name", ""),
        "cve": ";".join(cves),
        "severity": f.get("severity", ""),
        "modified_severity": f.get("severity_modification_type", ""),
        "vpr": ((plugin.get("vpr") or {}).get("score", "")
                if isinstance(plugin.get("vpr"), dict) else ""),
        "cvss3_base": plugin.get("cvss3_base_score", ""),
        "state": state,
        "first_found": epoch_to_iso(first),
        "last_found": epoch_to_iso(last),
        "last_fixed": epoch_to_iso(fixed),
        "resurfaced_date": epoch_to_iso(iso_to_epoch(f.get("resurfaced_date"))),
        "time_taken_to_fix_sec": native if isinstance(native, (int, float)) else "",
        "days_to_fix": days if days is not None else "",
        "mttr_source": source,
        "days_open": open_age if open_age is not None else "",
        "scan_source": f.get("source", ""),
    }


# ----------------------------------------------------------------------------
# Analysis  (ported: comparar_filtros 618, detectar_lotes 653, percentil 710)
# ----------------------------------------------------------------------------

def compare_filters(requested, applied) -> tuple[bool, dict]:
    """SEMANTIC comparison, not literal.

    The API does not return what was sent: it normalises the severity (upper
    case, in a different order) and adds ALL date filters with value zero.
    Comparing the two dictionaries literally would report a mismatch on every
    run - and that is why the consumer reads `filters_diverged`, never the two
    dicts.
    """
    if not isinstance(requested, dict) or not isinstance(applied, dict):
        return True, {"error": "filters absent or in an unexpected format"}

    def norm(v):
        if isinstance(v, (list, tuple)):
            return {str(x).strip().lower() for x in v}
        if isinstance(v, str):
            return v.strip().lower()
        return v

    div: dict[str, Any] = {}
    for k, req in requested.items():
        if k not in applied:
            div[k] = {"requested": req, "applied": "<absent>"}
        elif norm(req) != norm(applied[k]):
            div[k] = {"requested": req, "applied": applied[k]}
    # Keys the job brought that were not requested only count if they carry a
    # value: the date ones always come with 0 and are an API default, not an
    # applied filter.
    for k, v in applied.items():
        if k in requested or v in (0, "", None, [], {}, False):
            continue
        div[k] = {"requested": "<not requested>", "applied": v}
    return bool(div), div


def detect_batches(rows: list[dict], cutoff: int = 2) -> dict:
    """Finds findings closed in a batch: same asset, same first_found, same
    last_fixed. They all share the SAME days_to_fix by construction, and that
    value is the INTERVAL BETWEEN TWO SCANS, not the team's time to act.

    An asset scanned on 09 Jun, not scanned again, and seen clean on 02 Sep
    produces 85 days for everything on it - including what was fixed on the
    first day. Without this detection the report confuses cadence with MTTR.

    The `cutoff` goes into the summary because it CHANGES the percentage: in the
    reference CSV of 2026-09-03 it gave 93.5% with cutoff 2, 74.2% with 3, 64.5%
    with 4 and 38.7% with 5 - and the skill's alert threshold is 40%. With
    cutoff 5 the same data would pass the guard. Whoever reads the number needs
    to know which cutoff produced it.
    """
    groups: dict[tuple, list] = {}
    for r in rows:
        if r["state"] != "FIXED" or not r["days_to_fix"]:
            continue
        groups.setdefault((r["asset_name"], r["first_found"], r["last_fixed"]), []).append(r)

    total = sum(1 for r in rows
                if r["state"] == "FIXED" and r["days_to_fix"])

    def _pct(c: int) -> float:
        n = sum(len(v) for v in groups.values() if len(v) >= c)
        return round(n / total * 100, 1) if total else 0.0

    batches = {k: v for k, v in groups.items() if len(v) >= cutoff}
    in_batch = sum(len(v) for v in batches.values())
    detail = sorted(
        ({"asset": k[0], "first_found": k[1], "last_fixed": k[2],
          "findings": len(v), "days_to_fix": float(v[0]["days_to_fix"])}
         for k, v in batches.items()), key=lambda d: -d["findings"])

    # If a handful of dates explains ALL the windows, those dates are the scan
    # dates and the MTTR is the interval between them. The consumer cross-checks
    # against scan history - and that is how M4 became a gap in the sandbox: the
    # 7 dates were, 7 out of 7, execution days of scan 33.
    dates: set = set()
    for k in groups:
        dates.add(str(k[1])[:10])
        dates.add(str(k[2])[:10])

    # ALL windows, including single-finding ones. `batches` already comes
    # filtered by the cutoff, so feeding the guard with it drops the singleton
    # windows from the denominator and inflates the percentage - here it gave
    # 100% against the real 93.5%, and one of the 7 dates disappeared.
    windows = sorted(
        ({"asset": k[0], "first_found": k[1], "last_fixed": k[2],
          "findings": len(v), "days_to_fix": float(v[0]["days_to_fix"])}
         for k, v in groups.items()), key=lambda d: -d["findings"])

    return {
        "findings_in_batch": in_batch,
        "findings_with_mttr": total,
        "windows": windows,
        "pct_in_batch": round(in_batch / total * 100, 1) if total else 0.0,
        "min_batch_per_window": cutoff,
        "sensitivity_to_cutoff": {str(c): _pct(c) for c in (2, 3, 4, 5)},
        "distinct_windows": len(groups),
        "dates_forming_the_windows": sorted(dates),
        "batches": detail,
        "windows_note": ("`windows` carries ALL windows, including single-finding "
                         "ones; `batches` carries only those reaching the cutoff. "
                         "Pass `windows` to mttr_cadence_guard - passing `batches` "
                         "drops the singletons from the denominator and inflates "
                         "the percentage."),
    }


def percentile(sorted_values: list[float], p: float) -> float | None:
    """INTERPOLATED percentile: linear interpolation between the two neighbouring
    positions (R's type 7, numpy's default, Excel's PERCENTILE.INC).

    With a small n the choice changes the number: in the reference CSV the
    critical p90 with n=10 gave 101.43 interpolated and 92.91 by nearest
    position - a 9% difference. That is why the method is DECLARED in the summary.
    """
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return round(sorted_values[0], 2)
    pos = (len(sorted_values) - 1) * (p / 100.0)
    low = int(pos)
    high = min(low + 1, len(sorted_values) - 1)
    weight = pos - low
    return round(sorted_values[low] * (1 - weight) + sorted_values[high] * weight, 2)


def percentile_nearest_position(sorted_values: list[float], p: float) -> float | None:
    """The other method, so the summary can show the effect of the choice."""
    if not sorted_values:
        return None
    i = int(round((len(sorted_values) - 1) * (p / 100.0)))
    return round(sorted_values[i], 2)


def summarise(rows: list[dict], filters: dict, uuid: str, status: dict,
              batch_cutoff: int = 2) -> dict:
    by_sev: dict[str, dict] = {}
    for r in rows:
        sev = r["severity"] or "no_severity"
        b = by_sev.setdefault(sev, {"fixed": [], "native": 0, "derived": 0,
                                    "no_date": 0, "open": [], "total": 0,
                                    "reopened": 0, "reopened_with_date": []})
        b["total"] += 1
        if r["state"] == "REOPENED":
            b["reopened"] += 1
            if r["days_to_fix"] != "":
                b["reopened_with_date"].append(float(r["days_to_fix"]))
        if r["state"] == "FIXED":
            if r["days_to_fix"] != "":
                b["fixed"].append(float(r["days_to_fix"]))
                b[r["mttr_source"]] += 1
            else:
                b["no_date"] += 1
        elif r["days_open"] != "":
            b["open"].append(float(r["days_open"]))

    out = {}
    for sev, b in sorted(by_sev.items()):
        ordered = sorted(b["fixed"])
        open_ = sorted(b["open"])
        out[sev] = {
            "findings_in_slice": b["total"],
            "fixed_with_date": len(ordered),
            "fixed_without_date": b["no_date"],
            "source_native_time_taken_to_fix": b["native"],
            "source_derived_last_fixed_minus_first_found": b["derived"],
            "mttr_days_mean": (round(sum(ordered) / len(ordered), 2)
                               if ordered else None),
            "mttr_days_p50": percentile(ordered, 50),
            "mttr_days_p90": percentile(ordered, 90),
            "mttr_days_p90_nearest_position": percentile_nearest_position(
                ordered, 90),
            "mttr_days_max": round(ordered[-1], 2) if ordered else None,
            "open_in_slice": len(open_),
            "age_days_p50_open": percentile(open_, 50),
            "age_days_p90_open": percentile(open_, 90),
            "reopened_in_slice": b["reopened"],
            "reopened_excluded_from_mttr": len(b["reopened_with_date"]),
            "mttr_days_mean_if_reopened_included": (
                round((sum(ordered) + sum(b["reopened_with_date"]))
                      / (len(ordered) + len(b["reopened_with_date"])), 2)
                if (ordered or b["reopened_with_date"]) else None),
        }

    diverged, divergences = compare_filters(filters, status.get("filters"))
    recast = sum(1 for r in rows
                 if r["modified_severity"] not in ("", "NONE", None))
    return {
        "tool": f"tenable_mttr_export.py {COLLECTOR_VERSION}",
        "collected_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base_url": base_url(),
        "export_uuid": uuid,
        "requested_filters": filters,
        "filters_applied_by_job": status.get("filters"),
        "filters_diverged": diverged,
        "filter_divergences": divergences,
        "filter_comparison_note": (
            "The API normalises the filters and returns every date one with value "
            "0. Use `filters_diverged`, which already compares semantically; "
            "comparing the two dictionaries literally reports a mismatch on every "
            "run."),
        "scan_cadence": detect_batches(rows, batch_cutoff),
        "modified_severity_other_than_none": recast,
        "modified_severity_note": (
            "Comes from `severity_modification_type`, which the Exposure "
            "Management API does NOT expose: it is the only direct measurement of "
            "recast and acceptance the assessment reaches, and it applies to S3, "
            "P1 and P2, not only to M4."),
        "percentile_method": (
            "interpolated - linear interpolation between the two neighbouring "
            "positions (R's type 7, numpy's default, Excel's PERCENTILE.INC). The "
            "nearest-position value travels alongside, in "
            "`mttr_days_p90_nearest_position`, so the reader can measure the "
            "effect of the choice."),
        "states_included_in_mttr": ["FIXED"],
        "states_note": (
            "MTTR is computed ONLY over FIXED findings. REOPENED ones are counted "
            "in `reopened_in_slice` and stay OUT of the mean: a reopened finding "
            "was not fixed. `mttr_days_mean_if_reopened_included` exists so the "
            "reader can measure the effect of the exclusion - in the reference CSV "
            "the high mean went from 60.39 to 49.66 days."),
        "cadence_note": (
            "`time_taken_to_fix` measures detection to detection, not time to act. "
            "Findings of the same asset with the same first_found and the same "
            "last_fixed were all seen fixed in the SAME scan: their value is the "
            "interval between two scans. If `pct_in_batch` is high, the MTTR is an "
            "UPPER BOUND set by the cadence and does not measure the team. Read "
            "`min_batch_per_window`, `sensitivity_to_cutoff` and "
            "`dates_forming_the_windows` together: if few dates explain every "
            "window, those dates are the scan dates - confirm against scan_cadence."),
        "final_job_status": status.get("status"),
        "total_chunks": status.get("total_chunks"),
        "failed_chunks": status.get("chunks_failed") or [],
        "records_analysed": len(rows),
        "endpoint": "POST /vulns/export (Tenable Vulnerability Management API)",
        "mttr_definition": (
            "days_to_fix = time_taken_to_fix/86400 when the API returns the field "
            "(mttr_source=native); otherwise (last_fixed - first_found)/86400 "
            "(mttr_source=derived). FIXED findings with neither date go into "
            "fixed_without_date and do NOT enter the mean."),
        "mttr_by_severity": out,
    }


# ----------------------------------------------------------------------------
# The tool
# ----------------------------------------------------------------------------

def mttr_collect(days: int = 180, severities: list[str] | None = None,
                 tags: dict | None = None, max_wait_s: int = 240,
                 export_uuid: str | None = None, states: list[str] | None = None,
                 num_assets: int = 100, batch_cutoff: int = 2) -> dict[str, Any]:
    """Opens (or resumes) the export, aggregates and returns the summary.

    Three mandatory behaviours, all inherited from the collector:
      1. max_wait_s exceeded -> {status: "pending", export_uuid}, no exception
      2. filters_diverged -> structured error, never a number
      3. TLS failure -> diagnosed cause, never a raw exception
    """
    severities = [s.lower() for s in (severities or ["critical", "high"])]
    invalid = [s for s in severities if s not in VALID_SEVERITIES]
    if invalid:
        raise ValueError(f"invalid severity: {invalid}. Use {VALID_SEVERITIES}.")
    states = [e.upper() for e in (states or list(VALID_STATES))]

    try:
        if export_uuid:
            uuid, filters, resumed = export_uuid, {}, True
        else:
            uuid, filters, resumed = open_export(days, severities, states,
                                                 num_assets, tags or {})

        findings, status, pending = wait_for(uuid, max_wait_s)

        if pending:
            # Does NOT raise, and does NOT return a partial number: it returns
            # the ticket for the next call to resume. Asking for another export
            # would answer 409.
            return {
                "status": "pending",
                "export_uuid": uuid,
                "job_status": status.get("status"),
                "chunks_ready": status.get("finished_chunks"),
                "total_chunks": status.get("total_chunks"),
                "findings_downloaded_so_far": len(findings),
                "how_to_resume": (f"call mttr_collect again with "
                                  f"export_uuid='{uuid}'. Do NOT open a new export: "
                                  "the API answers 409 while this one is open."),
            }

        now = int(time.time())
        rows = [normalise(f, now) for f in findings]
        summary = summarise(rows, filters or status.get("filters") or {},
                            uuid, status, batch_cutoff)

        if summary["filters_diverged"] and not resumed:
            raise FilterMismatchError(
                "The job applied a slice different from the one requested, so the "
                "number does not answer the question. Divergences: "
                + json.dumps(summary["filter_divergences"], ensure_ascii=False),
                cause="filters_diverged")

        summary["status"] = "complete"
        summary["export_resumed"] = resumed
        if resumed and summary["filters_diverged"]:
            summary["resume_warning"] = (
                "Export resumed: this job's filters may not be the ones you asked "
                "for. The real filters are in `filters_applied_by_job`.")
        return summary

    except TlsError:
        # Rises untouched: client.py already diagnosed the cause (corporate proxy
        # intercepting TLS) and the server never offers to disable verification.
        raise


def mttr_cadence_guard(windows: list[dict], scan_dates: list[str] | None = None,
                       alert_cutoff_pct: float = 40.0) -> dict[str, Any]:
    """Takes the MTTR windows and says whether it is measuring scan cadence.

    Two gates, and the second matters more:
      1. `pct_in_batch` above the cutoff -> M4 is a gap;
      2. windows formed ONLY by scan dates -> M4 is a gap, even with
         pct_in_batch below the cutoff.

    Gate 2 exists because the percentage depends on the chosen batch cutoff, and
    cutoff 5 would let the same data through. The composition of the dates
    depends on no choice at all.
    """
    rows = [dict(w) for w in (windows or [])]
    total = sum(int(w.get("findings") or 0) for w in rows)

    def pct(c: int) -> float:
        n = sum(int(w["findings"]) for w in rows if int(w.get("findings") or 0) >= c)
        return round(n / total * 100, 1) if total else 0.0

    dates: set = set()
    for w in rows:
        for k in ("first_found", "last_fixed"):
            if w.get(k):
                dates.add(str(w[k])[:10])

    from_scan = {str(d)[:10] for d in (scan_dates or [])}
    coinciding = sorted(dates & from_scan) if from_scan else []
    all_from_scan = bool(from_scan) and dates.issubset(from_scan)
    sens = {str(c): pct(c) for c in (2, 3, 4, 5)}

    reasons = []
    if sens["2"] >= alert_cutoff_pct:
        reasons.append(f"pct_in_batch with cutoff 2 is {sens['2']}%, above the alert "
                       f"cutoff of {alert_cutoff_pct}%")
    if all_from_scan:
        reasons.append(f"the {len(dates)} dates forming the windows are ALL scan "
                       "execution dates: the MTTR here is the interval between scans")

    return {
        "pct_in_batch": sens["2"],
        "cutoff_used": 2,
        "alert_cutoff_pct": alert_cutoff_pct,
        "sensitivity_to_cutoff": sens,
        "dates_forming_the_windows": sorted(dates),
        "scan_dates_provided": sorted(from_scan),
        "dates_coinciding_with_scan": coinciding,
        "all_dates_are_scan_dates": all_from_scan,
        "verdict": "gap" if reasons else "can_score",
        "reasons": reasons,
        "note": ("The percentage depends on the chosen batch cutoff - with cutoff 5 "
                 "the same data would pass the guard. The composition of the dates "
                 "depends on no choice at all, which is why it is the stronger gate."),
    }
