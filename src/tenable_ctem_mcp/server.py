"""MCP tool registration. Nothing else.

Transport: stdio. No HTTP, no hosting, no network authentication - a closed
decision.

State at milestone M6: 12 assessment tools plus ctem_diagnostics, 13 in total.

NOTE on the SDK: CLAUDE.md asks for "FastMCP if available in the SDK". In the
official 2.x SDK FastMCP was renamed to MCPServer; the ergonomics are identical
(the @mcp.tool decorator and run("stdio")). This is not a deviation from the
decision, it is the new name of the same thing.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from . import __version__, now_utc
from .client import ApiError, tls_origin
from .indicators import (discovery, mobilization, prioritization, scoping,
                         validation)
from .indicators.discovery import discover_tenant
from .cadence import scan_cadence as _scan_cadence
from .mttr import FilterMismatchError
from .mttr import mttr_cadence_guard as _mttr_cadence_guard
from .mttr import mttr_collect as _mttr_collect
from .plugins import plugin_census as _plugin_census
from .plugins import plugin_details_batch as _plugin_details_batch
from .preflight import DenyListError
from .preflight import run_preflight as _run_preflight

mcp = MCPServer(
    name="tenable-ctem-mcp",
    version=__version__,
    instructions=(
        "Tenable CTEM assessment indicators, already aggregated. Every indicator "
        "carries value, n, literal_filter, collected_at_utc and "
        "preflight_verdict. A query that fails becomes a declared gap with a "
        "cause - never a partial number. Community/partner tooling, not "
        "supported by Tenable."
    ),
)


def _error(e: Exception) -> dict[str, Any]:
    """A structured error, always. Never a stack trace, never a partial number.

    The API key never appears here: `client.call` does not put it in any
    message, and the only place that reads it is the request header.
    """
    if isinstance(e, DenyListError):
        return dict(e.to_dict(), gap=True, collected_at_utc=now_utc())
    if isinstance(e, FilterMismatchError):
        return {"error": "filters_diverged", "cause": e.cause, "detail": str(e),
                "gap": True, "collected_at_utc": now_utc(),
                "note": ("The slice the job applied is not the one requested, so "
                         "the number does not answer the question. This is an "
                         "error, not a number with a caveat.")}
    if isinstance(e, ApiError):
        return {"error": "collection_failure", "cause": e.cause, "detail": str(e),
                "gap": True, "collected_at_utc": now_utc()}
    return {"error": "unexpected_failure", "cause": type(e).__name__,
            "detail": str(e), "gap": True, "collected_at_utc": now_utc()}


@mcp.tool()
def ctem_discover_tenant(use_cache: bool = True) -> dict[str, Any]:
    """Snapshot of the tenant in one call, for Step 0 of the assessment.

    Returns: tag categories and values, asset counts by asset_class, the
    exposure_classes present (with the total of each), scans with execution
    history, and agents by status.

    Replaces about ten calls of Phase A of Step 0. The result is cached with a
    short TTL; `use_cache=False` forces a fresh collection.

    CAUTION: asset_class is not exposure_classes. A tenant may have assets with
    asset_class = IDENTITY and exposure_classes = IDENTITY at zero. D2 uses
    exposure_classes.
    """
    try:
        return discover_tenant(use_cache=use_cache)
    except Exception as e:  # noqa: BLE001 - a structured error is the contract
        return _error(e)


@mcp.tool()
def ctem_preflight(workbenches_severity: str = "critical") -> dict[str, Any]:
    """The finished PREFLIGHT table: every filter the skill uses, tested live.

    No verdict is inherited from a document. Three forms of proof:
      exclusive_pair    two mutually exclusive queries whose totals must sum to
                        the corpus - "it reduced" is not enough, a filter can
                        reduce by accident
      boolean           true and false; equal totals mean the parameter is ignored
      monotonic         a ladder of cutoffs that must be strictly decreasing

    It also returns `deny_list`: the filters the server rejects BEFORE the
    request leaves, each with its rule and its measured proof.

    Run this before publishing any number derived from a filter. It costs
    queries with limit=1, because only the `total` field matters.
    """
    try:
        return _run_preflight(workbenches_severity)
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def ctem_scoping(mapping: dict[str, Any],
                 indicators: list[str] | None = None) -> dict[str, Any]:
    """Stage 1 - Scoping: S1, S2, S3, S4.

    `mapping` is mandatory and explicit - the server does not guess the tag
    category name:
        {"criticality_category": "Criticidade", "owner_category": "Owner"}
    Without it, S2 and S3 become gaps and the answer lists the categories that
    exist. Use `ctem_discover_tenant` first to see the tenant's categories.

    S1 % of assets with at least one tag - S2 % with a criticality tag
    S3 % with an owner tag - S4 declared Crown Jewels (INFORMATIONAL, no score)

    `indicators=["S2","S3"]` computes only the requested subset.
    """
    try:
        return {"indicators": scoping.compute(mapping, indicators)}
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def ctem_discovery(indicators: list[str] | None = None,
                   licensed_surfaces: list[str] | None = None,
                   sample_vpr_cutoff: float = 7.0,
                   sample_n: int = 30,
                   plugin_mode: str = "auto",
                   census_limit: int = 300) -> dict[str, Any]:
    """Stage 2 - Discovery: D1, D2, D3, D4.

    D1 days since the last assessment (inverted; source: scan_history, never a
       date filter on findings nor the `age` parameter)
    D2 % of licensed surfaces covered - pass `licensed_surfaces`
       (default ["VM"]). It is a percentage ratio, not a count
    D3 % of DEVICE assets with an agent - the denominator is DEVICE, not the total
    D4 % of plugins detected by a local plugin

    `plugin_mode`: "auto" (default) runs a CENSUS of every critical plugin if
    they fit within `census_limit`, and falls back to a stratified sample above
    that; "census" and "sample" force the choice. The census eliminates the
    confidence interval, the weighting base and the allocation bias - in the
    sandbox, 121 plugins cost 64 s and ~5,400 tokens, a fraction of what the same
    twenty plugins cost when every attribute travels.

    `indicators=["D1","D3"]` avoids the plugin calls D4 would require.
    """
    try:
        return {"indicators": discovery.compute(
            indicators, licensed_surfaces, sample_vpr_cutoff, sample_n,
            "by_detection", plugin_mode, census_limit)}
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def ctem_prioritization(mapping: dict[str, Any],
                        indicators: list[str] | None = None,
                        customer_priority_cutoff: dict[str, Any] | None = None,
                        p2_value: float | None = None) -> dict[str, Any]:
    """Stage 3 - Prioritization: P1, P2, P3. Also returns the compared queues.

    P1 % of the VPR >= 9 backlog on assets with declared criticality. It is NOT
       the agreement between score models - that has no direction of maturity
    P2 % of the ACTIVE backlog with VPR available (>= 0.1; `exists` answers 400)
    P3 composite: declared criterion + measured opportunity. Depends on P2

    `customer_priority_cutoff` = {"metric": "vpr"|"cvss3", "value": 7.0,
    "confirmed": bool}. With no declared metric P3 is a GAP, not a number: "the
    customer does not know which criterion they use" is the Ad Hoc stage itself.

    P3's context carries the three queues (CVSS >= cutoff, VPR >= cutoff,
    overlap) and the VPR coverage in the high slice - which is the coverage that
    supports a recommendation to change criterion, not that of the whole backlog.
    """
    try:
        return {"indicators": prioritization.compute(
            mapping, indicators, customer_priority_cutoff, p2_value)}
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def ctem_validation(mapping: dict[str, Any] | None = None,
                    indicators: list[str] | None = None,
                    sample_vpr_cutoff: float = 7.0,
                    sample_n: int = 30,
                    weight_by: str = "by_detection",
                    plugin_mode: str = "auto",
                    census_limit: int = 300) -> dict[str, Any]:
    """Stage 4 - Validation: V1, V2, V3, V4.

    V1 % of the set with an available exploit - INFORMATIONAL, does not score
    V2 median days in the CISA KEV (inverted; cutoffs anchored in CISA BOD 26-04)
    V3 recurrence rate: RESURFACED / (RESURFACED + FIXED). Direct data.
       Reported as a PERCENTAGE - the skill's cutoffs are [25, 15, 8, 3]
    V4 % of DEVICE with out-of-support software - the denominator is DEVICE

    V1 and V2 come from the SAME set as D4, so the report does not describe
    three different sets under a single declared size.

    `plugin_mode`: "auto" (default) runs a CENSUS if it fits in `census_limit`.
    Under a census there is no confidence interval and no weighting - `weight_by`
    has no effect and the context says `not_applicable`. Under a sample,
    `weight_by` changes the number (59.3% by detection against 54.6% by plugin in
    the sandbox) and is declared.
    """
    try:
        return {"indicators": validation.compute(
            mapping, indicators, sample_vpr_cutoff, sample_n, weight_by,
            plugin_mode, census_limit)}
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def ctem_mobilization(mapping: dict[str, Any] | None = None,
                      indicators: list[str] | None = None,
                      sample_vpr_cutoff: float = 7.0, sample_n: int = 30,
                      plugin_mode: str = "auto", census_limit: int = 300,
                      mttr_days: int = 180,
                      mttr_severities: list[str] | None = None,
                      mttr_max_wait_s: int = 240,
                      mttr_export_uuid: str | None = None,
                      batch_cutoff: int = 2,
                      max_batch_pct: float = 40.0) -> dict[str, Any]:
    """Stage 5 - Mobilization: M1, M2, M3, M4.

    M1 median assessment cadence (inverted) - runs COLLAPSED into distinct days,
       on the server. Without the collapse the sandbox median is 1.42 days;
       with it, 21 - two stages apart
    M2 largest assessment gap (inverted) - does not change with the collapse
    M3 median age of the available fix (inverted) - `Published` is a declared
       proxy for the patch date
    M4 MTTR, through mttr_collect, WITH the cadence guard applied

    `mapping["recurring_scans"]` is MANDATORY for M1 and M2: the server does not
    choose which scans represent the cadence. In the sandbox, the recurring scan
    alone gives a median of 21 and a maximum of 140; adding every scan with
    history gives a median of 1.0 and a maximum of 89, because one of them runs
    almost daily.

    M4 becomes a GAP when the guard fires - that is a correct result, not a
    defect. If the export exceeds `mttr_max_wait_s`, M4 becomes a recoverable
    gap with the `export_uuid` in the cause; call again passing
    `mttr_export_uuid`.
    """
    try:
        return {"indicators": mobilization.compute(
            mapping, indicators, sample_vpr_cutoff, sample_n,
            plugin_mode, census_limit, mttr_days,
            mttr_severities, mttr_max_wait_s, mttr_export_uuid, batch_cutoff,
            max_batch_pct)}
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def plugin_details_batch(plugin_ids: list[int]) -> dict[str, Any]:
    """Detail of several plugins in one call, with FIVE fields per plugin.

    Returns only: scan_type (local/remote), published, exploit_available,
    exploitability and the CISA-KNOWN-EXPLOITED dates.

    The full detail of one plugin is ~8,200 characters and 97 attributes. Twenty
    plugins the full way are ~15,000 tokens; this way, ~1,500. A plugin that
    fails goes into `gaps` with its cause, and the others continue.
    """
    try:
        return _plugin_details_batch(plugin_ids)
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def plugin_census(severity: str = "critical") -> dict[str, Any]:
    """Sampling frame: plugin, detection count, VPR and family.

    One call, cached with a short TTL. It is the denominator of D4, M3, V1 and
    V2. There is no census by search: plugins_search_plugins accepts a keyword
    and a CVE, not a list of plugin IDs.
    """
    try:
        return _plugin_census(severity)
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def scan_cadence(scan_ids: list[str], collapse_same_day_runs: bool = True,
                 completed_only: bool = True) -> dict[str, Any]:
    """Collapses same-day runs into DISTINCT ASSESSMENT DAYS.

    Returns intervals, median and maximum - and also
    `median_without_collapse_days`, always, so the contrast stays visible.

    Why this exists: a scan relaunched minutes later is the SAME assessment, not
    a new cycle. In the sandbox the recurring scan's 12 runs fall on 9 distinct
    days; the raw median gives 1.42 days and the collapsed one gives 21 -
    Standardized instead of Optimized, two stages apart.

    `collapse_same_day_runs=False` exists so the report can show the difference,
    never to be the default. M2 (largest gap) does not change with the collapse.
    """
    try:
        return _scan_cadence(scan_ids, collapse_same_day_runs, completed_only)
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def mttr_collect(days: int = 180, severities: list[str] | None = None,
                 tags: dict[str, Any] | None = None, max_wait_s: int = 240,
                 export_uuid: str | None = None,
                 states: list[str] | None = None,
                 num_assets: int = 100, batch_cutoff: int = 2) -> dict[str, Any]:
    """MTTR through POST /vulns/export, with polling and chunked download.

    It is the ONLY path to MTTR: `last_fixed`, `time_taken_to_fix` and
    `severity_modification_type` are not among the 44 findings properties of the
    Exposure Management API. It is not a missing wrapper.

    It does NOT block. On exceeding `max_wait_s` it returns
    {status: "pending", export_uuid} - call again passing that `export_uuid` to
    resume. Opening a new export would answer 409.

    If the job applies a slice different from the one requested, it returns a
    structured ERROR and not a number: the slice is not the question.

    Always read `scan_cadence` alongside the MTTR, and pass its windows to
    `mttr_cadence_guard`.
    """
    try:
        return _mttr_collect(days, severities, tags, max_wait_s, export_uuid,
                             states, num_assets, batch_cutoff)
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def mttr_cadence_guard(windows: list[dict[str, Any]],
                       scan_dates: list[str] | None = None,
                       alert_cutoff_pct: float = 40.0) -> dict[str, Any]:
    """Says whether the MTTR is measuring scan cadence instead of time to fix.

    Pass `windows` = `scan_cadence.WINDOWS` from mttr_collect (not `batches`:
    that one already comes filtered by the cutoff, and without the singleton
    windows the denominator shrinks and the percentage inflates), and
    `scan_dates` = the dates from scan_cadence.

    Two gates, and the second matters more:
      1. pct_in_batch above the alert cutoff -> M4 is a gap;
      2. windows formed ONLY by scan dates -> M4 is a gap, even with
         pct_in_batch below the cutoff.

    Gate 2 exists because the percentage depends on the chosen batch cutoff: in
    the reference CSV the same data gave 93.5% with cutoff 2 and 38.7% with
    cutoff 5, and cutoff 5 would pass a 40% guard. The composition of the dates
    depends on no choice at all.
    """
    try:
        return _mttr_cadence_guard(windows, scan_dates, alert_cutoff_pct)
    except Exception as e:  # noqa: BLE001
        return _error(e)


@mcp.tool()
def ctem_diagnostics() -> dict[str, Any]:
    """Says whether the server can talk to the tenant, without collecting an
    indicator.

    It does not print the key, nor any part of it. It serves to separate three
    causes that look alike from the client: credential missing, credential
    invalid, and TLS intercepted by a corporate proxy.
    """
    import os

    has_ak = bool(os.environ.get("TIO_ACCESS_KEY", "").strip())
    has_sk = bool(os.environ.get("TIO_SECRET_KEY", "").strip())
    d: dict[str, Any] = {
        "version": __version__,
        "tio_url": os.environ.get("TIO_URL", "https://cloud.tenable.com"),
        "credentials_in_environment": has_ak and has_sk,
        "collected_at_utc": now_utc(),
    }
    try:
        d["tls_ca_origin"] = tls_origin()
    except Exception as e:  # noqa: BLE001
        d["tls_ca_origin"] = f"undetermined: {e}"

    if not (has_ak and has_sk):
        d["verdict"] = "credential_missing"
        d["detail"] = ("Set TIO_ACCESS_KEY and TIO_SECRET_KEY in the server "
                       "process's environment. The key comes from Settings > My "
                       "Account > API Keys in the tenant.")
        return d

    from .client import call
    try:
        call("GET", "/tags/categories")
        d["verdict"] = "ok"
    except Exception as e:  # noqa: BLE001
        d["verdict"] = "failure"
        d.update(_error(e))
    return d


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
