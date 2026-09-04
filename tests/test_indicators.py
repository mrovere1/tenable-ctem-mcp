"""Golden tests for the 19 indicators, with the numbers measured 2026-09-02/03.

Sources: _docs/execucao-maturidade-sandbox-2026-09-03.md and
         _docs/validacao-dados-coleta-mttr-2026-09-03.md

A divergence is a failure. Do not adjust the test to make it pass - investigate.

The ENVELOPE contract, which every indicator goes through, is at the top. The
per-stage golden tests follow, in the order of the milestones.
"""

import json

from tenable_ctem_mcp import Indicator


def test_envelope_has_exactly_the_contract_fields():
    d = Indicator.ok("M1", 21.0, n=12,
                     literal_filter="scan_ids=['abc'], runs collapsed into 5 distinct days"
                     ).to_dict()
    assert set(d) == {"indicator", "value", "n", "literal_filter",
                      "collected_at_utc", "preflight_verdict"}
    assert d["value"] == 21.0 and d["n"] == 12
    assert d["preflight_verdict"] == "ok"


def test_gap_nulls_the_value_and_names_the_cause():
    """A silent partial number is forbidden: it is the project's central rule.
    A query that failed becomes a declared gap, with a cause."""
    d = Indicator.declared_gap("M4", cause="scan cadence dominates the windows").to_dict()
    assert d["value"] is None
    assert d["gap"] is True
    assert d["cause"] == "scan cadence dominates the windows"


def test_timestamp_is_utc_with_z():
    d = Indicator.ok("S1", 30.0).to_dict()
    assert d["collected_at_utc"].endswith("Z")
    assert len(d["collected_at_utc"]) == 20


def test_envelope_serialises_to_json():
    """The envelope crosses the MCP transport: it must be plain JSON."""
    json.dumps(Indicator.ok("D2", 100.0, n=4, literal_filter="exposure_classes").to_dict())


# --- Pagination: silent truncation is the defect this project forbids -------

def test_paginate_does_not_stop_at_the_page_size(monkeypatch):
    """Regression of a real defect, found at M0 against the sandbox.

    The first version read the scan history with a single limit=200 call and
    returned `runs: 200` for a scan that has 243 runs. A wrong count wearing the
    appearance of a right one - with no signal at all that it happened. It is
    the same kind of failure that motivated the deny-list.
    """
    from tenable_ctem_mcp import client

    total = 243
    pages = []

    def fake_call(method, path, body=None, params=None, **kwargs):
        offset = (params or {}).get("offset", 0)
        limit = (params or {}).get("limit", 200)
        pages.append((offset, limit))
        return {"history": [{"i": i} for i in range(offset, min(offset + limit, total))]}

    monkeypatch.setattr(client, "call", fake_call)
    runs = client.paginate("GET", "/scans/13/history", field="history")

    assert len(runs) == total, f"truncated at {len(runs)} of {total}"
    assert len(pages) > 1, "did not paginate: read a single page"


def test_paginate_stops_when_the_page_comes_short(monkeypatch):
    """It does not request one page too many after the last one."""
    from tenable_ctem_mcp import client

    calls = []

    def fake_call(method, path, body=None, params=None, **kwargs):
        calls.append(params)
        return {"data": [{"i": 1}, {"i": 2}]}

    monkeypatch.setattr(client, "call", fake_call)
    items = client.paginate("GET", "/anything", page_size=200)
    assert len(items) == 2
    assert len(calls) == 1


# ===========================================================================
# GOLDEN TESTS - numbers measured in the sandbox on 2026-09-02/03.
# Source: _docs/execucao-maturidade-sandbox-2026-09-03.md
#
# A divergence is a failure. Do NOT adjust the expected number to make it pass:
# investigate.
# ===========================================================================

from datetime import datetime, timezone

import pytest

MAPPING = {"criticality_category": "Criticidade", "owner_category": "Owner"}


def _by_id(rows):
    return {i["indicator"]: i for i in rows}


# --- Tenant snapshot --------------------------------------------------------

def test_tenant_snapshot_matches_the_measurement(sandbox):
    from tenable_ctem_mcp.indicators.discovery import discover_tenant
    r = discover_tenant(use_cache=False)

    assert r["tags"]["count"] == 9
    assert r["assets"]["total"] == 30
    assert r["assets"]["by_asset_class"]["DEVICE"] == 8
    assert r["exposure_classes"]["VM"] == 8
    assert r["exposure_classes"]["WAS"] == 2
    assert r["exposure_classes"]["CLOUD"] == 0
    assert r["exposure_classes"]["IDENTITY"] == 0
    assert r["agents"]["active"] == 7


def test_scan_33_has_12_runs(sandbox):
    """The sandbox's recurring scan: 12 runs across 9 distinct days.

    It is the case that underpins M1 at milestone M5 - a median of 1.42 days
    without the collapse, 21 days with it.
    """
    from tenable_ctem_mcp.indicators.discovery import discover_tenant
    r = discover_tenant(use_cache=False)
    s33 = next(s for s in r["scans"]["scans"] if s["scan_id"] == 33)
    assert s33["runs"] == 12
    assert s33["runs_completed"] == 12


# --- Scoping: S1, S2, S3, S4 ------------------------------------------------

@pytest.mark.parametrize("indicator,expected", [
    ("S1", 30.0),    # 9 of 30 assets with at least one tag
    ("S2", 26.7),    # 8 of 30 with a criticality tag
    ("S3", 6.7),     # 2 of 30 with an owner tag
])
def test_scoping_matches_the_measurement(sandbox, indicator, expected):
    from tenable_ctem_mcp.indicators.scoping import compute
    r = _by_id(compute(MAPPING, indicators=[indicator]))
    assert r[indicator]["value"] == expected
    assert r[indicator]["preflight_verdict"] == "applied"


def test_s4_is_informational_and_does_not_score(sandbox):
    from tenable_ctem_mcp.indicators.scoping import compute
    s4 = _by_id(compute(MAPPING, indicators=["S4"]))["S4"]
    assert s4["value"] is True
    assert s4["context"]["informational"] is True
    assert "curation" in s4["context"]["structural_gap"]


def test_s2_without_mapping_becomes_a_gap_not_a_number(sandbox):
    """The server does not guess the category name. Without a mapping, a gap."""
    from tenable_ctem_mcp.indicators.scoping import compute
    s2 = _by_id(compute({}, indicators=["S2"]))["S2"]
    assert s2["value"] is None and s2["gap"] is True
    assert "criticality_category" in s2["cause"]


def test_s3_with_a_nonexistent_category_lists_the_existing_ones(sandbox):
    from tenable_ctem_mcp.indicators.scoping import compute
    s3 = _by_id(compute({"owner_category": "Does Not Exist"}, indicators=["S3"]))["S3"]
    assert s3["gap"] is True
    assert "Criticidade" in s3["cause"]     # helps the consultant point at the right one


def test_category_suggestion_does_not_decide_on_its_own(sandbox):
    """It suggests, it does not choose: 'Owner' and 'Team' both match the owner hints."""
    from tenable_ctem_mcp.indicators.discovery import discover_tenant
    from tenable_ctem_mcp.indicators.scoping import suggest_categories
    s = suggest_categories(discover_tenant(use_cache=False)["tags"]["categories"])
    assert s["criticality"] == ["Criticidade"]
    assert set(s["owner"]) == {"Owner", "Team"}


# --- Discovery: D1, D2, D3, D4 ---------------------------------------------

# D1 is a difference against the instant of collection. Without a fixed clock
# there is no regression test: the value grows on its own every day. This
# instant is the one that reproduces the 0.5 days recorded in the document, over
# the fixture's most recent run (2026-09-03T00:28:58Z).
MEASUREMENT_INSTANT = datetime(2026, 9, 3, 12, 28, 58, tzinfo=timezone.utc)


def test_d1_days_since_the_last_assessment(sandbox):
    from tenable_ctem_mcp.indicators.discovery import compute
    d1 = _by_id(compute(indicators=["D1"], now=MEASUREMENT_INSTANT))["D1"]
    assert d1["value"] == 0.5
    assert d1["context"]["most_recent_run_utc"] == "2026-09-03T00:28:58Z"
    assert d1["context"]["inverted"] is True


def test_d2_coverage_of_the_licensed_surfaces(sandbox):
    """A percentage ratio, not an absolute count. A customer licensing VM and
    WAS and covering both cannot land in Defined for having 'only 2'."""
    from tenable_ctem_mcp.indicators.discovery import compute
    d2 = _by_id(compute(indicators=["D2"]))["D2"]
    assert d2["value"] == 100.0
    assert d2["context"]["present"] == ["VM", "WAS"]
    assert d2["context"]["present_not_licensed"] == ["WAS"]


def test_d3_agent_coverage_over_device(sandbox):
    """The denominator is DEVICE, not the total of assets: IDENTITY, ACCOUNT and
    GROUP have no software installed."""
    from tenable_ctem_mcp.indicators.discovery import compute
    d3 = _by_id(compute(indicators=["D3"]))["D3"]
    assert d3["value"] == 87.5            # 7 active agents over 8 DEVICE
    assert d3["n"] == 8


def test_d4_detected_by_a_local_plugin(sandbox):
    """Census by default: 121 of 121, with no confidence interval."""
    from tenable_ctem_mcp.indicators.discovery import compute
    d4 = _by_id(compute(indicators=["D4"]))["D4"]
    assert d4["value"] == 100.0
    assert d4["context"]["plugins_without_detail"] == []
    assert d4["context"]["mode"] == "census"
    assert d4["n"] == 121
    assert "CENSUS" in d4["literal_filter"]


def test_d4_sample_is_allocated_proportionally_to_the_population(sandbox):
    """This applies when the population exceeds the census limit and the sample
    comes back.

    The mistake this guard exists in order not to repeat: on the first real run
    the sample was 60/40 while the population was 65/35. It came out nearly
    right by coincidence."""
    from tenable_ctem_mcp.indicators.discovery import compute
    ctx = _by_id(compute(indicators=["D4"],
                         plugin_mode="sample"))["D4"]["context"]
    a, b = ctx["strata"]["A"], ctx["strata"]["B"]
    assert a["population"] + b["population"] == 121    # the tenant's critical plugins
    # the sample's share tracks the population's share, within one plugin
    assert abs(a["sample"] / (a["sample"] + b["sample"])
               - a["share_by_plugin"]) < 1 / (a["sample"] + b["sample"])


def test_census_has_121_critical_plugins(sandbox):
    from tenable_ctem_mcp.plugins import plugin_census
    assert plugin_census("critical")["distinct_plugins"] == 121


def test_plugin_detail_returns_exactly_five_fields(sandbox):
    """The project's token saving depends on this. An extra field here is a
    regression, not an improvement."""
    from tenable_ctem_mcp.plugins import (stratified_sample, plugin_census,
                                          plugin_details_batch)
    census = plugin_census("critical")
    pid = stratified_sample(census["plugins"])["sample"][0]["plugin_id"]
    batch = plugin_details_batch([pid])
    assert batch["gaps"] == []       # otherwise the test hides a hole in the fixture
    d = batch["plugins"][0]
    assert set(d) == {"plugin_id", "scan_type", "published", "exploit_available",
                      "exploitability", "cisa_known_exploited"}
    assert d["scan_type"] in ("local", "remote")


def test_a_plugin_without_detail_becomes_a_declared_gap_and_does_not_vanish(sandbox):
    """A DECLARED partial result is legitimate; a silent partial one is not."""
    from tenable_ctem_mcp.plugins import plugin_details_batch
    batch = plugin_details_batch([999999999])
    assert batch["plugins"] == []
    assert batch["gaps"][0]["plugin_id"] == 999999999
    assert batch["n_requested"] == 1 and batch["n_resolved"] == 0


def test_wilson_reproduces_the_published_ci(sandbox):
    """9 of 20 in the KEV gave a 95% CI of 25.8% to 65.8% in the document."""
    from tenable_ctem_mcp.plugins import wilson
    lo, hi = wilson(9, 20)
    assert round(lo * 100, 1) == 25.8
    assert round(hi * 100, 1) == 65.8


# --- Prioritization: P1, P2, P3 --------------------------------------------

def test_findings_corpus_matches_the_measurement(sandbox):
    """5,486 findings: 5,425 ACTIVE, 11 RESURFACED, 50 FIXED."""
    from tenable_ctem_mcp.indicators.prioritization import _count, _state
    assert _count(None) == 5486
    assert _count([_state("ACTIVE")]) == 5425
    assert _count([_state("RESURFACED")]) == 11
    assert _count([_state("FIXED")]) == 50


def test_p1_all_critical_backlog_sits_on_assets_with_criticality(sandbox):
    """The finding of the acceptance run: 100% of the VPR >= 9 backlog sits on
    assets with criticality, against 26.7% coverage across the inventory. The
    customer tagged the right assets - and that is more mature than the reverse."""
    from tenable_ctem_mcp.indicators.prioritization import compute
    p1 = _by_id(compute(MAPPING, indicators=["P1"]))["P1"]
    assert p1["value"] == 100.0
    ctx = p1["context"]
    # the per-tag-value sum cannot exceed the total: an asset may carry two
    assert ctx["on_asset_with_criticality"] == ctx["backlog_vpr_gte_9"]


def test_p2_vpr_coverage_in_the_active_backlog(sandbox):
    """81.6% - the denominator is ACTIVE, not the whole corpus.
    With the corpus (5,486) it would be 81.3%, and with VPR over every state, 82.2%."""
    from tenable_ctem_mcp.indicators.prioritization import compute
    p2 = _by_id(compute(MAPPING, indicators=["P2"]))["P2"]
    assert p2["value"] == 81.6
    assert p2["n"] == 5425


def test_p3_without_a_declared_criterion_is_a_gap_not_a_number(sandbox):
    """"The customer does not know which criterion they use" is the Ad Hoc stage
    itself. Classifying it is the skill's job; the server invents no cutoff."""
    from tenable_ctem_mcp.indicators.prioritization import compute
    p3 = _by_id(compute(MAPPING, indicators=["P3"]))["P3"]
    assert p3["value"] is None and p3["gap"] is True


def test_p3_opportunity_and_queues_with_a_cvss_criterion(sandbox):
    """Swapping CVSS >= 7 for VPR >= 7 shrinks the queue by ~63%."""
    from tenable_ctem_mcp.indicators.prioritization import compute
    p3 = _by_id(compute(MAPPING, indicators=["P3"],
                        customer_priority_cutoff={"metric": "cvss3", "value": 7.0}))["P3"]
    q = p3["context"]["queues"]
    assert q["cvss3_gte_cutoff"] == 3377
    assert q["vpr_coverage_in_high_slice_pct"] == 98.1   # 3,314 of 3,377
    assert 0.62 <= p3["value"] <= 0.64


def test_vpr_queues_are_monotonic(sandbox):
    """0.1 -> 7.0 -> 9.0 must be decreasing. That is what proves the VPR filter
    is applied and not ignored."""
    from tenable_ctem_mcp.indicators.prioritization import _count, _vpr
    n01 = _count([_vpr(">=", "0.1")])
    n7 = _count([_vpr(">=", "7")])
    n9 = _count([_vpr(">=", "9")])
    assert n01 == 4462
    assert n01 > n7 > n9 > 0


# --- Validation: V1, V2, V3, V4 --------------------------------------------

def test_v3_recurrence_rate(sandbox):
    """18.0% = 11 RESURFACED over 11 + 50 FIXED. Direct data, not a computation."""
    from tenable_ctem_mcp.indicators.validation import compute
    v3 = _by_id(compute(indicators=["V3"]))["V3"]
    assert v3["value"] == 18.0
    assert v3["n"] == 61
    assert v3["context"]["inverted"] is True


def test_v3_is_reported_as_a_percentage_not_a_fraction(sandbox):
    """Audit finding of 2026-09-04. The skill carried V3 cutoffs as
    [0.25, 0.15, 0.08, 0.03] while every other rate cutoff there is a whole
    number - S1 [20,50,80,95], P2 [40,70,90,98]. Being inverted, 18.0 compared
    against 0.25 fell into the worst bucket every time; against [25,15,8,3] it
    lands in stage 2. The unit is stated in the context so the comparison cannot
    silently drift again."""
    from tenable_ctem_mcp.indicators.validation import compute
    v3 = _by_id(compute(indicators=["V3"]))["V3"]
    assert v3["value"] > 1.0            # a percentage, never a 0..1 fraction
    assert "PERCENTAGE" in v3["context"]["unit"]
    assert "[25, 15, 8, 3]" in v3["context"]["unit"]


def test_v4_device_with_out_of_support_software(sandbox):
    """87.5% = 7 of 8 DEVICE. With the total of assets it would be 23% - two
    stages apart. The denominator is DEVICE."""
    from tenable_ctem_mcp.indicators.validation import compute
    v4 = _by_id(compute(indicators=["V4"]))["V4"]
    assert v4["value"] == 87.5
    assert v4["n"] == 8
    assert v4["context"]["devices_with_eol"] == 7


def test_v1_is_informational_and_declares_the_weight_base(sandbox):
    """A weighted rate without a declared base is not verifiable: the same
    sample gives 59.3% by detection and 54.6% by plugin with n=20."""
    from tenable_ctem_mcp.indicators.validation import compute
    for base, expected in (("by_detection", 59.3), ("by_plugin", 54.6)):
        v1 = _by_id(compute(indicators=["V1"], sample_n=20, weight_by=base,
                            plugin_mode="sample"))["V1"]
        assert v1["context"]["informational"] is True
        assert v1["context"]["weight_base"] == base
        assert v1["value"] == expected


def test_v2_median_days_in_the_kev_with_a_frozen_clock(sandbox):
    """V2 is a difference against the instant of collection and grows on its own
    every day. Without a fixed clock there is no regression test."""
    from tenable_ctem_mcp.indicators.validation import compute
    v2 = _by_id(compute(indicators=["V2"], now=MEASUREMENT_INSTANT,
                        plugin_mode="sample"))["V2"]
    assert v2["value"] == 1357.0
    assert v2["context"]["inverted"] is True
    assert v2["context"]["plugins_with_kev"] == 12
    assert "BOD 26-04" in v2["context"]["threshold_origin"]


def test_v2_under_a_census_has_no_confidence_interval(sandbox):
    """A census does not infer: there is nothing to estimate, so there is no CI."""
    from tenable_ctem_mcp.indicators.validation import compute
    v2 = _by_id(compute(indicators=["V2"], now=MEASUREMENT_INSTANT))["V2"]
    assert v2["context"]["mode"] == "census"
    assert v2["context"]["ci95_proportion_with_kev"] is None
    assert v2["context"]["plugins_in_set"] == 121


def test_v1_and_v2_come_from_the_same_set_as_d4(sandbox):
    """Otherwise the report describes three different sets under a single
    declared size, and the published CI holds for none of them."""
    from tenable_ctem_mcp.indicators.discovery import compute as disc
    from tenable_ctem_mcp.indicators.validation import compute as val
    for mode in ("census", "sample"):
        d4 = _by_id(disc(indicators=["D4"], plugin_mode=mode))["D4"]
        v1 = _by_id(val(indicators=["V1"], plugin_mode=mode))["V1"]
        assert d4["n"] == v1["n"]
        assert d4["context"]["mode"] == v1["context"]["mode"] == mode


def test_the_v1_divergence_has_an_identified_cause(sandbox):
    """The document publishes V1 = 59.6% with its own sample (A 11/12, B 1/8).

    That number does NOT reconstruct from the 65/35 population the document
    itself states - that gives 64.0%. It reconstructs exactly with
    share_A = 0.595 (the per-plugin share measured today) and weighting BY
    PLUGIN, not by detection.

    Two conclusions, and both matter:
      1. the weight base used there was `by_plugin`, not the `by_detection` the
         skill's config carries as the default;
      2. the population share narrated in the document is not the one that
         supports the number published in it.

    That is why V1 and V2 have NO golden test against the document's value: they
    depend on which plugins were drawn, and that sample is not recoverable. What
    is tested is the method, over the fixture, with a fixed seed.
    """
    def reconstruct(share_a):
        return round(100 * ((11 / 12) * share_a + (1 / 8) * (1 - share_a)), 1)

    assert reconstruct(0.65) == 64.0                  # what the document narrates
    assert reconstruct(0.5950413223140496) == 59.6    # what the document publishes


def test_the_sample_is_reproducible_across_runs(sandbox):
    """A fixed seed. Without reproducibility the same tenant scores differently
    every round, and a golden test cannot exist."""
    from tenable_ctem_mcp.client import CACHE
    from tenable_ctem_mcp.plugins import sample_with_details
    a = [p["plugin_id"] for p in
         sample_with_details(mode="sample")["sample"]["sample"]]
    CACHE.clear()
    b = [p["plugin_id"] for p in
         sample_with_details(mode="sample")["sample"]["sample"]]
    assert a == b and len(a) == 30


# --- Census: the default mode since plugin_details_batch exists -------------

def test_census_is_the_default_when_it_fits_the_limit(sandbox):
    """Sampling existed because plugins_search_plugins does not accept a list of
    IDs. plugin_details_batch does, so the constraint fell away."""
    from tenable_ctem_mcp.plugins import sample_with_details
    c = sample_with_details()["sample"]
    assert c["mode"] == "census"
    assert c["n"] == c["population"] == 121
    assert c["seed"] is None          # there is no draw


def test_census_falls_back_to_a_sample_above_the_limit(sandbox):
    """A large tenant may have thousands of critical plugins; at 528 ms each, a
    thousand plugins are nine minutes."""
    from tenable_ctem_mcp.plugins import sample_with_details
    c = sample_with_details(census_limit=50)["sample"]
    assert c["mode"] == "sample"
    assert c["n"] == 30 and c["population"] == 121


def test_census_neither_weights_nor_estimates(sandbox):
    """Under a census the rate is the count. `weight_base` comes back as
    `not_applicable` rather than a label suggesting a method choice where there
    was none."""
    from tenable_ctem_mcp.plugins import sample_with_details, rate
    pkg = sample_with_details()
    r = rate(pkg["sample"], pkg["details"],
             lambda d: bool(d.get("exploit_available")))
    assert r["mode"] == "census"
    assert r["weight_base"] == "not_applicable"
    assert r["ci95_whole_sample"] is None
    assert r["n"] == 121


def test_census_eliminates_the_weight_base_ambiguity(sandbox):
    """Under a sample, by_detection and by_plugin give 59.3% and 54.6% - five
    points of difference from the method choice alone. Under a census both give
    the same number, because there is no weighting at all."""
    from tenable_ctem_mcp.indicators.validation import compute
    values = {b: _by_id(compute(indicators=["V1"], weight_by=b))["V1"]["value"]
              for b in ("by_detection", "by_plugin")}
    assert values["by_detection"] == values["by_plugin"] == 61.2


# --- Mobilization: M1, M2, M3, M4 ------------------------------------------

RECURRING_SCANS = {"recurring_scans": [33]}


def test_m1_uses_distinct_days_and_not_raw_runs(sandbox):
    """THE DONE CRITERION OF M5.

    The previous formula was "median interval between consecutive completed
    runs", and it was wrong: a scan relaunched minutes later is the SAME
    assessment. The recurring scan's 12 runs fall on 9 distinct days; the raw
    median gives 1.42 days - a number with no meaning for a tenant that assessed
    on 9 days across 12 months. Collapsed, 21 days: Standardized instead of
    Optimized.
    """
    from tenable_ctem_mcp.indicators.mobilization import compute
    m1 = _by_id(compute(RECURRING_SCANS, indicators=["M1"]))["M1"]
    assert m1["value"] == 21.0
    assert m1["value"] != 1.42
    assert m1["context"]["intervals_days"] == [140, 40, 2, 89, 1, 1, 85, 1]
    assert m1["context"]["distinct_days"] == 9
    # the contrast travels alongside, always, so the reader sees what the
    # collapse changes
    assert m1["context"]["median_without_collapse_days"]["33"] == 1.42


def test_m2_largest_gap_does_not_change_with_the_collapse(sandbox):
    from tenable_ctem_mcp.cadence import scan_cadence
    from tenable_ctem_mcp.indicators.mobilization import compute
    m2 = _by_id(compute(RECURRING_SCANS, indicators=["M2"]))["M2"]
    assert m2["value"] == 140.0
    assert scan_cadence([33], collapse_same_day_runs=False)["max_days"] == 140


def test_scan_cadence_without_collapse_aggregates_raw_intervals(sandbox):
    """Audit finding of 2026-09-04: with `collapse_same_day_runs=False` the raw
    intervals were computed per scan but the OVERALL median still summed the
    collapsed ones - both modes returned 21.0. The diagnostic mode exists
    precisely to SHOW the 1.42 vs 21 contrast; returning the same number, it hid
    what it was there to expose."""
    from tenable_ctem_mcp.cadence import scan_cadence
    with_collapse = scan_cadence([33], collapse_same_day_runs=True)
    without = scan_cadence([33], collapse_same_day_runs=False)
    assert with_collapse["median_days"] == 21.0
    assert without["median_days"] == 1.42
    assert without["median_days"] != with_collapse["median_days"]
    # the raw list travels alongside, so the number is auditable and not merely
    # asserted
    assert len(without["scans"]["33"]["raw_intervals_days"]) == 11
    assert without["warning"] and "COLLAPSE DISABLED" in without["warning"]


def test_m1_without_declared_scans_is_a_gap(sandbox):
    """The server does not choose which scans represent the cadence, and the
    reason is measured: with every scan that has history the median drops from
    21 to 1.0 and the maximum from 140 to 89, because one of them runs almost
    daily."""
    from tenable_ctem_mcp.indicators.mobilization import compute
    m1 = _by_id(compute({}, indicators=["M1"]))["M1"]
    assert m1["gap"] is True and m1["value"] is None
    assert "recurring_scans" in m1["cause"]
    assert "33" in m1["cause"]          # lists the scans with history


def test_m3_labels_published_as_a_declared_proxy(sandbox):
    """`Published` is the DETECTION PLUGIN's date, not the patch's."""
    from tenable_ctem_mcp.indicators.mobilization import compute
    m3 = _by_id(compute(RECURRING_SCANS, indicators=["M3"],
                        now=MEASUREMENT_INSTANT, plugin_mode="sample"))["M3"]
    assert m3["value"] == 1047.0
    assert m3["context"]["inverted"] is True
    assert "proxy" in m3["context"]["declared_proxy"]
    assert "patch_publication_date" in m3["context"]["declared_proxy"]


def test_m4_becomes_a_gap_when_the_cadence_guard_fires(sandbox, monkeypatch):
    """In the sandbox M4 is a gap ON MERIT: the 7 dates forming the windows are
    7 out of 7 scan execution dates. With cadence dominating, M4 would measure
    the same thing as M1 and M2 - counting cadence twice."""
    import json
    from pathlib import Path

    from tenable_ctem_mcp import mttr
    from tenable_ctem_mcp.indicators import mobilization

    d = json.loads((Path(__file__).parent / "fixtures"
                    / "mttr_export_2026-09-03.json").read_text(encoding="utf-8"))
    rows = [dict(zip(d["fields"], r)) for r in d["rows"]]
    summary = mttr.summarise(rows, d["requested_filters"], "uuid-fixture", d["status"], 2)
    summary["status"] = "complete"
    monkeypatch.setattr(mobilization, "mttr_collect", lambda **k: summary)

    m4 = _by_id(mobilization.compute(RECURRING_SCANS, indicators=["M4"]))["M4"]
    assert m4["gap"] is True and m4["value"] is None
    assert "assessment cadence" in m4["cause"]
    g = m4["context"]["cadence_guard"]
    assert g["pct_in_batch"] == 93.5
    assert g["all_dates_are_scan_dates"] is True
    # the p50s stay visible even in the gap: the skill needs them for the text
    assert m4["context"]["p50_critical"] == 42.94
    assert m4["context"]["p50_high"] == 85.51


def test_m4_carries_the_per_severity_evidence(sandbox, monkeypatch):
    """Audit finding of 2026-09-04: the skill requires n per severity, the
    origin of the datum (native vs derived) and the reopened count to declare
    the method in the report. mttr_collect already computed all of it; the
    indicator simply did not pass it on."""
    import json
    from pathlib import Path

    from tenable_ctem_mcp import mttr
    from tenable_ctem_mcp.indicators import mobilization

    d = json.loads((Path(__file__).parent / "fixtures"
                    / "mttr_export_2026-09-03.json").read_text(encoding="utf-8"))
    rows = [dict(zip(d["fields"], r)) for r in d["rows"]]
    summary = mttr.summarise(rows, d["requested_filters"], "uuid-fixture", d["status"], 2)
    summary["status"] = "complete"
    monkeypatch.setattr(mobilization, "mttr_collect", lambda **k: summary)

    ctx = _by_id(mobilization.compute(RECURRING_SCANS, indicators=["M4"]))["M4"]["context"]
    crit = ctx["by_severity"]["critical"]
    assert crit["fixed_with_date"] == 10
    assert crit["source_native_time_taken_to_fix"] + \
           crit["source_derived_last_fixed_minus_first_found"] == 10
    assert "reopened_in_slice" in crit
    assert ctx["states_included"] == ["FIXED"]


def test_m4_pending_is_a_recoverable_gap_with_the_uuid(sandbox, monkeypatch):
    """An export in progress is not a failure: it is a recoverable gap, and the
    cause carries the export_uuid for the next call to resume."""
    from tenable_ctem_mcp.indicators import mobilization

    monkeypatch.setattr(mobilization, "mttr_collect",
                        lambda **k: {"status": "pending", "export_uuid": "u-123",
                                     "job_status": "PROCESSING"})
    m4 = _by_id(mobilization.compute(RECURRING_SCANS, indicators=["M4"]))["M4"]
    assert m4["gap"] is True
    assert "u-123" in m4["cause"] and "409" in m4["cause"]


def test_m4_declares_it_is_the_lower_of_the_two_stages(sandbox, monkeypatch):
    """Mature mobilisation closes both severities, it does not offset one with
    the other. The stage belongs to the skill; the server delivers the two p50s
    and the cutoffs."""
    from tenable_ctem_mcp.indicators import mobilization

    summary = {
        "status": "complete", "export_uuid": "u",
        "scan_cadence": {"windows": [{"asset": "a", "first_found": "2026-01-05",
                                      "last_fixed": "2026-01-09", "findings": 1}],
                         "findings_with_mttr": 1},
        "mttr_by_severity": {"critical": {"mttr_days_p50": 12.0},
                             "high": {"mttr_days_p50": 40.0}},
        "percentile_method": "interpolated", "states_included_in_mttr": ["FIXED"],
        "modified_severity_other_than_none": 0,
    }
    monkeypatch.setattr(mobilization, "mttr_collect", lambda **k: summary)
    m4 = _by_id(mobilization.compute({"recurring_scans": [33]},
                                     indicators=["M4"]))["M4"]
    assert m4.get("gap", False) is False
    assert m4["value"] == {"p50_critical": 12.0, "p50_high": 40.0}
    assert m4["context"]["cutoffs"]["critical"] == [90, 30, 15, 7]
    assert "LOWER of the two" in m4["context"]["how_to_score"]
