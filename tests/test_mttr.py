"""M4 - MTTR, cadence and the three mandatory locks.

Numbers from _docs/validacao-dados-coleta-mttr-2026-09-03.md.
A divergence is a failure. Do not adjust the test: investigate.
"""

import json
from pathlib import Path

import pytest

from tenable_ctem_mcp.mttr import (
    FilterMismatchError,
    compare_filters,
    detect_batches,
    mttr_cadence_guard,
    mttr_collect,
    percentile,
    percentile_nearest_position,
    summarise,
)

FIXTURE = Path(__file__).parent / "fixtures" / "mttr_export_2026-09-03.json"


@pytest.fixture(scope="module")
def collection():
    d = json.loads(FIXTURE.read_text(encoding="utf-8"))
    fields = d["fields"]
    rows = [dict(zip(fields, r)) for r in d["rows"]]
    return d, rows


@pytest.fixture(scope="module")
def summary(collection):
    d, rows = collection
    return summarise(rows, d["requested_filters"],
                     "00000000-0000-0000-0000-000000000001",
                     d["status"], batch_cutoff=2)


# --- The reference numbers -------------------------------------------------

def test_the_slice_has_the_4278_rows(collection):
    _, rows = collection
    assert len(rows) == 4278


def test_modified_severity_is_none_on_all_of_them(summary):
    """The only direct measurement of recast and acceptance the assessment
    reaches. `severity_modification_type` does not exist in the Exposure
    Management API - no tenable_one_* tool gets to it. It applies to S3, P1 and
    P2, not only M4."""
    assert summary["modified_severity_other_than_none"] == 0
    assert summary["records_analysed"] == 4278


def test_critical_mttr_matches_the_reference_csv(summary):
    c = summary["mttr_by_severity"]["critical"]
    assert c["fixed_with_date"] == 10
    assert c["mttr_days_mean"] == 52.93
    assert c["mttr_days_p50"] == 42.94
    assert c["mttr_days_p90"] == 101.43
    assert c["mttr_days_max"] == 178.07


def test_the_interpolated_percentile_differs_from_the_positional_one(summary):
    """With n=10 the choice changes the number by 9%: 101.43 against 92.91. That
    is why the method is declared, and both values go into the summary."""
    c = summary["mttr_by_severity"]["critical"]
    assert c["mttr_days_p90"] == 101.43
    assert c["mttr_days_p90_nearest_position"] == 92.91
    assert "interpolated" in summary["percentile_method"]


def test_the_mttr_origin_is_native_on_all_of_them(summary):
    """100% native `time_taken_to_fix`, 0 derived."""
    for sev in ("critical", "high", "medium"):
        b = summary["mttr_by_severity"][sev]
        assert b["source_derived_last_fixed_minus_first_found"] == 0
        assert b["source_native_time_taken_to_fix"] == b["fixed_with_date"]


def test_the_reopened_exclusion_is_declared_with_its_effect(summary):
    """The exclusion is defensible - a reopened finding was not fixed - but it
    has to be written down, with the number it changes."""
    h = summary["mttr_by_severity"]["high"]
    assert h["mttr_days_mean"] == 60.39            # FIXED only
    assert h["mttr_days_mean_if_reopened_included"] == 49.66
    assert h["reopened_in_slice"] == 5
    m = summary["mttr_by_severity"]["medium"]
    assert m["mttr_days_mean"] == 95.95
    assert m["mttr_days_mean_if_reopened_included"] == 64.08
    assert summary["states_included_in_mttr"] == ["FIXED"]


# --- Cadence: the finding that matters more than the percentage ------------

def test_pct_in_batch_and_the_sensitivity_to_the_cutoff(collection):
    """Cutoff 5 would give 38.7% and would pass the skill's 40% guard. That is
    why the cutoff used and the sensitivity go into the summary: whoever reads
    the number needs to know which cutoff produced it."""
    _, rows = collection
    c = detect_batches(rows, cutoff=2)
    assert c["pct_in_batch"] == 93.5
    assert c["min_batch_per_window"] == 2
    assert c["sensitivity_to_cutoff"] == {"2": 93.5, "3": 74.2, "4": 64.5, "5": 38.7}
    assert c["findings_with_mttr"] == 31
    assert c["findings_in_batch"] == 29


def test_nine_windows_over_seven_dates(collection):
    """The 9 windows (first_found, last_fixed) are all pairs drawn from 7 dates.
    That is the structural finding: those 7 dates are the tenant's scan dates."""
    _, rows = collection
    c = detect_batches(rows, cutoff=2)
    assert c["distinct_windows"] == 9
    assert c["dates_forming_the_windows"] == [
        "2026-01-27", "2026-03-08", "2026-06-07", "2026-06-08",
        "2026-06-09", "2026-09-02", "2026-09-03"]


def test_the_largest_batch_has_12_findings_of_the_same_asset(collection):
    """All with the same days_to_fix by construction - the value is the interval
    between two scans, not the team's time to act."""
    _, rows = collection
    largest = detect_batches(rows, cutoff=2)["batches"][0]
    assert largest["findings"] == 12
    assert largest["days_to_fix"] == 85.51


def test_windows_includes_the_singletons_and_batches_does_not(collection):
    """Defect found when wiring up the guard: feeding mttr_cadence_guard with
    `batches` drops the single-finding windows from the denominator and inflates
    the percentage - it gave 100% against the real 93.5%, and one of the 7 dates
    disappeared."""
    _, rows = collection
    c = detect_batches(rows, cutoff=2)
    assert len(c["windows"]) == 9
    assert len(c["batches"]) < len(c["windows"])
    assert sum(w["findings"] for w in c["windows"]) == c["findings_with_mttr"]


SCAN_DATES = ["2025-09-09", "2026-01-27", "2026-03-08", "2026-03-10",
              "2026-06-07", "2026-06-08", "2026-06-09", "2026-09-02", "2026-09-03"]


def test_the_cadence_guard_declares_a_gap_through_both_gates(collection):
    """The windows' 7 dates are 7 out of 7 scan execution dates. The MTTR here
    is the interval between scans - it measures assessment cadence, not fixing."""
    _, rows = collection
    g = mttr_cadence_guard(detect_batches(rows, cutoff=2)["windows"],
                           scan_dates=SCAN_DATES)
    assert g["verdict"] == "gap"
    assert g["pct_in_batch"] == 93.5
    assert g["all_dates_are_scan_dates"] is True
    assert len(g["dates_coinciding_with_scan"]) == 7
    assert len(g["reasons"]) == 2      # both gates fire


def test_the_second_gate_fires_even_with_a_low_percentage():
    """The dates gate does not depend on the chosen cutoff, and that is why it
    exists: with cutoff 5 the percentage would drop to 38.7% and pass the guard."""
    windows = [{"asset": "a", "first_found": "2026-06-09",
                "last_fixed": "2026-09-02", "findings": 1}]
    g = mttr_cadence_guard(windows, scan_dates=["2026-06-09", "2026-09-02"])
    assert g["pct_in_batch"] == 0.0           # no batch at all
    assert g["verdict"] == "gap"              # a gap even so
    assert g["all_dates_are_scan_dates"] is True


def test_the_guard_clears_when_the_dates_are_not_scan_dates():
    windows = [{"asset": "a", "first_found": "2026-01-05",
                "last_fixed": "2026-01-09", "findings": 1}]
    g = mttr_cadence_guard(windows, scan_dates=["2026-06-09"])
    assert g["verdict"] == "can_score"
    assert g["reasons"] == []


# ===========================================================================
# The THREE mandatory locks of mttr_collect.
# None of them may be lost in the port from the collector - decision 2 of the
# plan: there is no parallel path, so the failure must be explicit and
# recoverable.
# ===========================================================================

def test_lock_1_a_timeout_returns_pending_with_the_uuid(monkeypatch):
    """It does not raise and does not return a partial number: it returns the
    ticket for the next call to resume. Opening another export would answer 409."""
    from tenable_ctem_mcp import mttr

    monkeypatch.setattr(mttr, "open_export",
                        lambda *a, **k: ("job-uuid", {"state": ["FIXED"]}, False))
    monkeypatch.setattr(mttr, "wait_for",
                        lambda uuid, s: ([], {"status": "PROCESSING",
                                              "finished_chunks": 1,
                                              "total_chunks": 4}, True))
    r = mttr_collect(max_wait_s=1)
    assert r["status"] == "pending"
    assert r["export_uuid"] == "job-uuid"
    assert "409" in r["how_to_resume"]
    assert "mttr_days_mean" not in json.dumps(r)   # no partial number


def test_lock_2_diverging_filters_become_an_error_not_a_number(monkeypatch):
    """The slice is not the request, so the number does not answer the question."""
    from tenable_ctem_mcp import mttr

    monkeypatch.setattr(mttr, "open_export",
                        lambda *a, **k: ("u", {"severity": ["critical"]}, False))
    monkeypatch.setattr(mttr, "wait_for",
                        lambda uuid, s: ([], {"status": "FINISHED",
                                              "filters": {"severity": ["low"]}}, False))
    with pytest.raises(FilterMismatchError) as exc:
        mttr_collect()
    assert exc.value.cause == "filters_diverged"


def test_lock_3_a_tls_failure_rises_with_a_diagnosed_cause(monkeypatch):
    """Never a raw exception: the partner needs to know it is their proxy, not
    the MCP. And the server NEVER offers to disable verification."""
    from tenable_ctem_mcp import mttr
    from tenable_ctem_mcp.client import TlsError

    def explode(*a, **k):
        raise TlsError("corporate proxy intercepting TLS",
                       cause="tls_corporate_proxy")

    monkeypatch.setattr(mttr, "open_export", explode)
    with pytest.raises(TlsError) as exc:
        mttr_collect()
    assert exc.value.cause == "tls_corporate_proxy"


def test_resuming_by_uuid_does_not_open_a_new_export(monkeypatch):
    """This is how the 409 is avoided."""
    from tenable_ctem_mcp import mttr

    def should_not_happen(*a, **k):
        raise AssertionError("opened a new export while holding an export_uuid; "
                             "that would give a 409")

    monkeypatch.setattr(mttr, "open_export", should_not_happen)
    monkeypatch.setattr(mttr, "wait_for",
                        lambda uuid, s: ([], {"status": "FINISHED", "filters": {}}, False))
    r = mttr_collect(export_uuid="existing-uuid")
    assert r["status"] == "complete"
    assert r["export_resumed"] is True


def test_an_invalid_severity_is_refused_before_leaving():
    with pytest.raises(ValueError):
        mttr_collect(severities=["catastrophic"])


# --- Semantic filter comparison --------------------------------------------

def test_the_filter_comparison_ignores_the_apis_normalisation():
    """The API normalises the severity and adds ALL date filters with value 0.
    Comparing the dictionaries literally would report a mismatch on every run -
    which is why the consumer reads `filters_diverged`, never the two dicts."""
    requested = {"state": ["FIXED"], "severity": ["critical", "high"]}
    applied = {"state": ["FIXED"], "severity": ["HIGH", "CRITICAL"],
               "since": 0, "first_found": 0, "last_fixed": 0}
    diverged, div = compare_filters(requested, applied)
    assert diverged is False and div == {}


def test_the_filter_comparison_catches_a_real_divergence():
    diverged, div = compare_filters({"severity": ["critical"]},
                                    {"severity": ["low"]})
    assert diverged is True and "severity" in div


def test_a_percentile_of_an_empty_list_is_none():
    assert percentile([], 90) is None
    assert percentile_nearest_position([], 90) is None
