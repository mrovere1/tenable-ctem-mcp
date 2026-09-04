"""Filter deny-list. Rejection happens BEFORE the request leaves.

The two cases of 2026-09-03 are the done criterion of milestone M3 and have been
here since M0, because the module has existed since M0.
"""

import pytest

from tenable_ctem_mcp.preflight import (
    DenyListError,
    validate_filters,
    validate_workbenches_params,
    verdict,
)


# --- New case 1 of 2026-09-03: `filters` as free text ----------------------

def test_filters_as_a_string_is_rejected():
    """The easiest trap in the set to fall into.

    `filters="tag_count >= 1"` returned the 30 assets of the corpus, with no
    error; the same filter as a JSON array returned 9. The free-text syntax is
    exactly the one list_inventory_properties suggests.
    """
    with pytest.raises(DenyListError) as exc:
        validate_filters("tag_count >= 1")
    assert exc.value.rule == "filters_must_be_json_array"
    assert "30" in exc.value.proof  # the measured proof travels with the error


@pytest.mark.parametrize("value", [{"property": "tag_count"}, 42, ["loose text"]])
def test_filters_that_is_not_an_array_of_objects_is_rejected(value):
    with pytest.raises(DenyListError):
        validate_filters(value)


# --- New case 2 of 2026-09-03, CORRECTED against the direct API ------------
#
# The matrix recorded "the `exists` operator answers 400 on finding_vpr_score"
# and concluded that the property does not support the operator. Re-running the
# discriminant pair against the REST API, the cause is another: the 400 comes
# from an EMPTY `value`, and the API message is literally "Missing value in
# filter". With value=["true"], `exists` gives 4,462 and `not exists` gives
# 1,024 - summing to the 5,486 of the corpus. The operator works.
#
# The right rule is about the missing value, not about the property.

def test_an_operator_without_a_value_is_rejected():
    with pytest.raises(DenyListError) as exc:
        validate_filters([{"property": "finding_vpr_score", "operator": "exists"}])
    assert exc.value.rule == "operator_requires_value"
    assert "Missing value in filter" in exc.value.proof


def test_exists_with_a_value_is_accepted():
    """Corrects the matrix: through the direct API the operator works."""
    f = [{"property": "finding_vpr_score", "operator": "exists", "value": ["true"]}]
    assert validate_filters(f) == f


def test_vpr_greater_or_equal_is_accepted():
    """The valid path: >= 0.1, applied and monotonic (4,462 / 1,254 / 586)."""
    f = [{"property": "finding_vpr_score", "operator": ">=", "value": ["0.1"]}]
    assert validate_filters(f) == f


# --- Date filters on findings ---------------------------------------------

@pytest.mark.parametrize("prop", ["last_updated", "first_observed_at", "last_found"])
@pytest.mark.parametrize("op", ["older than", "within last", "newer than"])
def test_a_relative_date_operator_is_rejected(prop, op):
    """Accepted and silently ignored.

    Proof: state=FIXED gives 50; with `older than 3650d` it gives 50 and with
    `within last 1d` also 50 - mutually exclusive, both returning the whole
    corpus.
    """
    with pytest.raises(DenyListError) as exc:
        validate_filters([{"property": prop, "operator": op, "value": ["3650d"]}])
    assert exc.value.rule == "relative_date_operator_is_ignored"


@pytest.mark.parametrize("prop", ["last_updated", "first_observed_at"])
@pytest.mark.parametrize("op", ["<", ">="])
def test_comparison_against_an_absolute_date_is_accepted(prop, op):
    """CORRECTS the matrix, which denied date filters wholesale.

    `last_updated < 2020-01-01` gives 0 and `>= 2020-01-01` gives 50, and the
    two sum to the corpus's 50 FIXED findings. That is the definition of an
    applied filter.
    """
    f = [{"property": prop, "operator": op, "value": ["2020-01-01"]}]
    assert validate_filters(f) == f


# --- Workbenches booleans --------------------------------------------------

@pytest.mark.parametrize("param", ["authenticated", "exploitable", "resolvable"])
def test_a_workbenches_boolean_is_rejected(param):
    """true and false return the same set: the parameter is not applied.

    With severity=critical (121 plugins), all three return 121 on both values.
    `resolvable` was "presumed ignored until proven"; it is now proven.
    """
    with pytest.raises(DenyListError):
        validate_workbenches_params({param: True})


def test_age_is_rejected_because_it_does_not_exist_in_the_api():
    """CORRECTS the matrix. `age` was the official MCP's name; in the API the
    parameter is `date_range`. A non-existent parameter is silently discarded -
    the worst case, because it looks filtered and returns the corpus."""
    with pytest.raises(DenyListError) as exc:
        validate_workbenches_params({"severity": "critical", "age": 90})
    assert "date_range" in exc.value.proof


def test_date_range_and_severity_pass():
    """The two provably applied parameters: severity and date_range
    (1 -> 17, 30 -> 118, 90 -> 121)."""
    assert validate_workbenches_params({"severity": "critical", "date_range": 90})


# --- The discriminant test -------------------------------------------------

def test_a_verdict_equal_to_the_corpus_is_ignored():
    """If the filtered total is identical to the corpus, the filter is ignored.
    The number is not published: it becomes a gap."""
    assert verdict(30, 30) == "ignored"


def test_a_verdict_smaller_than_the_corpus_is_applied():
    assert verdict(30, 9) == "applied"


def test_a_verdict_without_a_total_is_undetermined():
    assert verdict(None, 9) == "undetermined"


# ===========================================================================
# The executable preflight (M3): runs the discriminant pairs against the API.
# No verdict is inherited - that is what surfaced the four corrections to the
# trust matrix.
# ===========================================================================

def _row(table, id_):
    return next(r for r in table["checks"] if r["id"] == id_)


def test_preflight_produces_the_complete_table(sandbox):
    from tenable_ctem_mcp.preflight import run_preflight
    t = run_preflight()
    assert t["summary"]["undetermined"] == 0
    assert t["summary"]["applied"] >= 8
    assert t["summary"]["ignored"] >= 5


def test_preflight_catches_the_relative_date_operator(sandbox):
    """The two queries are mutually exclusive and both return the corpus. They
    cannot both be right - that is the proof that exposed the problem."""
    from tenable_ctem_mcp.preflight import run_preflight
    r = _row(run_preflight(), "last_updated_relative")
    assert r["verdict"] == "ignored"
    assert r["use"] is False


def test_preflight_approves_comparison_against_an_absolute_date(sandbox):
    """CORRECTION 1 to the matrix: `< 2020-01-01` gives 0 and `>= 2020-01-01`
    gives 50, and the two sum to the FIXED corpus. Date filters are not ignored
    wholesale."""
    from tenable_ctem_mcp.preflight import run_preflight
    r = _row(run_preflight(), "last_updated_comparison")
    assert r["verdict"] == "applied"
    assert r["use"] is True


def test_preflight_approves_exists_on_vpr(sandbox):
    """CORRECTION 2: exists 4,462 + not exists 1,024 = 5,486, the corpus."""
    from tenable_ctem_mcp.preflight import run_preflight
    r = _row(run_preflight(), "finding_vpr_score_exists")
    assert r["verdict"] == "applied"
    assert "5486" in r["detail"]


@pytest.mark.parametrize("param", ["authenticated", "exploitable", "resolvable"])
def test_preflight_confirms_the_ignored_booleans(sandbox, param):
    """CORRECTION 3: `resolvable` was presumed; it is now proven."""
    from tenable_ctem_mcp.preflight import run_preflight
    r = _row(run_preflight(), param)
    assert r["verdict"] == "ignored"


def test_preflight_separates_age_from_date_range(sandbox):
    """CORRECTION 4: `age` does not exist in the API and is silently discarded;
    `date_range` exists and is applied."""
    from tenable_ctem_mcp.preflight import run_preflight
    t = run_preflight()
    assert _row(t, "age")["verdict"] == "ignored"
    assert _row(t, "date_range")["verdict"] == "applied"


def test_preflight_flags_that_the_tag_count_pair_does_not_close(sandbox):
    """tag_count >= 1 (9) + = 0 (20) sum to 29, not the corpus's 30: one asset
    lacks the property. The detail must say so, otherwise the reader concludes
    the denominator is 29."""
    from tenable_ctem_mcp.preflight import run_preflight
    r = _row(run_preflight(), "tag_count")
    assert r["verdict"] == "applied"
    assert "do NOT close" in r["detail"]


def test_preflight_proves_the_deny_list_rejects_before_leaving(sandbox):
    from tenable_ctem_mcp.preflight import run_preflight
    for d in run_preflight()["deny_list"]:
        assert d["rejected"] is True, d
        assert d["proof"]
