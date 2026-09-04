"""Filter deny-list and discriminant pairs.

Source: _docs/matriz-confianca-filtros-mcp.md, updated 2026-09-03.
The list lives HERE and nowhere else - CLAUDE.md points here on purpose, so that
two copies cannot diverge.

Why this module exists. The API accepts filters it does not apply, and returns
no error. The query looks filtered, returns the total of the whole corpus, and
the number travels into the report as if it were the result of the filter. That
is not missing data: it is a wrong number that looks right, and there is no
signal that it happened.

Rule: an untested filter is an untrusted filter. The deny-list rejects BEFORE
the request leaves - an explicit error, never a count.

A CAVEAT THAT PROVED ITSELF: the verdicts in the matrix were measured through
an EARLIER COLLECTION PATH. This server talks straight to the REST API, and the
behaviour DIFFERS on four points, all re-executed with a discriminant pair on
2026-09-03. No verdict was inherited on trust, and that was the right call:

  1. Date filters on findings are not ignored wholesale. The RELATIVE operators
     (`within last`, `older than`, `newer than`) are ignored; the COMPARISON
     ones (`<`, `<=`, `>`, `>=`, `=`) are applied.
     Proof: state=FIXED gives 50. With `older than 3650d` it gives 50 and with
     `within last 1d` it gives 50 - mutually exclusive, both with the whole
     corpus. Whereas `< 2020-01-01` gives 0 and `>= 2020-01-01` gives 50: they
     sum to 50.

  2. `exists` on finding_vpr_score WORKS, as long as `value` is not empty.
     Proof: `exists` with value=["true"] gives 4,462 and `not exists` gives
     1,024, summing to the 5,486 of the corpus. The HTTP 400 comes from an empty
     `value`, and the API message is literally "Missing value in filter" - the
     real rule is about the missing value, not about the property.

  3. `resolvable` on workbenches was "presumed ignored until proven". It is now
     proven: true and false return the same 121 plugins.

  4. `age` is not the parameter name in the API; it is `date_range`, and that
     one WORKS (1 -> 17, 30 -> 118, 90 -> 121). `age` was the name the official
     MCP used, and as a non-existent parameter it is silently discarded.

This does NOT invalidate the matrix: it describes the earlier path, and
its verdicts hold there. Here, this list holds.
"""

from __future__ import annotations

from typing import Any


class DenyListError(ValueError):
    """Forbidden filter. Never becomes a number: becomes an error with proof."""

    def __init__(self, message: str, rule: str, proof: str):
        super().__init__(message)
        self.rule = rule
        self.proof = proof

    def to_dict(self) -> dict[str, str]:
        return {"error": "filter_denied", "rule": self.rule,
                "detail": str(self), "proof": self.proof}


# Date properties on findings.
DATE_PROPERTIES_ON_FINDINGS = frozenset({
    "last_updated", "first_observed_at", "last_observed_at",
    "first_found", "last_found", "last_seen", "first_seen",
})

# RELATIVE date operators: accepted and silently ignored. These are the
# deny-list. Comparison operators against an absolute date pass, because the
# discriminant pair proves they are applied.
IGNORED_DATE_OPERATORS = frozenset({
    "within last", "older than", "newer than",
})

# Workbenches booleans proven to be ignored, plus the untested one of the same
# family - presumed ignored until proven otherwise.
DENIED_WORKBENCHES_PARAMS = frozenset({
    "authenticated", "exploitable", "resolvable",
    # `age` does not exist in the API: the real name is `date_range`, and it
    # works. A non-existent parameter is silently discarded, the worst case.
    "age",
})

# Operators that require a value. The API answers 400 "Missing value in filter"
# when `value` comes empty - including on existence operators, where the value
# is semantically useless but syntactically mandatory.
OPERATORS_REQUIRING_VALUE = frozenset({
    "exists", "not exists", "=", "!=", ">=", ">", "<=", "<", "between",
    "contains", "not contains", "match",
})

PROOFS = {
    "date_on_findings":
        "last_updated 'older than 3650d' returned 1840 findings, the whole corpus, "
        "the same as 'within last 1d'. Revalidated 2026-09-03: state=FIXED returned "
        "50, and within last 1d, older than 3650d and < 2020-01-01 returned the same 50.",
    "workbenches_boolean":
        "On the direct API, with severity=critical (121 plugins): authenticated, "
        "exploitable and resolvable all return 121 with both true and false. "
        "`resolvable` was 'presumed ignored until proven'; it is now proven.",
    "age_is_not_a_parameter":
        "`age` is not the parameter name in the API - it is `date_range`, and that "
        "one WORKS: 1 -> 17, 30 -> 118, 80 -> 118, 90 -> 121, 365 -> 121. `age` was "
        "the earlier path's name; as a non-existent parameter it is silently discarded.",
    "filters_string":
        "filters='tag_count >= 1' as free text returned the 30 assets of the corpus, "
        "with no error. The same filter as a JSON array returned 9. Confirmed 2026-09-03.",
    "operator_without_value":
        "`exists` with no value answers HTTP 400 with the literal message 'Missing "
        "value in filter'. With value=['true'] it works: exists gives 4,462 and not "
        "exists gives 1,024, summing to the 5,486 of the corpus. Measured on the "
        "direct API on 2026-09-03; on the earlier path that operator was "
        "unreachable.",
    "relative_date_on_findings":
        "state=FIXED gives 50. With `older than 3650d` it gives 50 and with "
        "`within last 1d` also 50 - mutually exclusive, both with the whole corpus. "
        "Whereas `< 2020-01-01` gives 0 and `>= 2020-01-01` gives 50, summing to 50: "
        "the comparison operators ARE applied.",
    "age_is_not_age":
        "The sandbox's last scan was 84 days before collection, and the cutoff fell "
        "between age=80 (zero) and age=90 (20) - on the date of the last scan, not on "
        "the discovery date. age is recency of last observation, not finding age.",
}


def validate_filters(filters: Any) -> list[dict]:
    """Validates the `filters` parameter and returns the normalised array.

    The cheapest and most valuable validation in the server: reject a string.
    The syntax 'tag_count >= 1' is exactly the one list_inventory_properties
    suggests when listing each property's operators - which is why it is the
    easiest trap in the set to fall into.
    """
    if filters is None:
        return []
    if isinstance(filters, str):
        raise DenyListError(
            "The `filters` parameter requires a JSON array. I received a string "
            f"({filters!r}), which the API silently discards, returning the query "
            "with NO filter at all - the total of the whole corpus wearing the "
            "appearance of a filtered result.",
            rule="filters_must_be_json_array",
            proof=PROOFS["filters_string"])
    if not isinstance(filters, list):
        raise DenyListError(
            f"`filters` must be a JSON array, I received {type(filters).__name__}.",
            rule="filters_must_be_json_array",
            proof=PROOFS["filters_string"])

    for clause in filters:
        if not isinstance(clause, dict):
            raise DenyListError(
                f"Every `filters` clause must be an object, I received "
                f"{type(clause).__name__}.",
                rule="filters_must_be_json_array",
                proof=PROOFS["filters_string"])
        prop = str(clause.get("property", ""))
        op = str(clause.get("operator", ""))
        _deny_property(prop)
        _deny_operator(prop, op)
        _require_value(prop, op, clause.get("value"))
    return filters


def _deny_property(prop: str) -> None:
    """Placeholder kept for symmetry; the date rule is per operator."""
    return None


def _deny_operator(prop: str, op: str) -> None:
    if (prop.lower() in DATE_PROPERTIES_ON_FINDINGS
            and op.lower() in IGNORED_DATE_OPERATORS):
        raise DenyListError(
            f"The relative operator `{op}` on `{prop}` is accepted by the API and "
            "silently ignored: the query comes back with the whole corpus. Use a "
            "comparison operator against an absolute date (`<`, `>=`), which the "
            "discriminant pair proves is applied. For time-to-fix, mttr_collect "
            "still applies, because `last_fixed` and `time_taken_to_fix` do not "
            "exist in this API.",
            rule="relative_date_operator_is_ignored",
            proof=PROOFS["relative_date_on_findings"])


def _require_value(prop: str, op: str, value) -> None:
    """The API answers 400 'Missing value in filter' when the value is absent.

    Rejecting here saves the trip and, more importantly, keeps the 400 from
    being read as "the property does not support the operator" - it was that
    reading that put `exists` on finding_vpr_score into the deny-list by mistake.
    """
    if op.lower() in OPERATORS_REQUIRING_VALUE and not value:
        raise DenyListError(
            f"The operator `{op}` on `{prop}` requires a non-empty `value`. The "
            "API answers HTTP 400 'Missing value in filter'. For existence "
            "operators, use value=[\"true\"].",
            rule="operator_requires_value",
            proof=PROOFS["operator_without_value"])


def validate_workbenches_params(params: dict[str, Any]) -> dict[str, Any]:
    """Rejects the workbenches booleans the API accepts and does not apply."""
    for key in params:
        if key.lower() == "age":
            raise DenyListError(
                "`age` is not a parameter of this API - the real name is "
                "`date_range`, and that one is applied. A non-existent parameter "
                "is silently discarded, and the query comes back with the whole "
                "corpus looking filtered. Mind the semantics: `date_range` is "
                "recency of last observation, not finding age.",
                rule="age_does_not_exist_use_date_range",
                proof=PROOFS["age_is_not_a_parameter"])
        if key.lower() in DENIED_WORKBENCHES_PARAMS:
            raise DenyListError(
                f"The workbenches parameter `{key}` is accepted and not applied: "
                "true and false return the same set. Using it as a filter "
                "produces a whole-corpus number wearing the appearance of a "
                "filtered one.",
                rule="workbenches_boolean_ignored",
                proof=PROOFS["workbenches_boolean"])
    return params


def verdict(corpus_total: int | None, filtered_total: int | None) -> str:
    """The discriminant test in one line.

    If the filtered total is identical to the corpus, the filter is ignored and
    the indicator is a gap - the number is never published.
    """
    if corpus_total is None or filtered_total is None:
        return "undetermined"
    if corpus_total == 0:
        return "empty_corpus"
    if filtered_total == corpus_total:
        return "ignored"
    return "applied"


# ----------------------------------------------------------------------------
# The executable preflight: runs the discriminant pairs against the API and
# returns the finished table. It inherits no verdict from any document.
# ----------------------------------------------------------------------------

FINDINGS_SEARCH = "/api/v1/t1/inventory/findings/search"
ASSETS_SEARCH = "/api/v1/t1/inventory/assets/search"
WORKBENCHES = "/workbenches/vulnerabilities"


def _f(prop: str, op: str, *values: str) -> dict:
    return {"property": prop, "operator": op, "value": list(values)}


def run_preflight(workbenches_severity: str = "critical") -> dict[str, Any]:
    """Runs every check and returns the PREFLIGHT table.

    Three forms of proof, and the choice depends on the filter:

    - `exclusive_pair`: two mutually exclusive queries whose totals must sum to
      the corpus. It is the strongest proof, because "it reduced" is not enough -
      a filter can reduce by accident.
    - `boolean`: true and false. Equal totals mean the parameter is ignored.
    - `monotonic`: a ladder of cutoffs that must be strictly decreasing.

    Cost: queries with limit=1, because only the `total` field matters.
    """
    from .client import ApiError, call, total_of

    def n_findings(filters=None):
        body = {"filters": filters} if filters else {}
        return total_of(call("POST", FINDINGS_SEARCH, body=body, params={"limit": 1}))

    def n_assets(filters=None):
        body = {"filters": filters} if filters else {}
        return total_of(call("POST", ASSETS_SEARCH, body=body, params={"limit": 1}))

    def n_workbenches(extra=None):
        p = {"filter.0.filter": "severity", "filter.0.quality": "eq",
             "filter.0.value": workbenches_severity, "filter.search_type": "and"}
        p.update(extra or {})
        return len(call("GET", WORKBENCHES, params=p).get("vulnerabilities") or [])

    rows: list[dict[str, Any]] = []

    def record(id_, target, filter_, kind, verdict_, detail, use=None):
        rows.append({"id": id_, "target": target, "filter": filter_, "kind": kind,
                     "verdict": verdict_, "detail": detail, "use": use})

    # --- exclusive pairs on findings -------------------------------------
    try:
        corpus_f = n_findings()
        fixed = n_findings([_f("state", "=", "FIXED")])
        record("state", "findings", "state = FIXED", "corpus_vs_filtered",
               verdict(corpus_f, fixed),
               f"corpus {corpus_f}, filtered {fixed}", use=True)

        # relative date: both exclusives return the corpus => ignored
        base = [_f("state", "=", "FIXED")]
        old = n_findings(base + [_f("last_updated", "older than", "3650d")])
        new = n_findings(base + [_f("last_updated", "within last", "1d")])
        ignored = (old == fixed and new == fixed)
        record("last_updated_relative", "findings",
               "last_updated with `older than` / `within last`", "exclusive_pair",
               "ignored" if ignored else "applied",
               f"older than 3650d -> {old}; within last 1d -> {new}; "
               f"FIXED corpus {fixed}. Mutually exclusive: they cannot both be "
               f"right.", use=False)

        # absolute date: both exclusives sum to the corpus => applied
        before = n_findings(base + [_f("last_updated", "<", "2020-01-01")])
        after = n_findings(base + [_f("last_updated", ">=", "2020-01-01")])
        sum_matches = (before + after == fixed)
        record("last_updated_comparison", "findings",
               "last_updated with `<` / `>=` against an absolute date",
               "exclusive_pair", "applied" if sum_matches else "suspect",
               f"< 2020-01-01 -> {before}; >= 2020-01-01 -> {after}; "
               f"summing {before + after} against FIXED corpus {fixed}",
               use=sum_matches)

        # exists / not exists on VPR
        has = n_findings([_f("finding_vpr_score", "exists", "true")])
        has_not = n_findings([_f("finding_vpr_score", "not exists", "true")])
        vpr_sum = (has + has_not == corpus_f)
        record("finding_vpr_score_exists", "findings",
               "finding_vpr_score with `exists` / `not exists` (value mandatory)",
               "exclusive_pair", "applied" if vpr_sum else "suspect",
               f"exists -> {has}; not exists -> {has_not}; summing {has + has_not} "
               f"against corpus {corpus_f}", use=vpr_sum)

        # monotonic VPR ladder
        ladder = [(v, n_findings([_f("finding_vpr_score", ">=", v)]))
                  for v in ("0.1", "7", "9")]
        decreasing = all(ladder[i][1] > ladder[i + 1][1] for i in range(len(ladder) - 1))
        record("finding_vpr_score_ladder", "findings", "finding_vpr_score `>=`",
               "monotonic", "applied" if decreasing else "suspect",
               " > ".join(f"{v} -> {n}" for v, n in ladder), use=decreasing)

        cvss = n_findings([_f("finding_cvss3_base_score", ">=", "7")])
        record("finding_cvss3_base_score", "findings",
               "finding_cvss3_base_score `>=`", "corpus_vs_filtered",
               verdict(corpus_f, cvss), f"corpus {corpus_f}, >= 7 -> {cvss}",
               use=True)
    except ApiError as e:
        record("findings", "findings", "-", "-", "undetermined",
               f"collection failure: {e}", use=None)

    # --- assets -----------------------------------------------------------
    try:
        corpus_a = n_assets()
        tagged = n_assets([_f("tag_count", ">=", "1")])
        untagged = n_assets([_f("tag_count", "=", "0")])
        record("tag_count", "assets", "tag_count `>=` / `=`", "exclusive_pair",
               verdict(corpus_a, tagged),
               f">= 1 -> {tagged}; = 0 -> {untagged}; summing {tagged + untagged} "
               f"against corpus {corpus_a}"
               + ("" if tagged + untagged == corpus_a else
                  ". They do NOT close: some asset lacks the `tag_count` property, "
                  "and the correct denominator remains the corpus"),
               use=True)
        device = n_assets([_f("asset_class", "=", "DEVICE")])
        record("asset_class", "assets", "asset_class `=`", "corpus_vs_filtered",
               verdict(corpus_a, device), f"corpus {corpus_a}, DEVICE -> {device}",
               use=True)
    except ApiError as e:
        record("assets", "assets", "-", "-", "undetermined",
               f"collection failure: {e}", use=None)

    # --- workbenches -------------------------------------------------------
    try:
        corpus_w = n_workbenches()
        for param in ("authenticated", "exploitable", "resolvable"):
            t = n_workbenches({param: "true"})
            fl = n_workbenches({param: "false"})
            record(param, "workbenches", f"{param} true/false", "boolean",
                   "ignored" if t == fl else "applied",
                   f"true -> {t}; false -> {fl}; corpus {corpus_w}", use=(t != fl))
        short = n_workbenches({"date_range": "1"})
        long_ = n_workbenches({"date_range": "90"})
        record("date_range", "workbenches", "date_range", "monotonic",
               "applied" if short < long_ else "ignored",
               f"1 -> {short}; 90 -> {long_}; corpus {corpus_w}. CAUTION: this is "
               f"recency of last observation, NOT finding age.",
               use=(short < long_))
        age = n_workbenches({"age": "1"})
        record("age", "workbenches", "age", "corpus_vs_filtered",
               "ignored" if age == corpus_w else "applied",
               f"age=1 -> {age}; corpus {corpus_w}. `age` is not a parameter of "
               f"this API; the real name is `date_range`.", use=False)
    except ApiError as e:
        record("workbenches", "workbenches", "-", "-", "undetermined",
               f"collection failure: {e}", use=None)

    # --- deny-list: rejected BEFORE leaving, never executed ---------------
    denied = []
    for description, attempt in (
        ("`filters` as a string", lambda: validate_filters("tag_count >= 1")),
        ("`exists` with no value", lambda: validate_filters(
            [_f("finding_vpr_score", "exists")])),
        ("`older than` on last_updated", lambda: validate_filters(
            [_f("last_updated", "older than", "3650d")])),
        ("`authenticated` on workbenches", lambda: validate_workbenches_params(
            {"authenticated": True})),
        ("`age` on workbenches", lambda: validate_workbenches_params({"age": 90})),
    ):
        try:
            attempt()
            denied.append({"case": description, "rejected": False,
                           "caution": "it SHOULD have been rejected"})
        except DenyListError as e:
            denied.append({"case": description, "rejected": True,
                           "rule": e.rule, "proof": e.proof})

    return {
        "checks": rows,
        "deny_list": denied,
        "summary": {
            "applied": sum(1 for r in rows if r["verdict"] == "applied"),
            "ignored": sum(1 for r in rows if r["verdict"] == "ignored"),
            "undetermined": sum(1 for r in rows
                                if r["verdict"] in ("undetermined", "suspect")),
        },
        "note": ("The trust-matrix verdicts were measured through an EARLIER collection "
                 "path. This table is measured against the direct REST API, and "
                 "differs from it on four points - see the header of preflight.py. "
                 "An untested filter is an untrusted filter."),
    }
