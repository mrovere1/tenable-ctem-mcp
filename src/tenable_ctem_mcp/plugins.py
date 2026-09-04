"""Plugin primitives: batch details, census and stratified sampling.

`plugin_details_batch` is the biggest token win of the project. The full detail
of one plugin is ~8,200 characters (97 attributes: description, CVE list,
synopsis, solution). The skill uses FIVE fields. Twenty plugins the full way are
~164,000 characters; through the five fields, ~1,500 tokens.

DO NOT EXPOSE EXTRA FIELDS HERE. The saving depends on it, and it is a closed rule.

A census by search does not exist: `plugins_search_plugins` accepts a keyword and
a CVE, not a list of IDs. The right sampling frame is
GET /workbenches/vulnerabilities, which returns plugin, detection count, VPR and
family for every plugin of that severity in a single call - 121 critical plugins
in the sandbox.
"""

from __future__ import annotations

import math
import random
from typing import Any

from .client import CACHE, call
from .preflight import validate_workbenches_params

SEVERITIES = ("info", "low", "medium", "high", "critical")

# Fixed seed: the sample must be reproducible across runs, otherwise the same
# tenant scores differently every round and the golden test cannot exist.
SAMPLE_SEED = 20260903


# ----------------------------------------------------------------------------
# Batch detail - five fields, never more
# ----------------------------------------------------------------------------

def _five_fields(raw: dict) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "plugin_id": raw.get("id"),
        "scan_type": None,        # local or remote
        "published": None,        # plugin publication date
        "exploit_available": None,
        "exploitability": None,
        "cisa_known_exploited": [],
    }
    for a in raw.get("attributes") or []:
        name = a.get("attribute_name")
        value = a.get("attribute_value")
        if name == "plugin_type":
            fields["scan_type"] = value
        elif name == "plugin_publication_date":
            fields["published"] = value
        elif name == "exploit_available":
            fields["exploit_available"] = str(value).lower() == "true"
        elif name == "exploitability_ease":
            fields["exploitability"] = value
        elif name == "xref" and str(value).startswith("CISA-KNOWN-EXPLOITED:"):
            fields["cisa_known_exploited"].append(str(value).split(":", 1)[1])
    return fields


def plugin_details_batch(plugin_ids: list[int]) -> dict[str, Any]:
    """Detail of N plugins in one client call, with only five fields.

    The server makes N requests to the API - the win is in MCP transport tokens,
    not in requests against Tenable. A plugin that fails goes into `gaps` with
    its cause; the others continue. A silent partial number is forbidden, but a
    DECLARED partial result is legitimate.
    """
    items: list[dict] = []
    gaps: list[dict] = []
    for pid in plugin_ids:
        key = f"plugin_details/{pid}"
        found, value = CACHE.get(key)
        if found:
            items.append(value)
            continue
        try:
            raw = call("GET", f"/plugins/plugin/{pid}")
        except Exception as e:  # noqa: BLE001
            gaps.append({"plugin_id": pid, "cause": str(e)[:200]})
            continue
        fields = _five_fields(raw)
        CACHE.set(key, fields)
        items.append(fields)
    return {"plugins": items, "gaps": gaps,
            "n_requested": len(plugin_ids), "n_resolved": len(items)}


# ----------------------------------------------------------------------------
# Census - the sampling frame
# ----------------------------------------------------------------------------

def plugin_census(severity: str = "critical") -> dict[str, Any]:
    """Sampling frame: plugin, detection count, VPR and family.

    One call, cached with a short TTL. It is the denominator of D4, M3, V1 and V2.
    """
    sev = str(severity).lower()
    if sev not in SEVERITIES:
        raise ValueError(f"invalid severity: {severity!r}. Use one of {SEVERITIES}.")

    key = f"plugin_census/{sev}"
    found, value = CACHE.get(key)
    if found:
        return dict(value, served_from_cache=True)

    params = validate_workbenches_params({"severity": sev})
    resp = call("GET", "/workbenches/vulnerabilities", params={
        "filter.0.filter": "severity",
        "filter.0.quality": "eq",
        "filter.0.value": params["severity"],
        "filter.search_type": "and",
    })
    vs = resp.get("vulnerabilities") or []
    plugins = [{
        "plugin_id": v.get("plugin_id"),
        "plugin_name": v.get("plugin_name"),
        "family": v.get("plugin_family"),
        "count": v.get("count"),
        "vpr": (v.get("vpr_score") if isinstance(v.get("vpr_score"), (int, float))
                else None),
    } for v in vs]

    census = {
        "severity": sev,
        "distinct_plugins": len(plugins),
        "detections": sum(p["count"] or 0 for p in plugins),
        "plugins": plugins,
        "literal_filter": f"workbenches/vulnerabilities severity={sev}",
        "served_from_cache": False,
    }
    CACHE.set(key, census)
    return census


# ----------------------------------------------------------------------------
# Stratified sampling - proportional allocation, stratum B floor, weighting by
# detection, and the Wilson interval.
# Rules in _skills/.../references/mcp-preflight.md section 4.
# ----------------------------------------------------------------------------

def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% CI of a proportion by the Wilson method.

    With n=10 the interval is ~50 points wide - useless for separating stages.
    That is why the confidence gate exists.
    """
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def stratified_sample(plugins: list[dict], n: int = 30,
                      vpr_cutoff: float = 7.0,
                      stratum_b_floor: int = 4) -> dict[str, Any]:
    """Sample stratified by VPR, with allocation PROPORTIONAL to the population.

    The mistake this function exists in order not to repeat: on the first real
    run the sample was allocated 60/40 by design decision while the population
    was 65/35. It came out nearly right by coincidence. In a tenant where
    stratum B is 10% of the population, a 40% allocation would bias it badly.

    The stratum B floor is deliberate: stratum B does not exist to estimate a
    rate, it exists to FIND cases of under-prioritisation. When the floor kicks
    in, the stratum is over-represented on purpose - and weighting by population
    is what keeps that from contaminating the rates.
    """
    a = [p for p in plugins if (p.get("vpr") or 0) >= vpr_cutoff]
    b = [p for p in plugins if (p.get("vpr") or 0) < vpr_cutoff]
    total = len(plugins)
    if total == 0:
        return {"sample": [], "strata": {}, "n": 0}

    det_a = sum(p.get("count") or 0 for p in a)
    det_b = sum(p.get("count") or 0 for p in b)
    det_total = det_a + det_b

    share_a = len(a) / total
    n = min(n, total)
    n_a = round(n * share_a)
    n_b = n - n_a
    if b and n_b < stratum_b_floor:
        n_b = min(stratum_b_floor, len(b))
        n_a = min(n - n_b, len(a))
    n_a = min(n_a, len(a))
    n_b = min(n_b, len(b))

    rng = random.Random(SAMPLE_SEED)
    s_a = rng.sample(a, n_a) if n_a else []
    s_b = rng.sample(b, n_b) if n_b else []
    for p in s_a:
        p["stratum"] = "A"
    for p in s_b:
        p["stratum"] = "B"

    return {
        "sample": s_a + s_b,
        "n": n_a + n_b,
        "strata": {
            "A": {"population": len(a), "sample": n_a,
                  "share_by_plugin": share_a,
                  "share_by_detection": (det_a / det_total) if det_total else 0.0},
            "B": {"population": len(b), "sample": n_b,
                  "share_by_plugin": 1 - share_a,
                  "share_by_detection": (det_b / det_total) if det_total else 0.0},
        },
        "vpr_cutoff": vpr_cutoff,
        "stratum_b_floor_triggered": bool(b) and n_b == stratum_b_floor,
        "seed": SAMPLE_SEED,
    }


def weighted_rate(sample: list[dict], details: dict[int, dict],
                  predicate, strata: dict, base: str = "by_detection"
                  ) -> dict[str, Any]:
    """Estimates within each stratum and combines by the POPULATION weights.

    Never compute the rate over the whole mixed sample: the strata carry
    different weight in the population, and the stratum B floor over-represents
    B on purpose.
    """
    weight_key = "share_by_detection" if base == "by_detection" else "share_by_plugin"
    by_stratum: dict[str, dict] = {}
    for name in ("A", "B"):
        of_stratum = [p for p in sample if p.get("stratum") == name]
        seen = [details[p["plugin_id"]] for p in of_stratum
                if p["plugin_id"] in details]
        successes = sum(1 for d in seen if predicate(d))
        n = len(seen)
        by_stratum[name] = {
            "n": n, "successes": successes,
            "rate": (successes / n) if n else None,
            "ci95": wilson(successes, n) if n else None,
            "weight": strata.get(name, {}).get(weight_key, 0.0),
        }
    combined = sum((s["rate"] or 0) * s["weight"] for s in by_stratum.values())
    n_total = sum(s["n"] for s in by_stratum.values())
    succ_total = sum(s["successes"] for s in by_stratum.values())
    return {
        "weighted_rate": combined,
        "by_stratum": by_stratum,
        "n": n_total,
        "ci95_whole_sample": wilson(succ_total, n_total),
        "weight_base": base,
    }


# Above this number of plugins the census gets too expensive and the sample
# comes back. The number comes from measurement: 121 plugins take 64 s and
# ~5,400 output tokens (528 ms per plugin, sequential). 300 keeps the worst case
# at ~2.6 min and ~13,000 tokens - still below what TWENTY plugins cost when
# every attribute travels. Parallelising the calls is the lever for raising this.
CENSUS_LIMIT = 300


def sample_with_details(n: int = 30, vpr_cutoff: float = 7.0,
                        severity: str = "critical",
                        census_limit: int = CENSUS_LIMIT,
                        mode: str = "auto") -> dict[str, Any]:
    """Five-field detail for ALL plugins, or for a sample.

    It exists so that D4, V1, V2 and M3 speak of the SAME set. If each indicator
    drew its own, the report would describe four different samples under a
    single declared size - and the published interval would hold for none of them.

    `mode`:
      auto     census if it fits in `census_limit`, otherwise sample (default)
      census   force the census, whatever it costs
      sample   force the stratified sample

    WHY THE CENSUS IS THE DEFAULT NOW. Sampling existed because
    `plugins_search_plugins` accepts a keyword and a CVE, not a list of IDs -
    that is why `census_d4_m3` became false on 2026-09-03. `plugin_details_batch`
    does accept a list of IDs, so the constraint fell away.

    The census eliminates in one move four sources of imprecision the sample
    forced us to manage: the Wilson gate, the weighting base (by_detection versus
    by_plugin moved V1 by 5 points on its own), the allocation bias between
    strata, and the irreproducibility that kept V1, V2 and M3 from having a
    golden test. Measured on the sandbox's 121 critical plugins: the n=30 sample
    gave V1 62.7% and the census gave 61.2% - the sample was right, but you only
    know that by HAVING the census.
    """
    key = f"set/{severity}/{n}/{vpr_cutoff}/{mode}/{census_limit}"
    found, value = CACHE.get(key)
    if found:
        return value

    census = plugin_census(severity)
    everything = census["plugins"]
    do_census = (mode == "census"
                 or (mode == "auto" and len(everything) <= census_limit))

    if do_census:
        for p in everything:
            p["stratum"] = "census"
        selection = {
            "mode": "census",
            "sample": everything,
            "n": len(everything),
            "population": len(everything),
            "strata": {"census": {"population": len(everything),
                                  "sample": len(everything),
                                  "share_by_plugin": 1.0,
                                  "share_by_detection": 1.0}},
            "vpr_cutoff": vpr_cutoff,
            "stratum_b_floor_triggered": False,
            "seed": None,
            "note": ("Census: every plugin of the severity. There is no confidence "
                     "interval because there is no inference - the rate is the rate."),
        }
    else:
        selection = stratified_sample(everything, n=n, vpr_cutoff=vpr_cutoff)
        selection["mode"] = "sample"
        selection["population"] = len(everything)
        selection["note"] = (
            f"Sample: the population has {len(everything)} plugins, above the "
            f"census limit of {census_limit}. Rates are estimates, with a Wilson "
            "interval per stratum and for the whole set.")

    batch = plugin_details_batch([p["plugin_id"] for p in selection["sample"]])
    package = {
        "census": census,
        "sample": selection,
        "details": {d["plugin_id"]: d for d in batch["plugins"]},
        "gaps": batch["gaps"],
    }
    CACHE.set(key, package)
    return package


def rate(selection: dict, details: dict, predicate, base: str = "by_detection"
         ) -> dict[str, Any]:
    """Exact rate under a census; weighted with a Wilson CI under a sample.

    Under a census there is nothing to weight and nothing to infer: the rate is
    the count. The `weight_base` field comes back as `not_applicable`, rather
    than a label suggesting a method choice was made where none was.
    """
    if selection.get("mode") == "census":
        seen = [details[p["plugin_id"]] for p in selection["sample"]
                if p["plugin_id"] in details]
        successes = sum(1 for d in seen if predicate(d))
        n = len(seen)
        return {
            "mode": "census",
            "weighted_rate": (successes / n) if n else None,
            "n": n, "successes": successes,
            "by_stratum": {"census": {"n": n, "successes": successes,
                                      "rate": (successes / n) if n else None,
                                      "ci95": None, "weight": 1.0}},
            "ci95_whole_sample": None,
            "weight_base": "not_applicable",
            "note": "Census: exact rate, no confidence interval.",
        }
    r = weighted_rate(selection["sample"], details, predicate,
                      selection["strata"], base=base)
    r["mode"] = "sample"
    return r
