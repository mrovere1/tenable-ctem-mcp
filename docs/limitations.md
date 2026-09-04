# Limitations — what the API does not deliver, with proof

Every line here was measured against the laboratory tenant, not presumed.
Source: `_docs/matriz-confianca-filtros-mcp.md`.

> **One path, one set of verdicts.** The source matrix was measured **through Tenable's official
> MCP**; this server talks **straight to the REST API**. Where the two disagree, the direct-API
> reading below is the one that holds here, and `ctem_preflight()` re-runs everything against the
> tenant of the moment, which is the final authority. Each section states which path it describes.

---

## Filters accepted and silently ignored

The worst kind of failure: the query looks filtered, returns the total of the whole corpus, and the
number travels into the report as if it were the result of the filter. **There is no signal that it
happened.**

| Filter | Proof | Path |
|---|---|---|
| dates on findings — the **relative** operators `within last`, `older than`, `newer than` | `older than 3650d` returned 1840, the whole corpus, the same as `within last 1d`. Revalidated 2026-09-03 with 50 `FIXED` | both |
| `authenticated` in workbenches | `true` → 20 and `false` → 20, identical results | both |
| `exploitable` in workbenches | `true` → 20, including a Mozilla Firefox SEoL and a Spectre check, which have no public exploit | both |
| `resolvable` in workbenches | `true` → 121 and `false` → 121 with severity=critical. Was "presumed ignored"; now proven | direct API |
| `age` in workbenches | not a parameter of this API at all. The real name is `date_range` | direct API |
| `filters` received as a string | `"tag_count >= 1"` → 30 assets of the corpus; as a JSON array → 9 | both |

The server rejects all of them before the request leaves.

## Date comparison against an absolute date works

**This corrects the matrix, which denied date filters on findings wholesale.** The relative
operators are ignored, but the comparison ones are applied: `< 2020-01-01` gives 0 and
`>= 2020-01-01` gives 50, and the two sum to the corpus's 50 `FIXED` findings. That is the
definition of an applied filter.

It does **not** reopen MTTR: `last_fixed` and `time_taken_to_fix` remain absent from the 44 findings
properties, so a working date filter has nothing to filter on.

## `exists` works, as long as `value` is not empty

**This corrects the matrix**, which recorded that `exists` on `finding_vpr_score` answers HTTP 400
and concluded the property does not support the operator. The 400 comes from an empty `value`, and
the API message is literally *"Missing value in filter"*.

*Proof:* with `value=["true"]`, `exists` → 4,462 and `not exists` → 1,024, summing to the 5,486 of
the corpus.

The `>= 0.1` path is valid on both paths and monotonic: 0.1 → 4,462 · 7.0 → 1,254 · 9.0 → 586.

## `age` is not age, and on the direct API it is not a parameter

Through the official MCP, `age` filters by **recency of last observation**, not by the finding's
age. The sandbox's last scan was 84 days before collection, and the cutoff fell between `age=80`
(zero) and `age=90` (20) — on the date of the last scan, not on the discovery date, which ranges
from 2018 to 2026.

On the direct API `age` is not a parameter at all; the real name is `date_range`, and it is applied
(1 → 17, 30 → 118, 90 → 121). A non-existent parameter is silently discarded — the worst case,
because the query looks filtered and returns the corpus.

**Consequence:** `date_range` serves for data freshness and scan coverage. A skill that uses either
name as "days open" produces a wrong number.

## What the Exposure Management API does not have

`last_fixed`, `time_taken_to_fix` and `severity_modification_type` **do not exist** in the Exposure
Management API. It is not a missing wrapper: they are fields of the Vulnerability Management API,
reachable only through `POST /vulns/export`. That is why `mttr_collect` exists.

## A plugin census is not reachable **by search** — but it is by batch

`plugins_search_plugins` accepts a keyword and a CVE, **not** a list of plugin IDs. That is why
`census_d4_m3` became `false` on 2026-09-03.

**That conclusion holds for the search, not for the census.** `plugin_details_batch` takes a list of
IDs, and the sampling frame comes from `GET /workbenches/vulnerabilities`, which returns every
plugin of the severity in one call — 121 critical in the sandbox. Putting the two together, **the
census is reachable**: 121 calls, 64 s, ~5,400 tokens.

That is why `plugin_mode` defaults to `auto`, running a census when the population fits within
`census_limit` and falling back to a sample above it. The census eliminates the confidence interval,
the weighting base and the allocation bias — see `docs/tools.md`.

**Sampling still exists**, and it is not legacy: a large tenant may have thousands of critical
plugins, and at 528 ms per plugin, a thousand plugins are nine minutes.

## Index propagation after a tag write

The inventory index takes time to reflect a write. Seconds after applying a tag, a search for it
returned empty while the tagging API had already confirmed success; about fifteen minutes later it
started working.

**Never validate a write by reading the index immediately**, and never conclude a filter is broken
based on a read taken right after a write.

---

## What the direct API reaches and the official MCP did not

Measured on 2026-09-03, while porting the queries to the REST API. **None of these items changes an
indicator formula on its own** — each change is a skill decision, and it is listed here to be
decided, not applied in silence.

| Item | Status through the official MCP | Status through the direct API |
|---|---|---|
| `patch_publication_date` | "not reachable" | **available** in `GET /plugins/plugin/{id}` |

**Why it matters.** M3 measures "median age of the available fix" and today uses `published` — the
publication date of the *detection plugin* — as a **declared proxy**, because the vendor's patch
date was unreachable. It no longer is.

In the sandbox the two dates coincide on most plugins of the set, but not on all: plugin 294870 has
`published = 2026/01/21` and `patch_publication_date = 2026/01/20`.

**Not applied.** `plugin_details_batch` exposes five fields, and that is a closed project rule
because of the token saving. Swapping M3's proxy for the real datum is a skill decision, and it
costs one extra field in the batch.

---

## Indicators that depend on a sample cannot be reproduced by number

**V1 and V2 have no golden test against the value published in the execution document**, and the
reason is methodological, not a server problem: both are estimated over a stratified sample, and
that run's sample is not recoverable.

Investigating the divergence surfaced an inconsistency in the document itself. It publishes
**V1 = 59.6%** with its own sample (stratum A 11/12, stratum B 1/8) and narrates a population of
**65/35**. Those two facts do not close:

| Reconstruction | Result |
|---|---|
| `share_A = 0.65`, weighted by plugin | **64.0%** |
| `share_A = 0.595`, weighted by plugin | **59.6%** ✅ |
| `share_A = 0.595`, weighted by detection | 62.7% |

The published number only reconstructs with **weighting by plugin** and a population share of
0.595 — which is what is measured today, not what is narrated. Two consequences:

1. **That run's weight base was `by_plugin`**, not the `by_detection` the skill's configuration
   block carries as the default. The choice changes the number: on the sandbox's same n=20 sample,
   V1 gives **59.3%** by detection and **54.6%** by plugin.
2. **A weighted rate without a declared base is not verifiable.** That is why `ctem_validation` and
   `ctem_discovery` accept `weight_by` and return `weight_base` in the context.

What the repository tests is the **method**, over the fixture, with a fixed seed — reproducible
across runs and auditable.

## VPR counts fluctuate; CVSS and state counts do not

Comparing the 2026-09-03 collection with the one recorded in the document for the same day:

| Measure | Document | Measured | |
|---|---|---|---|
| corpus · ACTIVE · RESURFACED · FIXED | 5,486 · 5,425 · 11 · 50 | identical | stable |
| CVSS3 >= 7 | 3,377 | 3,377 | stable |
| CVSS3 >= 7 **and** VPR >= 0.1 | 3,314 | 3,314 | stable |
| VPR >= 0.1 | 4,462 | 4,462 | stable |
| **VPR >= 9** | 586 | **579** | fluctuates |
| **VPR >= 7** | 1,254 | **1,261** | fluctuates |
| **overlap CVSS>=7 ∧ VPR>=7** | 1,209 | **1,210** | fluctuates |

**Cause:** the VPR is recomputed by Tenable from threat activity, and findings cross the cutoff in
both directions. Everything that does not depend on a VPR threshold matched exactly.

**Consequence for the tests:** a VPR count at a threshold is no golden test against live data — only
against the fixture. What is tested live is **monotonicity** (0.1 > 7.0 > 9.0), which is what proves
the filter is being applied.

**Consequence for the assessment:** P1 stayed at 100% and the sum identity kept closing
(87 + 492 = 579), so the indicator did not change. It is worth declaring the collection date next to
the critical backlog number, because it is not reproducible a week later.

---

## Summary of the four verdicts that change on the direct API

`_docs/matriz-confianca-filtros-mcp.md` was measured **through the official MCP**. This server talks
straight to the REST API, and there four verdicts are different. **The matrix is not wrong** — it
describes its own path. Running `ctem_preflight()` re-runs everything and is the source for this one.

1. **A date filter on findings is not ignored wholesale.** The relative operators are ignored; the
   comparison ones are applied.
2. **`exists` on `finding_vpr_score` works.** The HTTP 400 comes from an empty `value`.
3. **`resolvable` is proven ignored**, not merely presumed: `true` → 121, `false` → 121.
4. **`age` is not a parameter of this API.** The real name is `date_range`, and it is applied.

**This does not reopen MTTR.** `last_fixed` and `time_taken_to_fix` remain absent from the 44
findings properties of the Exposure Management API. `mttr_collect` through `POST /vulns/export`
remains the only path.
