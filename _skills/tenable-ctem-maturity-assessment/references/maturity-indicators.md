# The 19 CTEM maturity indicators

Reference file for the `tenable-ctem-maturity-assessment` skill. A copy lives inside the package.

Each indicator carries its formula, the origin of its threshold and the default cutoffs.

> **Updated 2026-09-04.** The **API path** column of each table describes where the number comes
> from in the API. Collection is done by the **`tenable-ctem-mcp`** server, which returns each
> indicator already aggregated:
>
> | Stage | Tool | Indicators |
> |---|---|---|
> | Scoping | `ctem_scoping(mapping)` | S1–S4 |
> | Discovery | `ctem_discovery()` | D1–D4 |
> | Prioritization | `ctem_prioritization(mapping, customer_priority_cutoff)` | P1–P3 |
> | Validation | `ctem_validation(mapping)` | V1–V4 |
> | Mobilization | `ctem_mobilization(mapping)` | M1–M4 |
>
> **The formulas, the cutoffs and the threshold origins have not changed** — only who runs the
> query. The path column stays because it documents where each number comes from in the API, and
> because it explains the filter traps the server's deny-list now blocks.
>
> Three changes of substance, not merely of path:
> - **D4, V1, V2 and M3 come from a CENSUS by default**, not from a sample — see `mcp-preflight.md`;
> - **M4 no longer uses a CSV**: `ctem_mobilization` calls `mttr_collect` and already applies the
>   cadence guard;
> - **M1 receives the runs already collapsed** into distinct days, done on the server.

**Every indicator goes through the preflight, which is now one call: `ctem_preflight()`.**

## How to read the cutoffs

Four cutoff points produce the five stages:

```
Ad Hoc < c1 <= Defined < c2 <= Standardized < c3 <= Advanced < c4 <= Optimized
```

`inverted` means lower is better — days, latency, recurrence rate. In those cases the cutoff order
is decreasing and the comparison flips.

`informational` means the indicator does **not** enter the stage calculation. It enters as context,
because converting that number into maturity would require a premise the data does not support.

**Unit.** Every rate cutoff in this file is a **percentage** with whole numbers. The single
exception is `P3_opportunity`, which is a 0..1 **ratio** because it is a ratio and not a rate.
Comparing a percentage against a fractional cutoff drops an inverted indicator into the worst bucket
every time — a real defect found in V3 during the audit of 2026-09-04.

---

## Stage 1 — Scoping

Matching official criteria: **Asset Visibility** and **People | Process**.

| ID | Indicator | Formula | API path | Default cutoffs |
|---|---|---|---|---|
| S1 | % of assets with at least one tag | `assets(tag_count >= 1) / assets(total)` | assets search with the `tag_count >= 1` filter | 20 / 50 / 80 / 95 |
| S2 | % of assets with a criticality tag | `assets in the criticality category / total` | tag categories and values to find the category, then assets search by `tag_names` | 10 / 40 / 70 / 90 |
| S3 | % of assets with an owner tag | same, on the owner category | same | 10 / 40 / 70 / 90 |
| S4 | Declared Crown Jewels | a criticality category exists **and** >= 1 asset with `acr >= 9` | `acr` + tags | `informational` (gate) |

**How to identify the criticality and owner categories.** Do not assume the name. Look, without
regard to accent or case, for: criticidade, criticality, criticality tier, business criticality,
crown jewel, tier, importancia. For owner: owner, dono, responsavel, responsible, custodian, team,
squad, departamento, department, business unit, bu. The hint list stays multilingual on purpose:
the customer's tenant is often in the customer's language, and translating the hints would break
detection. If nothing matches, S2 and S3 become **gaps** and the report lists the categories that
exist, so the consultant can point at the right one.

**Finding from validation:** `tag_names` holds the tag VALUE, not "Category:Value".
`contains "Criticidade"` returns 0; `= ["Alta","Baixa","Crown Jewel","Media"]` returns 8. An array
of values has OR semantics and already deduplicates an asset carrying two tags of the same category.

**S4's structural gap, always declared:** the API does not expose whether the ACR was human-adjusted
or is Tenable's automatic value. So S4 measures the *declaration* of context, not *curation*. That
is why it is informational and does not score a stage.

---

## Stage 2 — Discovery

Official criteria: **Asset Visibility**, **Risk Detection** and **Data Consolidation**.

| ID | Indicator | Formula | API path | Default cutoffs (days) |
|---|---|---|---|---|
| D1 | Days since the last assessment | `today − Start time of the most recent run` | scan list + scan history of every scan with history | 90 / 45 / 14 / 7 · `inverted` |
| D2 | Coverage of the licensed surfaces | `distinct(exposure_classes) present / licensed surfaces` | assets search, one query per class with `limit=1` reading only the total | 25 / 50 / 75 / 90 (percentage) |
| D3 | % of assets with an agent | `active agents / assets(asset_class = DEVICE)` | agent list + assets search on `asset_class="DEVICE"` | 20 / 50 / 75 / 90 |
| D4 | % of the set detected by a local plugin | `plugins(Scan Type = local) / plugins in the set` | `plugin_details_batch` over the census or sample | 25 / 50 / 75 / 90 |

**On D1.** Do not use a date filter on findings — the relative operators are silently ignored, see
`mcp-preflight.md` section 1. Do not use `date_range` as an age: it is recency of last observation.
Scan history returns the real `Start time` per run and is the correct source.

**On D2, corrected 2026-09-02.** The cutoffs used to be an absolute count, which contradicted the
instruction to compare against what is licensed: a customer licensing only VM and WAS and covering
both would sit at Defined for having "only 2". It is now a percentage ratio.

Possible values of `exposure_classes`: `VM`, `WAS`, `CLOUD`, `IDENTITY`, `OT`, `AI`, `CODE`.
**Caution:** `asset_class` is not `exposure_classes`. In the sandbox there are assets with
`asset_class = IDENTITY`, but `exposure_classes = IDENTITY` returns zero — the identity assets are
in the inventory without carrying Identity Exposure findings. Always use `exposure_classes`.

**On D4.** A legitimate, declared proxy: a plugin of type `local` only returns a result with a valid
credential or an agent. It is not a reading of credential status. Do not use the workbenches
`authenticated` parameter — provably ignored.

---

## Stage 3 — Prioritization

Official criteria: **Prioritization** and **Scoring Methodology**.

| ID | Indicator | Formula | API path | Default cutoffs |
|---|---|---|---|---|
| P1 | % of the critical backlog on assets with business context | `findings(VPR >= 9 AND asset with criticality tag) / findings(VPR >= 9)` | findings search with `finding_vpr_score >= 9` combined with `tag_names` — the AND works, validated | 10 / 40 / 70 / 90 |
| P2 | % of the backlog with VPR available | `findings(finding_vpr_score >= 0.1) / findings(ACTIVE)` | findings search | 40 / 70 / 90 / 98 |
| P3 | Fitness of the prioritisation criterion | composite, see below | `finding_cvss3_base_score`, `finding_vpr_score` and the Step 0 answer | its own stage table |

**P1 was redefined on 2026-09-02, during the first real run.** The previous version was
`findings(VPR >= 9) / findings(CRITICAL)`, marked as inverted. That was wrong: the number is the
**agreement between two score models**, and it has no defensible direction of maturity — for the
same reason the VPR × CVSS delta has none. Worse, the direction assigned to it contradicted the
indicator's own reading note. The error surfaced on seeing the real value of 94.4% in the sandbox
and realising it would classify as Ad Hoc a tenant where the two models simply agree.

The new definition measures what prioritisation maturity actually is: **does business context reach
the decision layer?** Of all the backlog the queue treats as critical by VPR, how much sits on an
asset with declared criticality.

It differs from S2, and the difference is informative. S2 measures tag coverage over the whole
inventory; P1 measures coverage weighted by where the critical risk actually is. A customer with 27%
of assets tagged and 100% of the critical backlog on tagged assets **tagged the right assets** —
that is more mature than the reverse. It was exactly the case measured in the sandbox.

The agreement between the two score models stays in the report, now as a context number inside P3,
where it makes sense because it is crossed with the criterion the customer declares.

### P3 in detail — why the raw delta cannot score on its own

**The VPR × CVSS delta measures opportunity, not maturity.** A customer with a huge delta has a lot
to gain by switching criteria, but the size of the delta is a property of their environment's
vulnerability mix, not of their process. Promoting the raw number to a maturity indicator would
punish a customer for having an old Windows estate, which is not a process choice.

The delta becomes a maturity signal when **combined with the criterion the customer declares**,
collected in Question 10 of Step 0. Then the question stops being "how big is the delta" and becomes
"is the customer operating on the criterion that concentrates risk, and does their data support that
criterion".

**Measured part — the opportunity:**

```
customer_queue = findings above the declared cutoff (CONFIG.metric >= CONFIG.value)
vpr_queue      = findings(VPR >= CONFIG.value)
opportunity    = max(0, 1 − vpr_queue / customer_queue)
```

**Declared part:** `CONFIG.metric`, which is `vpr` or `cvss3`.

**P3's stage table:**

| Stage | Condition |
|---|---|
| 1 — Ad Hoc | the customer **does not know** which criterion they use ("I do not know" at Step 0) |
| 2 — Defined | uses CVSS and `opportunity >= 0.50` — half the immediate queue would leave on switching |
| 3 — Standardized | uses CVSS and `0.20 <= opportunity < 0.50` |
| 4 — Advanced | uses CVSS with `opportunity < 0.20` (the two models agree in this environment), **or** uses VPR with VPR coverage below 98% |
| 5 — Optimized | uses VPR **and** VPR coverage >= 98% (the value of P2) |

**The distinction between Advanced and Optimized is what gives the indicator meaning.** A customer
may say they prioritise by VPR while 40% of the backlog has no VPR computed — in that case the
criterion is not applicable to most of the queue, and the process is declared but not supported by
the data. That is why P3 depends on P2.

**A dependency to record:** P3 requires P2 computed. If P2 is a gap, P3 becomes a gap too.

### Which criterion to recommend — measured in the sandbox on 2026-09-03

The recommendation does **not** go into `customer_priority_cutoff`, which is descriptive. It goes
into the roadmap. And it is supported by measurement, not by preference:

| Queue | Findings | What it means |
|---|---|---|
| `CVSSv3 >= 7` | 3,377 | the immediate queue if the criterion is CVSS |
| `VPR >= 7` | 1,254 | the immediate queue if the criterion is VPR |
| overlap | 1,209 | the two criteria agree here |
| CVSS >= 7 only | 2,168 | what leaves the queue on switching to VPR |
| VPR >= 7 only | 45 | what **enters** the queue on switching to VPR |

Swapping CVSS >= 7 for VPR >= 7 in this tenant removes 2,168 items and adds 45 — a 63% smaller
queue, with 45 new items VPR considers relevant through threat activity and CVSS was not flagging.

**The expected objection, and the measured answer.** "VPR does not cover the whole backlog" is true:
P2 gave 81.6%. But the coverage that matters is that of the slice a CVSS criterion would select, and
there it is **98.1%** — 3,314 of the 3,377 findings with CVSS >= 7 have a VPR. The missing VPR is
concentrated in the low-severity backlog, which neither criterion puts in the immediate queue.
Measuring this before recommending is mandatory: in a tenant where coverage of the high slice is
low, the recommendation becomes composite — VPR as primary and CVSS or severity as a fallback rule
for the findings without VPR, plus an exception rule that pulls to the top anything in the CISA KEV
or with an available exploit, regardless of score.

**Collection detail:** `finding_vpr_score` with the `>=` operator **works** in the `filters` array
(3,314 with CVSS >= 7 and VPR >= 0.1). `exists` also works, as long as `value` is not empty — the
HTTP 400 comes from the missing value, not from the property. See `mcp-preflight.md`.

**Declare in the report**, next to the number: that the delta itself measures opportunity in the
environment and not customer behaviour, and that P3's stage comes from combining the declared
criterion with the measured opportunity. Without that sentence, the reader may conclude Tenable is
assessing their process from the backlog, which is not the case.

---

## Stage 4 — Validation

Official criterion: **Risk Detection**.

| ID | Indicator | Formula | API path | Default cutoffs |
|---|---|---|---|---|
| V1 | % of the set with an available exploit | `plugins(Exploit Available = True) / plugins in the set` | `plugin_details_batch` | `informational` |
| V2 | Median days in the CISA KEV | `median(today − min(CISA-KNOWN-EXPLOITED dates))` | `plugin_details_batch`, Cross References | 180 / 90 / 30 / 14 · `inverted` |
| V3 | Recurrence rate | `findings(RESURFACED) / findings(RESURFACED + FIXED)` | findings search, `state` property | 25% / 15% / 8% / 3% · `inverted` |
| V4 | % of DEVICE with out-of-support software | `DEVICE assets with an EOL finding / assets(asset_class = DEVICE)` | findings search on `finding_name contains "Unsupported Version Detection"` and `"SEoL"` | 30 / 15 / 7 / 2 · `inverted` |

**V1 is informational.** A high percentage of available exploits may indicate a bad backlog or
merely an environment built on a popular stack, which concentrates exploit research. Without a
customer premise, turning it into a stage would be interpretation.

**V2 is the strongest indicator of the set** and the only one with a citable external anchor: the 14-
and 30-day cutoffs derive from the remediation tiers of CISA BOD 26-04. State in the report that the
directive applies to US federal agencies and that here it is a recognised deadline reference, not a
regulatory obligation of the customer.

**V3 uses direct data.** `state = RESURFACED` is the record's state, not a computation. High
recurrence indicates a fix that does not hold — a reverted patch, an uncorrected base image,
reprovisioning from a vulnerable template.

**V3's unit, corrected 2026-09-04.** The cutoffs are `[25, 15, 8, 3]`, percentages, like every other
rate in this file. They used to be carried as `[0.25, 0.15, 0.08, 0.03]` while the collection
returns `18.0`; being inverted, the comparison put V3 in the worst bucket every time. It was latent
in the sandbox because V2 and V4 already bottomed out Validation, and it would have surfaced at the
first customer with low recurrence.

**V4's denominator, corrected 2026-09-02:** it is the `DEVICE` assets, not the total of assets. The
Tenable One inventory includes IDENTITY, ACCOUNT and GROUP, which have no software installed; using
them in the denominator dilutes the indicator. In the sandbox the difference was large: 7 of 30
assets gives 23%, and 7 of 8 DEVICE gives 87.5% — two stages apart.

**On V4.** `unsupported_by_vendor` exists in the API but is not reachable. The valid path is a text
search, which works: `finding_name contains` is a provably applied filter.

---

## Stage 5 — Mobilization

Official criteria: **Mobilization** and **Metrics | Reporting**.

| ID | Indicator | Formula | API path | Default cutoffs (days) |
|---|---|---|---|---|
| M1 | Median assessment cadence | `median of the interval between DISTINCT assessment DAYS` | scan history, collapsed by `scan_cadence` | 90 / 45 / 14 / 7 · `inverted` |
| M2 | Largest assessment gap | `largest interval between two consecutive assessment days` | scan history | 180 / 90 / 30 / 14 · `inverted` |
| M3 | Median age of the available fix | `median(today − plugin Published)` over the set | `plugin_details_batch` | 180 / 90 / 30 / 14 · `inverted` |
| M4 | Median MTTR to close | `min(stage(p50 Critical), stage(p50 High))` — see below | `mttr_collect`, over `POST /vulns/export` | Critical 90 / 30 / 15 / 7 · High 180 / 60 / 30 / 14 · `inverted` |

### M4 — the only indicator outside the Exposure Management API

**Source.** `mttr_collect`, called internally by `ctem_mobilization`. It hits `POST /vulns/export` in
the Vulnerability Management API and brings back `first_found`, `last_found`, `last_fixed` and the
`time_taken_to_fix` that Tenable itself computes in seconds.

**Why it does not come from the Exposure Management API.** `last_fixed` and `time_taken_to_fix` do
not exist among its 44 findings properties — it is not a missing wrapper. And the relative date
operators on findings search are accepted and silently ignored (revalidated 2026-09-03:
`state=FIXED` returned 50 findings, and `within last 1d` and `older than 3650d` returned the same
50; the comparison operators against an absolute date, however, are applied).

**Formula.** Per severity, the `p50` of `days_to_fix` over rows with `state=FIXED` and a value. Each
p50 becomes a stage through its cutoffs; **M4 is the lower of the two** — mature mobilisation closes
both severities, it does not offset one with the other.

**Cutoff origins**, labelled indicator by indicator as layer 3 requires:

| Cutoff | Critical | High | Origin |
|---|---|---|---|
| Optimized | <= 7 d | <= 14 d | CIS Controls v8 |
| Advanced | <= 15 d | <= 30 d | NIST SP 800-40 |
| Standardized | <= 30 d | <= 60 d | PCI DSS v4.0 |
| Defined | <= 90 d | <= 180 d | **a floor with no reference standard** — declare it as the skill's choice |
| Ad Hoc | above that | above that | — |

None of these thresholds is official Tenable, and none is the customer's SLA. When the operator
supplies an internal SLA at the corresponding Step 0 question, use theirs and switch the origin to
`customer_sla` in the report.

**Conditional.** M4 becomes a gap through the cadence guard, a timeout, a filter mismatch or too
small an `n`, and the scoring total drops from 17 to 16. The gates are in Step 2.M4 of SKILL.md and
are mandatory.

**The gate that matters most: scan cadence.** `time_taken_to_fix` measures detection to detection.
If `scan_cadence.pct_in_batch` is 40% or more, M4 becomes a **gap** — not a label. With cadence
dominating, M4 would measure the same thing as M1 and M2, counting cadence twice and calling
remediation maturity what is assessment maturity. The same principle that stopped P3 from scoring on
the raw delta.

In the first real sandbox collection, on 2026-09-03 (4,278 findings, 31 `FIXED` with a date), the
recount with a batch cutoff of 2 gives **93.5%**. And the structural finding: the 9
`(first_found, last_fixed)` windows are all pairs drawn from 7 dates, which are the tenant's scan
dates, with 29 of the 31 findings in a shared window — the MTTR there **is** the interval between
scans. M4 is a gap in this tenant either way.

**Method choices the server declares, and the skill must repeat.** States: the MTTR is computed over
`FIXED` only; including `REOPENED` the High mean falls from 60.39 to 49.66 days. Keep `FIXED` only —
a reopened finding was not fixed — and declare the exclusion with the count. Percentile: Critical's
`p90` is 101.43 interpolated and 92.91 by nearest position; use interpolated and name the method.
Batch cutoff: the same slice gives 93.5% with cutoff 2 and 38.7% with cutoff 5, and cutoff 5 would
pass a 40% guard, so the cutoff used goes written next to the percentage.

**`modified_severity`** comes from `severity_modification_type`, absent from the Exposure Management
API: it is the only direct measurement of recast and acceptance the assessment reaches. In the
sandbox collection all 4,278 rows came back `NONE` — no severity distorted by an exception. When
rows other than `NONE` appear, count per severity and declare it in S3, P1, P2 and M4.

**Filter mismatch: read `filters_diverged`**, never compare `requested_filters` with
`filters_applied_by_job`. The API normalises the severity and returns every date filter with value
0, so a literal comparison reports a mismatch on every run.

**M4 and M1/M2 measure different things, and both count.** MTTR asks how long it takes to close;
cadence asks whether anyone is looking. A customer can have an excellent MTTR over a tiny sample
because they barely assess — it is crossing M4 with M1 that reveals this, and the report must make
that crossing in prose when M4 scores Advanced or above with M1 at Ad Hoc.

**On M1, corrected 2026-09-03 during the acceptance run.** The previous formula was "median interval
between consecutive `completed` runs", and it is wrong: a scan relaunched minutes later is the
**same** assessment, not a new cadence cycle. In the sandbox, the recurring scan's 12 runs include
four same-day pairs, and the median of the 11 raw intervals gave **1.42 days** — a number with no
meaning for a tenant that assessed on 9 days across 12 months. Collapsing the runs into **distinct
assessment days** (9 days), the intervals are 140, 40, 2, 89, 1, 1, 85 and 1 days, and the median is
**21 days** — Standardized instead of Optimized, two stages apart.
`CONFIG.cutoffs.collapse_same_day_runs` controls this and defaults to `true`; disabling it requires
declaring it in the report. The collapse happens on the server, never on the client — it was exactly
because it lived on the client that the error survived a whole run.

M2 does not change: the largest interval is the same with or without the collapse.

**On the census for D4 and M3, corrected 2026-09-04.** The original plan was a census through
`plugins_search_plugins` instead of a sample, and on 2026-09-03 that was recorded as unreachable:
that tool accepts `query` (a keyword) and `cve`, not a list of plugin IDs. `plugin_details_batch`
does accept a list of IDs, so the constraint fell away and the **census became the default** — 121
critical plugins cost 64 s and ~5,400 tokens. Above `census_limit` (300) it falls back to the
stratified sample, and the report declares which mode was used.

**On M3.** `Published` is the publication date of the detection plugin, not the vendor's patch — a
difference of days. Label it in the report as a declared proxy. `patch_publication_date` **is**
reachable through the direct API, but `plugin_details_batch` exposes five fields by a closed rule;
swapping the proxy for the real datum is a skill decision, not a server one.

---

## Mapping to the eight official criteria

The skill reports each indicator bound to one of the eight criteria of Tenable's official
assessment, so the result is comparable to an assessment the customer may already have answered.

| # | Official Tenable criterion | Skill indicators |
|---|---|---|
| 1 | Asset Visibility | S1, D1, D2, D3 |
| 2 | Prioritization | P1, P3 |
| 3 | Risk Detection | D4, V1, V2, V4 |
| 4 | People \| Process | S2, S3, S4 |
| 5 | Data Consolidation | D2 |
| 6 | Mobilization | M1, M2, M3, M4 |
| 7 | Scoring Methodology | P2 |
| 8 | Metrics \| Reporting | V3, M2 |

Source of the eight criteria: Tenable Exposure Management Maturity Assessment,
https://assess.tenable.com/exposure-management-maturity-assessment

---

## Official bands, fixed, not configurable

They go cited in the report and do not enter the threshold block.

| Metric | Scale | Official bands |
|---|---|---|
| CES | 0–1000 | High 650–1000 · Medium 350–649 · Low 0–349 |
| AES | 0–1000 | High 650–1000 · Medium 350–649 · Low 0–349 |
| ACR | 1–10 | Critical 9–10 · High 7–8 · Medium 4–6 · Low 1–3 |
| VPR | 0.1–10.0 | Critical 9.0–10.0 · High 7.0–8.9 · Medium 4.0–6.9 · Low 0.1–3.9 |

Official observations to reproduce: assets unobserved for more than 90 days are excluded from the
CES calculation, and the AES is not computed for an unlicensed asset.
Source: https://docs.tenable.com/exposure-management/Content/getting-started/metrics.htm

---

## What is NOT official

**No official Tenable material publishes a numeric threshold per maturity stage.** The Exposure
Management Maturity Model is qualitative: it describes capabilities per stage. The official
assessment classifies through declarative answers across eight criteria, with no published score
bands.

Therefore every cutoff in this file, except those of V2 and the ones derived from CISA BOD 26-04, is
the **skill's criterion**. The report is required to label them as such, indicator by indicator.
Nailing a percentage down as if it were a Tenable criterion would be inaccurate.
