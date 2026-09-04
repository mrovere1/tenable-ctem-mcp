# Tool contract

Thirteen tools in total: five per CTEM stage, two for discovery and preflight, five primitives, and
one diagnostic.

| Group | Tools |
|---|---|
| Discovery and preflight | `ctem_discover_tenant`, `ctem_preflight` |
| Indicators by stage | `ctem_scoping`, `ctem_discovery`, `ctem_prioritization`, `ctem_validation`, `ctem_mobilization` |
| Primitives | `plugin_details_batch`, `plugin_census`, `scan_cadence`, `mttr_collect`, `mttr_cadence_guard` |
| Diagnostic | `ctem_diagnostics` |

## Return envelope

Every indicator, in every tool, returns this envelope. It never deviates.

```json
{
  "indicator": "M1",
  "value": 21.0,
  "n": 12,
  "literal_filter": "scan_ids=['abc','def'], runs collapsed into 5 distinct days",
  "collected_at_utc": "2026-09-03T14:22:00Z",
  "preflight_verdict": "ok"
}
```

If the query fails, `value` is `null`, `gap` is `true` and `cause` is filled in.
**A silent partial number is forbidden.**

`preflight_verdict` takes: `ok`, `applied`, `ignored`, `undetermined`, `empty_corpus`,
`not_applicable`.

The stage tools return `{"indicators": [ <envelope>, ... ]}`.

## Errors

An error is never a stack trace nor a raw exception. Format:

```json
{"error": "collection_failure", "cause": "credential_invalid",
 "detail": "...", "gap": true, "collected_at_utc": "..."}
```

A filter denied by the deny-list:

```json
{"error": "filter_denied", "rule": "filters_must_be_json_array",
 "detail": "...", "proof": "...", "gap": true}
```

The `proof` is the measurement that supports the rule — whoever reads the error sees why the filter
was refused.

---

## `ctem_discover_tenant(use_cache: bool = True)`

A snapshot of the tenant in one call. Replaces ~10 calls of Phase A of the skill's Step 0.

**Returns:**

| Field | Content |
|---|---|
| `tags` | the `count` of categories and, in `categories`, the values of each |
| `assets` | `total` and `by_asset_class` |
| `exposure_classes` | the total per class: `VM`, `WAS`, `CLOUD`, `IDENTITY`, `OT`, `AI`, `CODE` |
| `scans` | `total_scans`, `with_history`, and per scan: `runs` and `runs_completed` |
| `agents` | `total`, `active`, `by_status` |
| `served_from_cache` | `true` when it came from the short-TTL cache |

**CAUTION:** `asset_class` is not `exposure_classes`. A tenant may have assets with
`asset_class = IDENTITY` and `exposure_classes = IDENTITY` at zero. D2 uses `exposure_classes`.

The scan history is paginated internally. Without that, a recurring scan with many runs comes back
truncated at the page size — measured in the sandbox, scan 13 has 242 runs and a single `limit=200`
call reported 200.

---

## `ctem_diagnostics()`

Says whether the server can talk to the tenant, without collecting a single indicator. It separates
three causes that look identical from the client: credential missing, credential invalid, and TLS
intercepted by a corporate proxy.

It never prints the key, nor any part of it. Returns `version`, `tio_url`,
`credentials_in_environment`, `tls_ca_origin` and `verdict`.

---

## `ctem_preflight(workbenches_severity="critical")`

The finished PREFLIGHT table: every filter the skill uses, tested **live** against the tenant. No
verdict is inherited from a document.

Three forms of proof:

| Kind | What it does |
|---|---|
| `exclusive_pair` | two mutually exclusive queries whose totals must sum to the corpus. The strongest form — "it reduced" is not enough, a filter can reduce by accident |
| `boolean` | `true` and `false`; equal totals mean the parameter is ignored |
| `monotonic` | a ladder of cutoffs that must be strictly decreasing |

Returns `checks` (one row per filter, with `verdict`, `detail` and `use`), `deny_list` (what the
server rejects before the request leaves, with rule and proof) and `summary`.

### The four corrections this preflight found

The trust matrix was measured through Tenable's **official MCP**. This server talks straight to the
REST API, and on four points the behaviour differs. The matrix is not wrong — it describes its own
path.

1. **A date filter on findings is not ignored wholesale.** The relative operators (`within last`,
   `older than`, `newer than`) are ignored; the comparison ones (`<`, `>=`) are applied.
   *Proof:* `older than 3650d` → 50 and `within last 1d` → 50, mutually exclusive and both with the
   whole corpus; but `< 2020-01-01` → 0 and `>= 2020-01-01` → 50, which sum to 50.
2. **`exists` on `finding_vpr_score` works.** The HTTP 400 comes from an empty `value`, and the
   message is *"Missing value in filter"*. *Proof:* `exists` → 4,462 and `not exists` → 1,024,
   summing to 5,486.
3. **`resolvable` is proven ignored**, not merely presumed: `true` → 121, `false` → 121.
4. **`age` is not a parameter of this API.** The real name is `date_range`, and it is applied
   (1 → 17, 30 → 118, 90 → 121). `age` is silently discarded — the worst case.

---

## `ctem_scoping(mapping, indicators=None)`

Stage 1: S1, S2, S3, S4.

`mapping` is mandatory and explicit:

```json
{"criticality_category": "Criticidade", "owner_category": "Owner"}
```

Without it, S2 and S3 become gaps and the cause lists the categories that exist in the tenant. The
server does not guess the name — a customer may call it `Tier`, `BIA` or `Business Impact`.

| ID | What it measures | Note |
|---|---|---|
| S1 | % of assets with at least one tag | |
| S2 | % with a criticality tag | needs `criticality_category` |
| S3 | % with an owner tag | needs `owner_category` |
| S4 | declared Crown Jewels | **informational**, does not score a stage |

`tag_names` holds the tag VALUE, not "Category:Value". An array of values has OR semantics and
already deduplicates an asset carrying two tags of the same category.

---

## `ctem_discovery(indicators=None, licensed_surfaces=None, sample_vpr_cutoff=7.0, sample_n=30, plugin_mode="auto", census_limit=300)`

Stage 2: D1, D2, D3, D4.

| ID | What it measures | Note |
|---|---|---|
| D1 | days since the last assessment | inverted. Source: scan history, never a date filter on findings |
| D2 | % of licensed surfaces covered | pass `licensed_surfaces` (default `["VM"]`). A percentage ratio, not a count |
| D3 | % of DEVICE assets with an agent | the denominator is DEVICE, not the total |
| D4 | % of the set detected by a local plugin | uses `plugin_details_batch` internally |

`indicators=["D1","D3"]` avoids the plugin calls D4 would require.

---

## `ctem_prioritization(mapping, indicators=None, customer_priority_cutoff=None, p2_value=None)`

Stage 3: P1, P2, P3, plus the three compared queues.

| ID | What it measures | Note |
|---|---|---|
| P1 | % of the VPR >= 9 backlog on assets with declared criticality | NOT the agreement between score models |
| P2 | % of the ACTIVE backlog with VPR available | `>= 0.1`; `exists` needs a non-empty value |
| P3 | fitness of the prioritisation criterion | composite; depends on P2 |

`customer_priority_cutoff = {"metric": "vpr"|"cvss3", "value": 7.0, "confirmed": bool}`.
With no declared metric, **P3 is a gap, not a number**: "the customer does not know which criterion
they use" is the Ad Hoc stage itself, and classifying that is the skill's job.

P3's context carries `queues` with `cvss3_gte_cutoff`, `vpr_gte_cutoff`, `overlap`, `cvss_only`,
`vpr_only` and `vpr_coverage_in_high_slice_pct` — which is the coverage that supports a
recommendation to change criterion, not that of the whole backlog.

---

## `ctem_validation(mapping=None, indicators=None, sample_vpr_cutoff=7.0, sample_n=30, weight_by="by_detection", plugin_mode="auto", census_limit=300)`

Stage 4: V1, V2, V3, V4.

| ID | What it measures | Note |
|---|---|---|
| V1 | % of the set with an available exploit | **informational**, does not score |
| V2 | median days in the CISA KEV | inverted; cutoffs anchored in CISA BOD 26-04 |
| V3 | recurrence rate RESURFACED/(RESURFACED+FIXED) | inverted. Returned as a **percentage** — the skill's cutoffs are `[25, 15, 8, 3]` |
| V4 | % of DEVICE with out-of-support software | inverted; the denominator is DEVICE |

V1 and V2 come from the **same set** as D4, so the report does not describe three different sets
under a single declared size.

---

## `ctem_mobilization(mapping=None, indicators=None, ..., mttr_days=180, mttr_max_wait_s=240, mttr_export_uuid=None, batch_cutoff=2, max_batch_pct=40.0)`

Stage 5: M1, M2, M3, M4.

| ID | What it measures | Note |
|---|---|---|
| M1 | median assessment cadence | inverted. Runs **collapsed** into distinct days, on the server |
| M2 | largest assessment gap | inverted. Does not change with the collapse |
| M3 | median age of the available fix | inverted. `published` is a declared proxy |
| M4 | MTTR | through `mttr_collect`, WITH the cadence guard applied |

`mapping["recurring_scans"]` is **mandatory** for M1 and M2. The server does not choose which scans
represent the cadence, and the reason is measured: in the sandbox, the recurring scan alone gives a
median of 21 days and a maximum of 140; adding every scan with history gives a median of 1.0 and a
maximum of 89, because one of them runs almost daily.

M4 becomes a **gap** when the cadence guard fires — that is a correct result, not a defect. If the
export exceeds `mttr_max_wait_s`, M4 becomes a **recoverable** gap with the `export_uuid` in the
cause; call again passing `mttr_export_uuid`. Never open a new export while one is open: the API
answers 409.

M4's context carries `by_severity` with the full per-severity evidence — `n`, the native/derived
origin and the reopened count — because the skill has to declare the method in the report.

---

## `plugin_details_batch(plugin_ids)`

**Five fields per plugin, never more:** `scan_type`, `published`, `exploit_available`,
`exploitability`, `cisa_known_exploited`.

The full detail of one plugin is ~8,200 characters and 97 attributes. Twenty plugins the full way
are ~15,000 tokens; this way, ~1,500. **The project's token saving depends on this, and adding a
field is a regression.**

A plugin that fails goes into `gaps` with its cause, and the others continue. A DECLARED partial
result is legitimate; a silent partial one is not.

---

## `plugin_census(severity="critical")`

The sampling frame: plugin, detection count, VPR and family. One call, cached with a short TTL. It
is the denominator of D4, M3, V1 and V2.

There is no census by search: `plugins_search_plugins` accepts a keyword and a CVE, not a list of
plugin IDs.

### Census or sample — `plugin_mode`

`auto` (the default) runs a **census** of every plugin of the severity when the population fits
within `census_limit` (300), and falls back to a stratified sample above that. `census` and `sample`
force the choice. The mode used goes into `literal_filter` and into `context.mode`.

The census eliminates four sources of imprecision the sample forced us to manage: the Wilson gate,
the weighting base (`by_detection` versus `by_plugin` moved V1 by 5 points on its own), the
allocation bias between strata, and the irreproducibility that kept V1, V2 and M3 from having a
golden test.

Measured on the sandbox's 121 critical plugins: the n=30 sample gave V1 62.7% and the census gave
61.2% — the sample was right, but you only know that by HAVING the census. Cost: 64 s and ~5,400
tokens, still three times less than the ~15,000 the official MCP spent on twenty plugins.

Under a census, `weight_base` comes back as `not_applicable` and `ci95_whole_sample` as `null` —
rather than a label suggesting a method choice was made where none was.

### Sampling, when the population exceeds the limit

Proportional allocation to each stratum's real share, a stratum B floor of 4, weighting by the
population weights, and a Wilson 95% interval per stratum and for the whole set. The seed is fixed
(`20260903`) so the sample is reproducible — without that the same tenant scores differently every
round and a golden test cannot exist.

---

## `scan_cadence(scan_ids, collapse_same_day_runs=True, completed_only=True)`

Collapses same-day runs into **DISTINCT ASSESSMENT DAYS**.

A scan relaunched minutes later is the SAME assessment, not a new cycle. In the sandbox the
recurring scan's 12 runs fall on 9 distinct days; the raw median gives **1.42 days** and the
collapsed one gives **21** — Standardized instead of Optimized, two stages apart.

The collapse happens **on the server, always**. It was exactly because it lived on the client that
the error survived a whole run.

Returns `intervals_days`, `median_days`, `max_days`, and per scan
`median_without_collapse_days` plus `raw_intervals_days` — always, so the contrast stays visible and
auditable.

`collapse_same_day_runs=False` exists so the report can SHOW the difference, never to be the
default; it carries a `warning` saying so. M2 (largest gap) does not change with the collapse.

---

## `mttr_collect(days=180, severities=None, tags=None, max_wait_s=240, export_uuid=None, states=None, num_assets=100, batch_cutoff=2)`

MTTR through `POST /vulns/export`, with polling and chunked download.

It is the **only** path to MTTR: `last_fixed`, `time_taken_to_fix` and
`severity_modification_type` are not among the 44 findings properties of the Exposure Management
API. It is not a missing wrapper.

### The three mandatory locks

1. **`max_wait_s` exceeded** → `{status: "pending", export_uuid}`. It does not raise and does not
   return a partial number: it returns the ticket for the next call to resume. Opening another
   export would answer 409.
2. **`filters_diverged`** → a structured error, never a number. The slice is not the request, so the
   number does not answer the question.
3. **A TLS failure** → a diagnosed cause ("corporate proxy intercepting TLS"), never a raw
   exception. The server **never** offers to disable certificate verification; `TIO_CA_BUNDLE` is
   the mechanism for networks that inspect TLS.

### What the summary declares, and why

Three method choices, all of which change the number and none of which change the verdict in the
sandbox — and layer 3 of the model requires the reader to be able to redo the arithmetic:

| Field | Why it matters |
|---|---|
| `min_batch_per_window` + `sensitivity_to_cutoff` | the same slice gives 93.5% with cutoff 2 and 38.7% with cutoff 5, and cutoff 5 would pass a 40% guard |
| `states_included_in_mttr` | computed over `FIXED` only; including `REOPENED` the High mean goes from 60.39 to 49.66 days |
| `percentile_method` | Critical's p90 is 101.43 interpolated and 92.91 by nearest position — with n=10, a 9% difference |

Always read `scan_cadence` alongside the MTTR, and pass its **`windows`** to `mttr_cadence_guard`.

---

## `mttr_cadence_guard(windows, scan_dates=None, alert_cutoff_pct=40.0)`

Says whether the MTTR is measuring scan cadence instead of time to fix.

Pass `windows` = `scan_cadence.windows` from `mttr_collect` — **not `batches`**: that one already
comes filtered by the cutoff, and without the singleton windows the denominator shrinks and the
percentage inflates. Measured: it gave 100% against the real 93.5%, and one of the 7 dates
disappeared.

Two gates, and the second matters more:

1. `pct_in_batch` above the alert cutoff → M4 is a gap;
2. windows formed **only** by scan dates → M4 is a gap, even with `pct_in_batch` below the cutoff.

Gate 2 exists because the percentage depends on the chosen batch cutoff. The composition of the
dates depends on no choice at all.

---

## Endpoints used

| Purpose | Endpoint |
|---|---|
| assets search | `POST /api/v1/t1/inventory/assets/search` (Exposure Management, **BETA**) |
| findings search | `POST /api/v1/t1/inventory/findings/search` (Exposure Management, **BETA**) |
| tag categories and values | `GET /tags/categories`, `GET /tags/values` |
| scans and history | `GET /scans`, `GET /scans/{id}/history` |
| agents | `GET /scanners/null/agents` |
| plugin detail | `GET /plugins/plugin/{id}` |
| workbenches | `GET /workbenches/vulnerabilities` |
| MTTR export | `POST /vulns/export`, `GET /vulns/export/{uuid}/status`, `GET /vulns/export/{uuid}/chunks/{n}` |

The Exposure Management endpoints are in **BETA** in Tenable's documentation; the response structure
may change, which is why every read is defensive and no shape is presumed.

**Rate limiting is dynamic** — the platform computes how many requests it accepts per minute
according to load and returns `retry-after` in seconds on a 429. The client reads that header rather
than hard-coding a number. See https://developer.tenable.com/docs/rate-limiting
