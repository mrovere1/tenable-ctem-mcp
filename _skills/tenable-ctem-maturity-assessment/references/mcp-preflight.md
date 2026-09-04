# Common procedure — Filter preflight and plugin sampling

A shared reference file. A copy lives inside every `.skill` package that needs it, so each skill
works on its own once downloaded from the Exchange.

Originally validated through Tenable's official MCP on 2026-09-01. Re-executed against the direct
REST API on 2026-09-03, which is how the `tenable-ctem-mcp` server talks.

> **Updated 2026-09-04, and on two points the verdict CHANGED.**
>
> **1. The preflight is now one call: `ctem_preflight()`.** The server runs the discriminant pairs
> live and returns the finished table, plus the `deny_list` of filters it rejects before the request
> leaves. The manual procedure in section 2 remains the *definition* of what it does — read it to
> understand, not to run by hand.
>
> **2. Four verdicts in this file hold for the official MCP and not for the direct REST API:**
>
> | Here (official MCP) | Through the direct API |
> |---|---|
> | a date filter on findings is ignored, on every operator | only the **relative** ones (`within last`, `older than`, `newer than`); `<` and `>=` against an absolute date **work** |
> | `exists` does not work on `finding_vpr_score` | it **works** — the HTTP 400 came from an empty `value` |
> | `resolvable` — presume ignored until proven | **proven** ignored |
> | `age` is applied in workbenches | `age` **is not a parameter** of the API; the real name is `date_range`, and that one works |
>
> **3. Section 4 (sampling) only applies when `context.mode` is `sample`.** The census became
> reachable — the conclusion in 4.1 holds for SEARCH (`plugins_search_plugins` does not accept a
> list of IDs), but `plugin_details_batch` does. With `plugin_mode: auto`, the server runs a census
> of every plugin of the severity when the population fits within `census_limit`. **Under a census
> there is no confidence interval, no weighting and no allocation between strata: the rate is the
> count.** The three rules of 4.2 and 4.3 still hold for large tenants, where the sample comes back.

---

## 1. Why this preflight exists

**The API accepts filters it does not apply, and returns no error.** The query looks filtered,
returns the total of the whole corpus, and the skill presents that number as if it were the result
of the filter.

That is not missing data. It is a wrong number wearing the appearance of a right one, with no signal
at all that it happened.

Proven cases of a silently ignored filter:

| Target | Ignored filter | Proof |
|---|---|---|
| findings search | `last_updated`, `first_observed_at` — the **relative** operators | `older than 3650d` returned the 1840 findings of the corpus, the same as `within last 1d` |
| workbenches | `authenticated` | `true` → 20 and `false` → 20, identical results |
| workbenches | `exploitable` | `true` returned all 20, including SEoL and a Spectre check |
| workbenches | `resolvable` | `true` → 121 and `false` → 121, with severity=critical |
| workbenches | `age` | not a parameter of this API; silently discarded. The real name is `date_range`, and it is applied (1 → 17, 30 → 118, 90 → 121) |
| assets and findings search | **the entire `filters` parameter, when it is not valid JSON** | `filters="tag_count >= 1"` as free text returned the 30 assets of the corpus, with no error. The same filter as `[{"property":"tag_count","operator":">=","value":["1"]}]` returned 9. Confirmed 2026-09-03 |

**The free-text `filters` trap is the easiest one to fall into**, because the syntax
`tag_count >= 1` is exactly what `list_inventory_properties` suggests when listing operators. The
parameter requires **a JSON array**; anything else is silently discarded and the query comes back
with no filter at all. The preflight catches this: a filter that returns the corpus total is
ignored, it is not a filter that "matches everything".

**Correction of 2026-09-03 on `exists`.** This file previously recorded that `exists` answers HTTP
400 on `finding_vpr_score` and concluded the property does not support the operator. Re-running the
discriminant pair against the direct API, the cause is another: the 400 comes from an **empty
`value`**, and the API message is literally *"Missing value in filter"*. With `value=["true"]`,
`exists` gives 4,462 and `not exists` gives 1,024 — summing to the 5,486 of the corpus. The rule is
about the missing value, not about the property. `>= 0.1` also works and is monotonic
(0.1 → 4,462 · 7.0 → 1,254 · 9.0 → 586).

Provably applied filters: `state`, `finding_severity`, `finding_vpr_score`,
`finding_cvss3_base_score`, `asset_class`, `tag_count`, `tag_names`, `finding_name contains`, date
comparison against an absolute date, and in workbenches only `severity` and `date_range`.

---

## 2. The preflight — run it before publishing any number derived from a filter

Cost: one extra query with `limit=1`, because only the `total` field matters.

**2a. Value filter (numeric, enum, text):**

1. Run the query **without** the filter. Keep `corpus_total`.
2. Run it **with** the filter. Keep `filtered_total`.
3. If `filtered_total == corpus_total`, treat the filter as **ignored** and the indicator as a
   **gap**. Do not publish the number.

**2b. Boolean filter:**

1. Run with the value `true`. Keep `total_true`.
2. Run with the value `false`. Keep `total_false`.
3. If `total_true == total_false`, the filter is **ignored**. The indicator becomes a gap.

**2c. The strongest form: the exclusive pair.** Two mutually exclusive queries whose totals must sum
to the corpus. "It reduced" is not enough — a filter can reduce by accident. It was this form that
exposed the relative date operators: `older than 3650d` and `within last 1d` are mutually exclusive
and both returned the whole corpus, so they cannot both be right.

**2d. Mandatory record in the report**, per indicator:

| What to record | Example |
|---|---|
| The literal filter applied | `[{"property":"state","operator":"=","value":["FIXED"]}]` |
| Corpus total | 1840 |
| Filtered total | 20 |
| Preflight verdict | applied |
| Collection date and time | 2026-09-01 22:13 UTC |

That makes the problem visible to whoever reads the report, and not only to whoever wrote the skill.

---

## 3. The index-propagation trap

After a tag write, the Tenable One inventory index **takes time to reflect it**. Seconds after
applying a tag, an assets search by that tag returned empty while the tagging API had already
confirmed success. About fifteen minutes later it started working.

Rule: **never validate a write by reading the index immediately**, and never conclude a filter is
broken based on a read taken right after a write.

---

## 4. Plugin sampling — three rules, and the order matters

Several attributes only exist in the plugin detail, which is **one call per plugin**. A small tenant
already has hundreds of distinct plugins.

But **raising N is not the first thing to do.** A larger stratified sample is a biased sample with
more precision. The correct order is: census where it is cheap, weighting always, and only then a
larger N — with a confidence gate.

### 4.1 Census where it is cheap

> **Limit proven 2026-09-03, and the consequence overturned on 2026-09-04.**
> `plugins_search_plugins` accepts `query` (a keyword) and `cve`, **not** a list of plugin IDs — so
> there is no census by SEARCH. That was recorded as "no census for D4 and M3".
>
> **`plugin_details_batch` does accept a list of IDs**, so the census became reachable and is now
> the default. What serves as the cheap sampling frame is the workbenches call by severity, which
> returns plugin, detection count, VPR and family for every plugin of that severity in one call —
> 121 critical plugins in the sandbox. From there, `plugin_details_batch` resolves the five fields
> for all of them: 64 s and ~5,400 tokens, still three times less than the ~15,000 the old path
> spent on **twenty** plugins.

**Under a census, sections 4.2 and 4.3 do not apply.** There is nothing to weight and nothing to
infer: the rate is the count. `weight_base` comes back as `not_applicable` and the confidence
interval comes back `null`, rather than a label suggesting a method choice was made where none was.

Measured on the sandbox's 121 critical plugins: the n=30 sample gave V1 62.7% and the census gave
61.2% — the sample was right, but you only know that by HAVING the census.

**Above `census_limit` (300) the sample comes back**, and the three rules below apply again. The
limit comes from measurement: at 528 ms per plugin, sequential, a thousand plugins are nine minutes.

### 4.2 Proportional allocation and weighting — mandatory, and free

**A mistake not to repeat:** on the first real run the sample was allocated 60% to stratum A and 40%
to B by design decision, while in the population A was 65% and B was 35%. It came out nearly right
by coincidence — stratum B was over-represented by a factor of 1.14 and the bias in the result was
about 5 percentage points. In a tenant where stratum B is 10% of the population, a 40% allocation
would bias it badly.

**Allocation:** size each stratum by its real share of the population, measured before sampling:

```
share_A = plugins above the customer's cutoff / total plugins
n_A     = round(N × share_A)   ·   n_B = N − n_A
```

**Stratum B floor:** a minimum of 4 plugins, even if the proportion gives fewer. Stratum B does not
exist to estimate a rate, it exists to **find cases** of under-prioritisation; with fewer than 4 it
loses that function. When the floor kicks in, the stratum is over-represented on purpose — and the
weighting below is what keeps that from contaminating the rates.

**Weighting of every rate and every median:** never compute over the whole mixed sample. Estimate
within each stratum and combine by the population weights:

```
estimated_rate = (rate_in_stratum_A × share_A) + (rate_in_stratum_B × share_B)
```

Use the `share` by **detection** (the sum of `Count`) rather than by plugin count when the indicator
speaks of backlog volume. Report which base was used — it is not a detail: on the sandbox's n=20
sample, V1 gives 59.3% by detection and 54.6% by plugin, five points apart from the method choice
alone.

### 4.3 The sample's confidence gate — what answers "is 10% enough?"

Do not decide by a fixed rule. **Let the data say.**

For each indicator estimated from a sample, compute the 95% confidence interval of the proportion by
the Wilson method and confront it with the indicator's cutoffs:

| Situation | Behaviour |
|---|---|
| The whole interval falls inside **one** stage | Classify. The sample is sufficient for this indicator in this tenant |
| The interval crosses a cutoff | **Widen the sample in blocks of 10** and recompute |
| The budget ceiling is reached and the interval still crosses a cutoff | **Do not classify.** Report the band and declare that the sample does not distinguish the two stages |

Widths measured in practice, for the KEV presence rate:

| N | Width of the 95% CI |
|---|---|
| 10 | 50 percentage points |
| 20 | 37 points |
| 30 | 31 points |
| 50 | 25 points |

With N=10 the interval is 50 points wide — useless for separating the stages of a rate. **That is
why the `n` default rose to 30, and the ceiling to 60.**

**A nuance the gate captures and a fixed rule does not:** a value far from the nearest cutoff
classifies safely even with a small sample. On the first real run the median days in the KEV gave
1,100 days against a most permissive cutoff of 180 — the smallest value observed in the sample was
629 days, so no larger N would change the stage, only the precision of the reported number. The gate
lets that indicator through and concentrates effort where the decision is tight.

---

## 4.4 Asset identity — do not infer duplication from a name

**A mistake made on the first real run:** six `DEVICE` assets with the same NetBIOS name were
reported as inventory duplication, supposedly inflating the denominators of S1, S2 and S3. **That
was wrong.**

Each of the six had a **distinct Tenable asset ID, its own Nessus agent with a distinct UUID and a
distinct IP**. They are six real machines with a poorly standardised name, not six records of the
same asset. The denominator was correct and no indicator changed.

Rules:

1. **An identical name is not duplication.** Never infer asset duplication from a hostname, NetBIOS
   name or FQDN.
2. **An installed agent is identity.** An asset with a Nessus agent is uniquely identified by the
   agent. Check the agent list's `Asset UUID` field: if each suspect asset appears with its own
   agent, they are distinct assets. Full stop.
3. **If duplication is genuinely suspected**, the test is a conjunction: the same `Asset UUID` from
   different sources, or the absence of an agent combined with a matching IP and MAC. A name never
   counts on its own.
4. A repeated name is still worth noting, but as a **naming-standard finding**, not as an inventory
   error — and with no effect whatsoever on denominators.

---

## 5. What `plugin_details_batch` delivers, and why only five fields

The full plugin detail is ~8,200 characters and 97 attributes. The skill uses **five fields**. Twenty
plugins the full way are ~15,000 tokens; through the batch tool, ~1,500. **Adding a field here is a
regression, not an improvement** — the token saving that justifies the whole server depends on it.

| Field | Use |
|---|---|
| `scan_type` | `local` or `remote`. A `local` plugin only returns with a valid credential or an agent — it is the correct proxy for an authenticated scan |
| `published` | the plugin's publication date. For a patch-check plugin, a declared proxy for the availability of the fix |
| `exploit_available` | `true` or `false` |
| `exploitability` | `Exploits are available`, `No exploit is required`, `No known exploits are available` |
| `cisa_known_exploited` | the `CISA-KNOWN-EXPLOITED: YYYY/MM/DD` dates, with the date of entry into the KEV |

**Fields deliberately left out**, and what would be given up by adding them: `Modified`, `VPR Score`
(already in the census), the CVSS vectors, `CVEs`, `Family`, `Solution` and `Synopsis`. Each is
cheap on its own and expensive at 121 plugins.

**One field under an open decision:** `patch_publication_date` **is** reachable through the direct
API and would replace M3's declared proxy — `published` is the detection plugin's date, not the
vendor's patch date. Adding it costs one extra field against the five-field rule. That is a skill
decision, not a server one, and it is recorded here so it is not forgotten.
