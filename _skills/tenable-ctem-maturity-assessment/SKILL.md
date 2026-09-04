---
name: tenable-ctem-maturity-assessment
description: >
  Measures objective indicators of a Tenable One tenant, classifies the customer across the five
  stages of Tenable's Exposure Management Maturity Model — Ad Hoc, Defined, Standardized, Advanced,
  Optimized — and delivers a three-quarter improvement plan. Use WHENEVER the user asks for: CTEM
  maturity, exposure management maturity, maturity assessment, what stage is my customer at, CTEM
  diagnosis, exposure assessment, exposure management maturity level, maturity roadmap, CTEM
  improvement plan, CTEM gap analysis, the five CTEM stages, scoping discovery prioritization
  validation mobilization. Use also for: maturidade CTEM, avaliação de maturidade, em que estágio
  meu cliente está, diagnóstico CTEM, roadmap de maturidade; madurez CTEM, evaluación de madurez,
  en qué etapa está, hoja de ruta de madurez. Evaluates 19 indicators across the five stages, maps
  each to Tenable's eight official criteria, delivers the effective stage and the average stage side
  by side, and names the stage that limits the whole. Read only.
---

# Skill: Tenable CTEM Maturity Assessment

Measures the tenant, classifies it across the five official stages of Tenable's Exposure Management
Maturity Model, and delivers the path to the next stage.

Audience: CISOs, Security Managers, and Channel SEs running an assessment at a customer or partner.
Mode: **read only.** No write tool is ever called.

**The two questions it answers:**
1. Which stage does the customer actually operate at — and which stage is holding the others back?
2. What has to change, in order of effort and impact, to move up?

---

## Required reading before starting

```
view references/mcp-preflight.md
view references/maturity-indicators.md
```

The first carries the filter preflight, the index-propagation trap and the stratified sampling.
**The API accepts filters it does not apply and returns no error** — without the preflight this
skill publishes the corpus total as if it were a filtered result.

The second carries the 19 indicators with their formula, MCP call, cutoffs and the origin of each
threshold.

---

## Report language — the first thing decided

The report, the operator dialogue and the delivered dashboard all follow **one language, chosen at
Step 0**: `EN`, `PT-BR` or `ES`. English is the default.

The choice governs three things at once, and this is deliberate: the questions the skill asks the
operator, the prose of the final report, and the dashboard's initial language. A consultant working
in Spanish should not have to read English questions to produce a Spanish report.

What the language choice does **not** change: the tenant's own data. Tag category names, tag values,
scan names and plugin names are printed exactly as they exist in the tenant, in whatever language
they were created. Translating a customer's tag called `Criticidade` into `Criticality` in the
report would break the operator's ability to find it in the console.

The dashboard still ships with all three languages available through the header selector — that
switch is for the reader who receives the file, not for the operator running the assessment.

**The default is EN**, and it applies whenever the operator does not choose: an unanswered Step 0, an
invocation that names no language, or a request written in another language without naming one. A
request written in Portuguese is not a request for a Portuguese report.

---

## The fact that determines this skill's design

**No official Tenable material publishes a numeric threshold per maturity stage.** The model is
qualitative; the official assessment uses eight declarative criteria with no published score bands.

That is why the skill separates three layers, and so does the report:

| Layer | What it is | Configurable |
|---|---|---|
| **1 — Official** | The five stages, the eight criteria, the CES, AES, ACR and VPR bands | No |
| **2 — Skill criterion** | The numeric cutoffs of each indicator | Yes, in the `maturity_config` block |
| **3 — Always visible** | Raw value, N, literal filter, applied threshold and its origin | Always present |

Nailing a percentage down as if it were a Tenable criterion would be inaccurate. Every cutoff appears
in the report labelled with its origin: `Tenable official`, `cited external (CISA BOD 26-04)`,
`skill default` or `operator override`.

---

> **First-run operator:** the complete walkthrough — prerequisites, environment variables and the
> customer delivery checklist — is in `references/execution-guide.md`, in all three languages.

## Step 0 — Discovery and confirmation (MANDATORY)

**Principle: discover, present, confirm. Never guess from a keyword and never offer a blank field.**
The operator should not have to remember the exact name of a tag category; the skill queries the
tenant, shows what exists, and asks for the mapping by choosing among the real values.

The previous version of this step tried to guess the criticality and owner categories from a keyword
list. That fails at any customer using its own nomenclature — `Tier`, `BIA`, `Classificação`,
`P1/P2/P3`, `Gold/Silver/Bronze`, `Squad`, `CI Owner`, or the name in another language.

### Phase A — Silent discovery, asking nothing

Run this before any question, and keep the result:

```
ctem_discover_tenant()
```

**One call.** It returns the real tag categories and values, total assets, counts by `asset_class`,
the `exposure_classes` present with the total of each, scans with history and how many runs each
one has, and agents by status. It replaces the ~10 calls this phase used to require.

The result is cached with a short TTL on the server, so re-consulting during the same run costs no
new call.

**A caution the snapshot already carries:** `asset_class` is not `exposure_classes`. A tenant may
have assets with `asset_class = IDENTITY` and `exposure_classes = IDENTITY` at zero — the identity
assets are in the inventory without carrying Identity Exposure findings. D2 uses `exposure_classes`.

### Phase B — Confirmation, with the real values as options

Use `ask_user_input_v0`. **Every mapping question offers the options found in Phase A, plus "none of
them".** Never free text where a list will do.

### Phase B.1 — The confirmation screen, before any question

> **Ask in the report language, not in the language of the conversation.** If Step 0 says EN, every
> question, option label and proposal-table heading below is written in English — even when the
> operator has been chatting in Portuguese or Spanish, and even when they wrote the request itself in
> another language. The conversation's language is not a signal; the declared report language is the
> only one. Getting this backwards was a real defect found on 2026-09-04: the run was invoked with
> `Report language: EN` and the confirmation questions came back in Portuguese, because the surrounding
> conversation was Portuguese. An operator who asks for English and is questioned in another language
> cannot hand the run to a colleague, and cannot trust that the report will come back in the language
> they asked for.
>
> The tenant's own data is the exception, and it is never translated: category names, tag values and
> scan names are quoted exactly as they exist in the tenant, inside a question written in the report
> language.

**Do not open with 14 questions.** After Phase A, build **one proposal table** with the 14 fields
filled in with the best guess from discovery, plus the reason for each guess, and ask **one**
question:

```
message: "I discovered the tenant and assembled this mapping. Check it before I measure —
          any line can be changed."

<table: Field | Proposed value | How I got there | Alternatives found>

questions:
  - question: "Proceed with this mapping?"
    type: single_select
    options:
      - "Proceed as is"
      - "Adjust a few fields — I will say which"
      - "Review field by field"
```

- **"Proceed as is"** → measure. It is the expected path when discovery got it right.
- **"Adjust a few fields"** → ask **only** the fields the operator named, with the real options from
  Phase A.
- **"Review field by field"** → the complete question sequence below.

**Rules of the proposal.** Each row carries *how* the skill arrived at the value, and the
alternatives that exist in the tenant — without that the operator has no way to judge. Fields the
skill **cannot propose** are left explicitly empty in the table and are asked anyway, because a
guess there is a coin toss: the **highest-criticality values** (the skill does not know the ordinal
order of `Alta`, `Tier 1`, `Gold` or `Class A`), the **customer's prioritisation criterion**, and
the **report language**.

**A category may be something the skill did not expect, and the way through is to offer, not to
guess.** If the tenant has `Location` with values `Site 1` and `Site 2`, the proposal offers
`Location` as a candidate for **locality** — not for environment. Locality is *where* the asset is;
environment is *production versus staging*. If at that customer the sites **are** the environments,
the operator repoints it at confirmation. The reverse holds too: a category called `Environment`
with values `HQ` and `Branch` is locality, not environment. The skill never decides this from the
category name — it proposes from the name and accepts the correction.

**The confirmed proposal table goes whole into the report's Methodology tab**, with the "how I got
there" column preserved. It is what makes reassessment comparable and what lets a second consultant
audit the scope.

### Phase B.2 — The questions, when the operator wants to review

```
Question 1 — Report language?
  options: ["English (EN)", "Português (PT-BR)", "Español (ES)"]
  → governs the report, the dashboard's initial language AND the remaining questions of this
    dialogue. Default: EN.

Question 2 — Which tag category represents the asset's CRITICALITY?
  type: single_select
  options: [<every category found in Phase A>, "None — the customer has none"]
  → mandatory. S2 and P1 depend on it.

Question 3 — Within that category, which values represent the HIGHEST criticality?
  type: multi_select
  options: [<every value of the category chosen in Q2>]
  → the skill does NOT know whether "Alta" outranks "Média", nor how to read "Tier 1", "P1", "Gold"
    or "Class A". The ordinal order has to come from the operator. Without it, "Crown Jewel" is a
    guess.

Question 4 — Which tag category represents the asset's OWNER?
  type: single_select
  options: [<categories from Phase A>, "None — the customer has none"]
  → S3 and the grouping by owner depend on it.

Question 4b — Which category represents LOCALITY (site, region, unit)?
  type: single_select
  options: [<categories from Phase A>, "None — the customer has none"]
  → does NOT filter scope and does NOT score any indicator. It lets the roadmap group items by site
    and lets the report say where the problem is. It is a separate field on purpose: locality and
    environment are different things, and customers swap the names for the two.

Question 5 — Which category represents ENVIRONMENT (production, staging, development)?
  type: single_select
  options: [<categories from Phase A>, "None — the customer has none"]
  → recorded for the report's narrative and for the v2 roadmap. It does NOT filter the measurement:
    the v1 scope is the whole tenant. See the note under "Saved profile".

Question 6 — Which scans represent the RECURRING ASSESSMENT of the environment?
  type: multi_select
  options: [<scans with completed status and history, with name, last run date and run count>]
  → D1, M1 and M2 come from here. A typical tenant has test scans, PCI scans, POC scans and one-offs.
    Computing cadence over all of them mixes real rhythm with experiment and produces a wrong number.

Question 7 — Any assets to EXCLUDE from the assessment scope?
  type: single_select
  options: ["No, assess everything"]
  → v1 measures the whole tenant. Exclusion by tag is v2 — see the note under "Saved profile".

Question 8 — Does the customer use exception rules (accept or recast) in Tenable VM?
  type: single_select
  options: ["Does not use", "Uses a little (under 10% of the backlog)", "Uses a lot (over 10%)",
            "I do not know"]
  → does NOT change any calculation. It determines the caveat text in the report. When M4 is
    collected, the `modified_severity` field measures the real thing and the caveat cites the
    measured number instead of the operator's estimate — including when they answered "I do not
    know". See the exceptions section below.

Question 9 — Surfaces licensed by the customer?
  type: multi_select
  options: ["VM","WAS","Cloud Security","Identity Exposure","OT Security","ASM","AI","Source Code"]
  → pre-tick the ones Phase A found in exposure_classes; the operator confirms or corrects.

Question 10 — Which prioritisation criterion does the customer use TODAY?
  options: ["VPR >= 7 (default)","VPR >= 9","CVSSv3 >= 7","CVSSv3 >= 9","Other — I will say","I do
            not know"]
  → **Default: `VPR >= 7`**, and it is the value pre-filled on the confirmation screen. The choice
    of default is not arbitrary: measured in the sandbox on 2026-09-03, swapping `CVSSv3 >= 7` for
    `VPR >= 7` shrinks the immediate queue from 3,377 to 1,254 findings — 2,168 leave, 45 enter —
    and VPR coverage within the CVSS >= 7 slice is 98.1%, so the criterion applies to virtually the
    whole queue CVSS would select.
  → **Descriptive, not prescriptive.** It records what the customer does, not what they should do.
    Filling it in with the recommended criterion when the customer uses another **breaks P3**: the
    indicator compares the declared criterion against the measured opportunity, and a false
    declaration reports maturity the customer does not have.
  → "I do not know" is a valid and common answer, and **it is not the same as accepting the
    default**. Explicit consequence, so two operators do not produce different P3s from the same
    tenant: **P3 = Ad Hoc**, and the opportunity is still measured with `vpr >= 7.0` as the
    comparison base, declared as a default base and not as the customer's criterion.
  → **Accepting the default without checking has a declared consequence.** If the operator clicks
    "Proceed as is" on the confirmation screen without touching this line, `confirmed` stays
    `false`: P3 scores with `VPR >= 7`, and the report writes, on the indicator's row and in the
    Methodology tab: *"prioritisation criterion assumed as the default (VPR >= 7), not confirmed
    with the customer"*. Without that label, a default accepted out of convenience would become a
    declaration of maturity nobody made — and P3 is exactly the indicator that measures whether the
    declaration exists.
  → How to find the real criterion, in order of reliability: the filter on the dashboards the team
    actually looks at; the queue filter in ServiceNow or Jira; the field used in the written SLA;
    and only then what the person says from memory.

Question 11 — Deadline standard for the KEV comparison?
  options: ["CISA BOD 26-04 (3 / 14 / 60 days)","Customer's own SLA","No deadline comparison"]

Question 12 — Nail the stage down, or deliver the indicators only?
  options: ["Nail the stage down","Indicators only, no classification"]

Question 13 — Threshold profile?
  options: ["Skill default","Conservative","Aggressive","Load my own profile"]

Question 14 — Plugin set size for V1 and V2?
  options: ["Census when it fits (recommended)","Top 30 sample","Top 50 sample","Top 20 sample"]
```

**When the operator answers "None" to a mapping**, the indicator that depends on it becomes a
**declared gap with a named cause** — "the customer has no owner tag category" — and not a generic
gap. The difference matters: the first is a Scoping finding that becomes a roadmap item; the second
looks like a tool failure.

**Record the mapping in the report.** The methodology tab shows, literally, which category was
treated as criticality, which values as highest criticality, which as owner, which scans entered the
cadence. Without that, two assessments of the same customer by different consultants are not
comparable.

**Saved profile.** At the end, the skill offers to export the mapping as a YAML block for the
operator to keep and reuse at reassessment. Changing the mapping between runs invalidates the
comparison, exactly as changing the threshold profile does.

```yaml
customer_mapping:
  criticality_category: "Business Impact"
  highest_criticality_values: ["Tier 1", "Mission Critical"]
  owner_category: "CI Owner"
  recurring_scans: [33, 40]
  uses_exceptions: "uses_a_little"
```

**The v1 scope is the whole tenant.** The profile has no `environment_category`,
`production_values` or `exclude` because no indicator would apply them: the server measures the
complete corpus, always. Fields the operator fills in and nobody consumes are worse than absent
fields — the operator excludes LAB and SANDBOX, checks the YAML, and receives a whole-tenant report
believing the scope held. If a customer needs a scope by environment or a laboratory exclusion, that
is v2 and enters as a tag filter inside the indicators, not as a profile field.

---

## Risk exceptions — accept and recast

**A question every customer asks, and one that needs an honest answer in the report.**

What the Tenable API has, and the skill does **not** reach through the Exposure Management API:

| VM API field | Definition from the spec |
|---|---|
| `severity_modification_type` | `NONE`, `RECASTED` or `ACCEPTED` — *"the type of modification a user made to the severity"* |
| `severity_id` | the severity **after** the recast |
| `severity_default_id` | *"the severity originally assigned before the user recast the risk"* |
| `recast_reason`, `recast_rule_uuid` | the comment and the rule applied |
| `accepted_count`, `recasted_count` | per plugin, in the workbenches response |

What that means for this skill's numbers, and what goes declared:

1. **A finding with accepted risk still appears as `ACTIVE`.** The Exposure Management API has no
   mention of recast, accept or exception — the `state` enum is only `ACTIVE`, `RESURFACED` and
   `FIXED`. There is no way to identify or exclude them.
2. **A recast changes the severity the inventory reports.** `severity_id` is the recast value. A
   Critical recast to Low is counted as Low by any severity-based indicator. That **silently
   deflates** the critical backlog — the effect is the opposite of what the operator expects.
3. `accepted_count` and `recasted_count` exist in the workbenches response, but are not among the
   five fields `plugin_details_batch` exposes.
4. **With `ctem_mobilization`, this stops being blind.** `POST /vulns/export` returns
   `severity_modification_type`, which M4 hands back in
   `context.modified_severity_other_than_none`. When M4 exists, count the rows by value (`NONE`,
   `RECASTED`, `ACCEPTED`) and **use the count instead of the operator's estimate**. The export's
   slice is usually narrower than the assessment's (severity and day window), so the count is
   declared with its slice alongside, never extrapolated to the whole backlog. In the reference
   collection of 2026-09-03, all 4,278 rows came back `NONE`: no severity distorted by an exception
   in that slice.

**Skill behaviour.** The answer to Question 8 changes no calculation — it changes the caveat:

| Answer | Text in the report |
|---|---|
| Does not use | No caveat |
| Uses a little | *"The customer uses exception rules. The Exposure Management API does not allow identifying them, so they are counted in the backlog and a recast may have reduced the reported severity. Impact estimated by the operator: under 10%."* |
| Uses a lot | Same caveat, **highlighted at the top of the report**, with a recommendation to validate the numbers in the console before taking them to the customer |
| I do not know | *"It was not possible to determine whether the customer uses exception rules. Confirm before using these numbers in an investment decision."* |
| Any answer, **with M4 collected** | Replace the estimate with the measurement: *"In the export's slice (severities X, last N days, M rows), K findings had a modified severity — J recast and L with accepted risk."* The number comes from `context.modified_severity_other_than_none`. If `K = 0`, say so: it is the confirmation that no severity in that slice was adjusted |

---

## Step 1 — Preflight and corpus

```
ctem_preflight()
```

**One call.** It returns the finished `PREFLIGHT` table — every filter tested **live**, with a
discriminant pair — and the `deny_list` of filters the server rejects before the request leaves,
each with its rule and its measured proof. The table goes whole into the report.

The server inherits no verdict from any document. Three forms of proof: `exclusive_pair` (two
mutually exclusive queries whose totals must sum to the corpus — "it reduced" is not enough),
`boolean` (`true` and `false` with equal totals mean the parameter is ignored) and `monotonic` (a
strictly decreasing ladder of cutoffs).

**The denominators come from `ctem_discover_tenant()`**, already collected at Step 0:
`assets.total`, `assets.by_asset_class.DEVICE`. The findings corpus comes from the preflight.

**Do not hand-build a date filter on findings.** The relative operators (`within last`,
`older than`, `newer than`) are accepted and silently ignored — the server rejects them with an
error. Where the skill needs assessment time, the source is `scan_cadence`; where it needs time to
fix, it is `mttr_collect`.

---

## Step 2 — Collect the 19 indicators

Follow `references/maturity-indicators.md`, which carries the formula and the threshold origin per
indicator. **Collection is five calls**, one per stage, each returning the indicators already
aggregated:

```
ctem_scoping(mapping)             → S1, S2, S3, S4
ctem_discovery()                  → D1, D2, D3, D4
ctem_prioritization(mapping, customer_priority_cutoff, p2_value)
                                  → P1, P2, P3 + the three compared queues
ctem_validation(mapping)          → V1, V2, V3, V4
ctem_mobilization(mapping)        → M1, M2, M3, M4
```

`mapping` is the answers from Phase B of Step 0:

```yaml
criticality_category: "<category name>"   # mandatory for S2, S4 and P1
owner_category:       "<category name>"   # mandatory for S3
recurring_scans:      [<scan_id>, ...]    # mandatory for M1 and M2
```

**The server guesses none of these.** Without them the indicator becomes a gap and the cause lists
the options that exist in the tenant, so the consultant can point at the right one. This is
deliberate: in the sandbox, M1 gives a median of 21 days with the declared recurring scan and 1.0
day adding every scan with history — two stages of difference coming out of a choice nobody made.

**Partial re-run.** Every stage tool accepts `indicators=["V2","V3"]` and computes only the
requested subset. Use that to re-collect an indicator that came back as a gap without paying for all
19 again — `ctem_validation(indicators=["V3"])` does not spend the plugin calls V1 and V2 would
require.

**Every indicator already carries its evidence.** The envelope brings `value`, `n`,
`literal_filter`, `collected_at_utc` and `preflight_verdict`; `context` brings what is specific to
the indicator (strata, intervals, cutoffs, proxy notes). Copy that into `EVIDENCE[id]` and add only
the applied cutoff with its origin, which is the skill's decision, not the server's.

**A query that failed does not become a number.** It comes back as `value: null` with `gap: true`
and `cause` filled in. A silent partial number does not exist in this chain.

### Census instead of sample

`ctem_discovery`, `ctem_validation` and `ctem_mobilization` accept `plugin_mode`, which defaults to
`auto`: it runs a **census** of every plugin of the severity when the population fits within
`census_limit` (300), and falls back to a stratified sample above that. The mode used goes into
`literal_filter` and into `context.mode`.

This **replaces** the old `sample_plugins.census_d4_m3: false`. That decision was correct for the
old path: `plugins_search_plugins` accepts a keyword and a CVE, not a list of IDs. But
`plugin_details_batch` takes a list of IDs, so the census became reachable — 121 critical plugins
cost 64 s and ~5,400 tokens, still three times less than the ~15,000 the old path spent on **twenty**
plugins.

Under a census there is **no confidence interval, no weighting, and no allocation between strata**:
the rate is the count. The sample's confidence gate (`ci_gate`) only applies when `context.mode` is
`sample`. When it is `census`, the report declares a census and publishes no CI.

### 2.M4 — MTTR, the only indicator outside the Exposure Management API

**M4 no longer requires a CSV or an external script.** `ctem_mobilization` calls `mttr_collect`
internally and already applies the cadence guard. The `tenable_mttr_export.py` collector has left
this skill's package: it still exists as the **source of the code** for `mttr.py` on the MCP server
and as the generator of the golden-test fixtures, not as an execution path. One path, not two.

The reason M4 is special has not changed: `last_fixed`, `time_taken_to_fix` and
`severity_modification_type` live in the Vulnerability Management API, in `POST /vulns/export`, and
**are not among the 44 findings properties** of the Exposure Management API. It is not a missing
wrapper.

**A slow export does not freeze the conversation.** If `mttr_max_wait_s` is exceeded, M4 comes back
as a **recoverable** gap, with the `export_uuid` in the cause. Call
`ctem_mobilization(indicators=["M4"], mttr_export_uuid="<uuid>")` to resume. Never open a new export
while one is open for that key: the API answers **409**.

**Never ask the operator for API keys in this conversation.** The credentials live in the MCP server
process's environment, in `TIO_ACCESS_KEY` and `TIO_SECRET_KEY`. No tool accepts a key as a
parameter, and the skill never asks for a credential.

**The cadence guard already comes applied.** `ctem_mobilization` crosses the MTTR windows against
the dates from `scan_cadence` of the declared `recurring_scans`, and returns M4 as a gap when either
gate fires:

1. `pct_in_batch` above `CONFIG.mttr.max_batch_pct`;
2. windows formed **only** by scan dates — even with `pct_in_batch` below the cutoff.

Gate 2 is the stronger one, and that is why it exists: the percentage depends on the chosen batch
cutoff — in the sandbox the same data gives 93.5% with cutoff 2 and 38.7% with cutoff 5, and cutoff
5 would pass a 40% guard. The composition of the dates depends on no choice at all.

**What the skill still has to do:** read `context.p50_critical` and `context.p50_high`, map each one
through its cutoffs, and take the **lower of the two stages**. Mature mobilisation closes both
severities, it does not offset one with the other. The server delivers the two numbers and the
cutoffs; the stage belongs to the skill.

Procedure:

1. `ctem_mobilization` already calls `mttr_collect` internally. There is no CSV to look for and no
   script to run, and **nothing to ask the operator** — the credentials live in the MCP server's
   environment.
2. If M4 comes back as a **recoverable** gap (export still running), the cause carries the
   `export_uuid`. Resume with `ctem_mobilization(indicators=["M4"], mttr_export_uuid="<uuid>")`.
   **Never** open a new export while one is open: the API answers 409.
3. If M4 comes back as a gap **on merit** (the cadence guard fired), that is a result, not a
   failure: declare the gap with the cause the server returned, `P = 16`, and the Step 4 gate
   adjusts itself.

**Calculation.** The two p50s arrive ready in `context.p50_critical` and `context.p50_high`,
computed over `state=FIXED` with `days_to_fix` present, by **interpolated** percentile (the method
is declared in `context.percentile_method`, alongside the nearest-position value, so the reader can
measure the effect of the choice).

Translate each p50 into a stage through the M4 cutoffs in `references/maturity-indicators.md`, and:

```
M4 = the LOWER of the two stages
```

The lower, not the average, by the same logic as `effective_stage`: mature mobilisation closes both
severities, it does not offset one with the other.

**M4 gates, all mandatory:**

| Condition | Behaviour |
|---|---|
| `n[sev] < CONFIG.mttr.min_n_per_severity` (default 5) | that severity does **not** score |
| both severities below the minimum | **M4 = gap**, with each `n` declared |
| `mttr_source = derived` on more than `max_derived_pct` (default 30%) | M4 scores, with a composition ⚠️ in the report |
| `filters_diverged = true` | **M4 = gap.** Job reused after a 409: the slice is not the request. **Read the boolean**, never compare the dictionaries — the API normalises and adds defaults, so a literal comparison reports a mismatch on every run |
| `pct_in_batch >= CONFIG.mttr.max_batch_pct` (default 40), **computed by the server with `min_batch_per_window`** | **M4 = gap with a named cause:** *"MTTR dominated by scan cadence (X% of findings closed in a batch); M1 and M2 already measure cadence"*. See below |
| windows `(first_found, last_fixed)` formed only by pairs of scan dates | **M4 = gap**, even with `pct_in_batch` below the cutoff: the number is the interval between scans |
| `FIXED` rows with an empty `days_to_fix` | out of the calculation, count declared. **Never** impute a value |
| `modified_severity != NONE` on any row | M4 scores, with the caveat that the severity was adjusted by a recast |

#### Why scan cadence invalidates M4 rather than merely labelling it

`time_taken_to_fix` measures **detection to detection**, not time to act. An asset scanned on 09 Jun,
not scanned again, and seen clean on 02 Sep produces 85 days for everything on it — including what
was fixed on the first day. The server detects this by grouping findings of the same asset with the
same `first_found` and the same `last_fixed`, and publishes `scan_cadence.pct_in_batch`.

In a dashboard skill that case becomes a **label** ("upper bound"), because there the number still
informs. Here it becomes a **gap**, and the reason is structural: with a high `pct_in_batch`, M4
would be measuring the same thing M1 and M2 already measure — assessment cadence. Scoring it would
count cadence twice and call remediation maturity what is in fact assessment maturity. It is the
same principle that stopped P3 from scoring on the raw delta alone: **do not score as process
maturity what is a characteristic of the environment.**

When M4 becomes a gap for this reason, the report is required to write the finding in prose, because
it is worth more than the lost number:

> *"MTTR is not measurable in this environment because X% of the fixed findings were seen closed in
> the same scan as their neighbours on the same asset — the number would measure the interval
> between scans, not time to fix. The largest batch is <asset>, with N findings. Increasing the
> assessment frequency on that asset is what makes MTTR measurable, and it is a Mobilization roadmap
> item."*

#### What the 2026-09-03 collection validation showed

A real sandbox collection, 4,278 findings, 31 `FIXED` with a date. Recounted row by row with cutoff
2, `pct_in_batch` is **93.5%**.

More decisive than the percentage: the 9 observed `(first_found, last_fixed)` windows are all pairs
drawn from **7 distinct dates** (27 Jan, 08 Mar, 07 Jun, 08 Jun, 09 Jun, 02 Sep, 03 Sep), which are
the tenant's scan dates, and **29 of the 31** findings fall into a shared window. In this tenant the
MTTR **is** the interval between scans: it measures assessment cadence, not time to fix. Largest
batch: 12 findings on one asset, all with exactly 85.5 days. M4 is a gap here, correctly.

**Consequence for the skill.** The server publishes the three method choices in the summary
(`min_batch_per_window`, `sensitivity_to_cutoff`, `states_included_in_mttr`, `percentile_method`) —
read them from there.

| Method choice | Why it matters | What to do |
|---|---|---|
| batch cutoff (`min_batch_per_window`) | in the sandbox the same slice gives 93.5% with cutoff 2, 74.2% with 3, 64.5% with 4 and 38.7% with 5 — cutoff 5 would pass the 40% guard and make M4 score | use **2** (the skill default) and say which cutoff produced the number |
| states included in the MTTR | the server computes over `FIXED` only. Including `REOPENED`, the High mean goes from 60.39 to 49.66 days — an 18% difference, and `REOPENED` is precisely the finding that came back | keep `FIXED` only (a reopened finding was not fixed), and **declare** the exclusion with the `REOPENED` count |
| percentile method | Critical `p90` gives 101.43 interpolated and 92.91 by nearest position; with n=10 the choice changes the number by 9% | use `interpolated` (`CONFIG.mttr.percentile_method`) and name the method |

None of the three changes the verdict in this tenant. All three change the number, and layer 3 of the
model requires the reader to be able to redo the arithmetic — which is why all three go written into
`EVIDENCE[M4]`.

**`modified_severity` now measures the distortion from exceptions.** In M4's return this field comes
from `severity_modification_type`, which the Exposure Management API does not expose — it used to be
a blind spot. In the sandbox collection all 4,278 rows came back `NONE`: no recast, no acceptance, so
no assessment severity is inflated or deflated by an exception. When rows other than `NONE` appear,
count and declare them per severity: it is the only direct measurement the skill has of what
exceptions hide, and it applies to S3, P1 and P2, not only to M4.

In `EVIDENCE[M4]`, besides the standard fields, record: `export_uuid` and `collected_at_utc`,
`requested_filters`, `filters_diverged`, `records_analysed`, `pct_in_batch` **with the batch cutoff
used**, the states included in the calculation **with the excluded `REOPENED` count**, the percentile
method, the count of `modified_severity != NONE`, `n` and the native/derived composition per
severity, and each severity's stage before the minimum was applied. Layer 3 of the model requires the
reader to be able to redo the arithmetic.

---

## Step 3 — Classify

### 3.1 Stage per indicator

Compare the value against the four cutoffs, respecting `inverted` where lower is better. Indicators
marked `informational` — S4 and V1 — do **not** score.

**Mind the unit.** Rate indicators are reported as **percentages**, and their cutoffs are whole
numbers: S1 `[20, 50, 80, 95]`, P2 `[40, 70, 90, 98]`, V3 `[25, 15, 8, 3]`. The one ratio expressed
as a 0..1 fraction is `P3_opportunity`, because it is a ratio and not a rate. Comparing a percentage
against a fractional cutoff drops an inverted indicator into the worst bucket every time — that was
a real defect in V3, found in the audit of 2026-09-04.

`P3` has its own stage table, composed of the criterion the customer declares at Step 0 and the
opportunity measured in the backlog. See `references/maturity-indicators.md`. **P3 depends on P2:**
if P2 is a gap, so is P3.

Result: **17 scoring indicators**, each in one of the five stages — 16 when M4 becomes a gap, which
now happens on merit (the cadence guard) or through a collection failure, not through a missing file.

### 3.2 Stage per CTEM stage

The mean of the stages of that stage's scoring indicators, rounded down. Rounding down is
deliberate: maturity is demonstrated, not presumed.

**The scale is the stage, not the number of indicators.** Each indicator is first translated into
one of the five stages by its four cutoffs; only then does it enter the mean. A stage with three
indicators reaches Optimized normally — all three simply have to land in Optimized. There is no
normalisation to do, because the conversion to the 1-to-5 scale already happened indicator by
indicator.

An example, to make it concrete in the report: **Scoping reaches Optimized** when S1 >= 95%,
S2 >= 90% and S3 >= 90%.

**No stage is classified with fewer than 2 indicators with data.** With 0 or 1, the stage becomes a
`gap` and enters nothing.

### 3.2.1 Support asymmetry — always declare it

The stages do **not** have the same number of scoring indicators:

| CTEM stage | Scoring indicators | Informational |
|---|---|---|
| Scoping | 3 — S1, S2, S3 | S4 |
| Discovery | **4** — D1, D2, D3, D4 | — |
| Prioritization | 3 — P1, P2, P3 | — |
| Validation | 3 — V2, V3, V4 | V1 |
| Mobilization | **4** — M1, M2, M3, M4 | — |

Total: **17 scoring**, **16** when M4 becomes a gap. 2 informational.

**M4 is still conditional, but for another reason.** It no longer depends on a file existing:
`ctem_mobilization` always tries to collect it. M4 becomes a gap when:

| Cause | What it is |
|---|---|
| the cadence guard fires | **a result, not a failure** — the MTTR there measures the interval between scans |
| the export exceeds `max_wait_s` | a **recoverable** gap: resume through the `export_uuid` |
| the job applies a slice different from the request | a structured error — the slice is not the question |
| n below `min_n_per_severity` | too small a sample for that severity to score |

In any of those cases Mobilization drops to three indicators and the total falls to 16. The Step 4
confidence gate is proportional precisely so it absorbs that without manual recalibration.

The distribution is nearly balanced — three stages with three indicators, Discovery and Mobilization
with four. Even so the report is required to show the support, because a stage with fewer indicators
moves on less evidence.

Concrete rules:

1. Each stage appears in the report with the **`n` supporting it**: "Prioritization — Advanced,
   supported by 3 of 3 indicators".
2. When a stage is classified with **fewer than 3 indicators with data** — through a gap, not by
   design — and it is the one setting the effective stage, the skill adds, prominently: *"the
   effective stage is supported by only N indicators; confirm before turning this into an investment
   plan"*.
3. The methodology tab repeats the table above, so the reader knows the weight of each stage.

### 3.3 The customer's two numbers, side by side

```
effective_stage = the lowest of the five assessed stages
average_stage   = the arithmetic mean of the assessed stages, rounded down
```

**The difference between the two is the report's central argument.** A customer with an average of
`Standardized` and an effective of `Ad Hoc` has tool investment that is not turning into results
because of one blocking stage — and that stage is exactly the scope of the service to sell. When the
two coincide, the improvement is incremental and distributed, and the conversation shifts from
"fix a gap" to "move up a level".

**The skill is required to name, in prose, which stage is pulling the effective stage down**, and
through which indicator. Showing the number is not enough.

Design rationale, for the report: the effective stage uses the weakest link because the CTEM stages
are sequentially dependent — without business context at Scoping, downstream prioritisation is
already compromised, however good the tooling is.

---

## Step 4 — Confidence gate

Before publishing any stage:

The gate is **proportional to that run's scoring indicators**, not to a fixed number. That is
necessary because M4 is conditional: 17 scoring when M4 scores, 16 when it becomes a gap.

```
P         = scoring indicators applicable to this run   (17 with M4, 16 without)
measured  = scoring indicators that returned data
normal    = ceil(0.8125 × P)
with_note = ceil(0.6250 × P)
```

| Condition | Behaviour |
|---|---|
| `measured >= normal` | Classify normally |
| `with_note <= measured < normal` | Classify, with a prominent note that the base is partial, listing what is missing |
| `measured < with_note` | **Do not classify.** Deliver the available indicators and what needs enabling in the tenant |
| `CONFIG.classify_stage = false` | **Do not classify**, regardless of the count. Deliver all 19 with bands and distances to the next cutoff |

The two coefficients come from the original calibration of 2026-09-02 (13 and 10 out of 16) and
reproduce it exactly: `ceil(0.8125 × 16) = 13` and `ceil(0.6250 × 16) = 10`. With 17 scoring
indicators the cutoffs become **14** and **11**. Round up here, unlike the stage — the gate protects
against classifying on a thin base, so ties resolve to the strict side.

The report is required to print `measured / P` and which of the three branches was applied.

In the no-classification mode, each indicator still shows the distance to the next cutoff — "S1 is 6
percentage points short of Advanced" — because that is what directs action without pinning a label.

---

## Step 5 — Three-quarter roadmap

Order the gaps by **estimated effort against impact on the effective stage**. Impact comes from how
far the indicator sits below the next cutoff and from how many stages it unblocks. Effort is
classified in three levels, and the criterion goes declared:

| Effort | Criterion | Examples |
|---|---|---|
| Low | console configuration, no project | create a tag category, adjust a scan schedule |
| Medium | a project of weeks, involving another team | tag the installed base, deploy an agent across a band of assets |
| High | a change of process or contract | license a new surface, redesign the prioritisation process |

Sequencing rule: **first what unblocks the effective stage**, even if the absolute impact looks
smaller. Raising Scoping from Ad Hoc to Defined is worth more than optimising Mobilization, because
the effective stage is the weakest link.

Each roadmap item carries: target indicator, current value, cutoff to reach, effort, and what
concretely to do. No calendar dates — the report uses Q1, Q2, Q3 relative to the project start.

**Do not convert a stage improvement into financial savings** without a premise supplied by the
customer.

---

## Step 6 — Dashboard

A single, self-contained HTML document, with CSS and JS embedded. Deliver it in the conversation and
as a file.

### Chart form — a deliberate decision

The radar has two real weaknesses: it distorts perceived area, because area grows with the square of
the value, and the order of the axes changes the polygon's shape with identical data. The horizontal
bar has neither, and it is the right form for comparing magnitude across five named categories.

But the radar has a strength the bar does not: it is the format an assessment audience recognises
without explanation, and it is superior for overlaying two measurements at reassessment.

**Decision: use both on the Overview tab**, radar on top for recognition and bar underneath for
reading, with the radar's traps neutralised by the rules below.

**In on top, the radar of the five stages.** A pentagon with one axis per stage, a 1-to-5 scale, and
grid rings at the five levels. It serves recognition: maturity assessments have used radars for
decades and the customer understands it without explanation. The blocking stage's vertex takes the
accent colour.

Mandatory radar rules, because it has two known traps:
- **Axis order fixed to the CTEM sequence** — Scoping, Discovery, Prioritization, Validation,
  Mobilization. Never reorder, neither alphabetically nor by value: the same measurement in a
  different order produces a differently shaped polygon, and the reader reads shape.
- **The numeric value printed at each vertex.** The eye reads area, and area grows with the square of
  the value — a stage 4 looks four times a stage 2, not twice. The number beside the vertex corrects
  the reading.

**Underneath, the horizontal bar with emphasis.** One bar per stage, a common 1-to-5 scale, a single
baseline. The stage that sets the effective one in accent, the other four in recessive grey, direct
labels with the value and the stage name. Two discreet vertical marks indicate the effective and the
average stage. This is where the value is read precisely, and where the weakest link jumps out.

The scale ruler is aligned to the same reference as the bars: the mark for value `v` at `v / 5` of
the track width, **not** distributed evenly across the width. Check this in the rendering — it is an
easy mistake and it goes unnoticed.

**Clicking a stage opens the indicator summary.** Both the radar vertex and the bar are clickable,
with a target larger than the mark. The click opens a compact panel with **only the essentials**:

| Column | Content |
|---|---|
| Indicator | ID and short name |
| Value | the raw measured value |
| Stage | the stage that indicator reached |

Nothing else in that panel — no formula, no filter, no N, no threshold origin. At its foot, a single
**"see detail"** link leading to the Indicators tab already filtered to that stage, where the full
columns live. Informational indicators appear in the panel marked `informational, not scored`, and
gaps as `declared gap` — the operator needs to see they exist, even when they do not score.

**The 19 indicators are a table, not a chart.** More than seven classes that all carry meaning call
for a table. One row per indicator, with value, N, stage reached, next cutoff, distance and threshold
origin.

### Palette — validated, not chosen by taste

Surface `#44494B`, text `#FFFFFF` and `rgba(255,255,255,.72)`. Font Inter or system-ui.

`#E7FF00` is an **accent**, never a series colour. Use it for the blocking stage and the highlighted
number.

Stage is an ordinal scale, so a sequential ramp of one hue, validated against `#44494B`:

| Stage | Hex |
|---|---|
| Ad Hoc | `#FFF0DC` |
| Defined | `#FFC894` |
| Standardized | `#FF9A45` |
| Advanced / Optimized | `#EE7000` |

Recessive grey `#7E8688`, used on the four bars that are not the blocking stage and on the previous
measurement's polygon at reassessment. Neutral for absent data `#9AA3A6`, **always with 45° hatching
and a label** — a gap must not look like a maturity level.

On the radar: polygon outline in `#FF9A45` with `rgba(255,154,69,.30)` fill, vertices in `#FF9A45`
and the blocking stage's vertex in `#E7FF00`. Grid rings in `rgba(255,255,255,.10)`, the outer ring
in `rgba(255,255,255,.22)`.

> **Do not use the blue `#4EA5FF` + purple `#BB8FF2` pair in the same series.** Verified with a
> validator: ΔE of 2.5 under protanopia and 13.4 under normal vision, below the floor of 15. They are
> indistinguishable for some readers.

Thin bars, 4px rounded end at the baseline, 2px gap between segments, recessive grid and axes, text
in the text colour and never in the series colour, a tooltip per mark on hover, **one scale per axis
and never a dual axis**, and a table view on every tab with a chart.

### Header controls — mandatory

**Language selector EN / PT-BR / ES.** Three buttons in the top right corner, the active one marked
with `aria-pressed="true"` and an accent background. The switch **re-renders everything without
reloading the page**: KPIs, tabs, charts, tables, roadmap and the methodology tab. No reload, and no
losing the tab the reader was on.

The dashboard opens in the language chosen at Step 0; the selector is for the reader who receives
the file.

Implementation: a dictionary `L` with the three languages for the labels and a dictionary `D` with
the data that changes by language — indicator names, roadmap items, limitations, formulas. A
`render()` function that rebuilds the document from `L[LANG]` and `D[LANG]`, and an
`applySections()` that reapplies the current tab. `setLang()` only swaps `LANG` and calls `render()`.

**An "Export HTML" button.** It generates a single, self-contained file **with every function of the
artefact preserved** — tabs, radar and bar clicks, drill-down, language switching and the export
itself. It lets the partner send it to the customer and the customer open it offline, depending on
nothing.

Implementation, and every detail below came from a defect found in testing:

```javascript
function exportHTML(){
  const clone = document.documentElement.cloneNode(true);
  clone.setAttribute('data-lang', LANG);          // the exported file opens in the exported language
  const html = '<!DOCTYPE html>\n' + clone.outerHTML;
  const blob = new Blob([html], {type:'text/html;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'ctem-maturity-' + LANG + '-<date>.html';
  document.body.appendChild(a); a.click(); a.remove();
}
```

And at initialisation:

```javascript
let LANG = document.documentElement.getAttribute('data-lang') || 'en';
```

**Three traps, all found in testing and all mandatory to avoid:**

1. **Do not touch the sections' `hidden` attribute in the clone.** The first version removed `hidden`
   from every section "to make sure they showed up", and the exported file opened with all five tabs
   stacked at once. Visibility has to be applied by `applySections()` on load, not written into the
   HTML.
2. **Pass the language through the `<html>` element's `data-lang`.** Without it the `let LANG` falls
   back to the default and the file exported from Spanish opens in English — exactly the opposite of
   what the partner wants when sending it to a customer abroad.
3. **No external resources.** No CDN, no remote font, no image by URL. CSS and JS embedded and images
   as `data:` URIs. The file has to work on a disconnected laptop.

Confirm in testing, by opening the exported file: a single visible tab on load, the right language,
tab switching, drill-down, language switching, and re-exporting from the exported file itself.

### Structure

```
header (title + language selector + export) → KPI bar → tabs 1..5 → footer with sources
```

**KPI bar (5):** effective stage · average stage · the stage that limits the whole · indicators with
data, over that run's scoring total (17 with M4, 16 without) · days since the last assessment.

**Tab 1 — Overview.** The radar of the five stages, and below it the bar with emphasis. Then, in
prose, the sentence naming the blocking stage and the indicator responsible. Last, the table of the
five stages with the stage reached and **how many indicators supported each one**.

At **reassessment**, when the operator supplies a previous run's result, the radar shows the two
polygons overlaid — the previous measurement in recessive grey, the current one in orange — with a
legend and the dates. It is the case where the radar is clearly better than the bar, and the reason
it is here.

**Tab 2 — Indicators.** The table of all 19, grouped by CTEM stage, with the threshold-origin column
visible. Informational and gap indicators marked as such. P3 shows the two parts that compose it: the
declared criterion and the measured opportunity.

**Tab 3 — Official Tenable criteria.** The eight criteria, each with the skill's indicators that
compose it and the resulting stage. It is the tab that allows comparison with an official assessment
the customer may already have answered.

**Tab 4 — Roadmap.** Three quarters, ordered items, with effort, impact and what to do. The item that
unblocks the effective stage highlighted in Q1.

**Tab 5 — Methodology and limitations.** A first-class tab. It contains, in this order: the complete
`PREFLIGHT` table; the plugin set's coverage and weighting declaration with the confidence intervals;
the formulas; the declared gaps, each with its named cause and the evidence supporting it; the
**confirmed proposal table from Step 0**, with the "how I got there" column preserved; and the
**table of the four threshold profiles**, so the reader knows which ruler was used and what the
others would change.

**There are five tabs, and only five.** Preflight and evidence are **not** tabs of their own: they
live inside Methodology, because the reader who wants the number goes to Overview and the reader who
wants to audit goes to one place. Opening a tab for each of them scatters the audit and makes the
report look like a tool report, not an assessment.

---

## Configuration block

It lives in SKILL.md and is overridable at run time. The `conservative` and `aggressive` profiles
shift all cutoffs as a block; `custom` replaces them indicator by indicator.

```yaml
maturity_config:
  language: en                 # en | pt-br | es. Governs report, dialogue and dashboard default
  profile: default             # default | conservative | aggressive | custom
  classify_stage: true         # false = pure indicator mode, Step 4
  rounding: down               # always down; maturity is demonstrated
  aggregation: both            # both = effective and average side by side (recommended)
                               # minimum = weakest link only | mean = average only
  min_indicators_per_stage: 2
  confidence_gate:
    mode: proportional         # proportional (recommended) | absolute
    coef_normal: 0.8125        # ceil(coef × scoring). At 16 gives 13; at 17 gives 14
    coef_with_note: 0.6250     # at 16 gives 10; at 17 gives 11
  mttr:
    days: 180                  # window of POST /vulns/export
    severities: [critical, high]    # M4 scores by the lower stage of the two
    max_wait_s: 240            # on timeout, M4 becomes a RECOVERABLE gap with export_uuid
    min_n_per_severity: 5      # below this the severity does not score in M4
    max_derived_pct: 30        # above this M4 scores with a composition ⚠️
    max_batch_pct: 40          # above this M4 becomes a gap (cadence guard)
    min_batch_per_window: 2    # findings in the same window to count as a batch
    percentile_method: interpolated   # interpolated | nearest_position — must match the server
  sample_plugins:
    n: 30                      # raised from 20 on 2026-09-03: with N=10 the CI is 50 points wide
    n_ceiling: 60              # limit of the adaptive widening
    allocation: proportional   # proportional to each stratum's real share of the population
    stratum_b_floor: 4         # stratum B exists to find cases, not to estimate a rate
    weight_by: by_detection    # by_detection | by_plugin — weight base when combining strata
    ci_gate: true              # widen in blocks of 10 while the 95% CI crosses a cutoff
    plugin_mode: auto          # auto | census | sample. REPLACES census_d4_m3.
                               # The census became reachable: plugins_search_plugins does not accept
                               # a list of IDs, but plugin_details_batch does. Measured 2026-09-04:
                               # 121 critical plugins in 64 s and ~5,400 tokens.
                               # Under a census there is no CI, no weighting and no allocation.
    census_limit: 300          # above this it falls back to the stratified sample
  customer_priority_cutoff:
    metric: vpr                # vpr | cvss3. Default: vpr
    value: 7.0                 # default VPR >= 7.0
    confirmed: false           # true only when the operator actively answers Question 10.
                               # false = default accepted without checking with the customer; P3
                               # scores, and the report must state the criterion was assumed
  deadline_reference: cisa_bod_26_04   # cisa_bod_26_04 | customer_sla | none
  customer_sla:
    critical_days: null
    high_days: null
  licensed_surfaces: [VM]
  customer_mapping:             # answers from Phase B of Step 0, reuse at reassessment
    criticality_category: null
    highest_criticality_values: []
    owner_category: null
    locality_category: null         # only groups the roadmap; does not filter scope
    recurring_scans: []
    uses_exceptions: unknown    # does_not_use | uses_a_little | uses_a_lot | unknown
  cutoffs:
    S1: [20, 50, 80, 95]
    S2: [10, 40, 70, 90]
    S3: [10, 40, 70, 90]
    D1: [90, 45, 14, 7]        # inverted
    D2: [25, 50, 75, 90]       # percentage of licensed surfaces, not a count
    D3: [20, 50, 75, 90]
    D4: [25, 50, 75, 90]
    P1: [10, 40, 70, 90]       # redefined 2026-09-02: business context in the critical backlog
    P2: [40, 70, 90, 98]
    P3: composite              # declared criterion + measured opportunity; its own table
    P3_opportunity: [0.50, 0.20]    # a 0..1 RATIO, not a rate - the one fractional cutoff here
    V2: [180, 90, 30, 14]      # inverted, anchored in CISA BOD 26-04
    V3: [25, 15, 8, 3]         # inverted. A PERCENTAGE, like every rate cutoff here
    V4: [30, 15, 7, 2]         # inverted
    M1: [90, 45, 14, 7]        # inverted. Intervals between DISTINCT assessment DAYS
    collapse_same_day_runs: true    # see the M1 note below. Never disable without declaring it
    M2: [180, 90, 30, 14]      # inverted
    M3: [180, 90, 30, 14]      # inverted
    M4_critical: [90, 30, 15, 7]    # inverted. p50 of days_to_fix, Critical severity
    M4_high: [180, 60, 30, 14]      # inverted. p50 of days_to_fix, High severity
  inverted: [D1, V2, V3, V4, M1, M2, M3, M4]
  informational: [S4, V1]      # do not score a stage
  # P3 has its own stage table and depends on P2 — see references/maturity-indicators.md
```

**Profiles, applied over the default cutoffs:**

| Profile | Effect on the cutoffs | When to use |
|---|---|---|
| `default` | the cutoffs above, as they are | standard assessment. The only profile ever run against a real tenant |
| `conservative` | percentage cutoffs **+10 points** · day cutoffs **−30%** | a regulated customer, or when the assessment has to be defensible in an audit. The same tenant tends to score one stage lower |
| `aggressive` | percentage cutoffs **−10 points** · day cutoffs **+30%** | an initial adoption conversation, so as not to pin everything at Ad Hoc and lose the value of the diagnosis. Declaring the profile is mandatory here: without it the number looks better than the standard ruler would say |
| `custom` | loads its own `maturity_config` block, cutoff by cutoff | a customer with a defined internal SLA, or a partner who standardised its own ruler across accounts. Every overridden cutoff appears marked as `operator override` in the indicators table |

**The profile shifts the ruler, never the formula nor the data source.** Choosing a profile is
choosing how severely the same number is read. That is why it is one of the answers on the Step 0
confirmation screen, and why the report has to show the four options — the reader has to know the
result they are seeing depends on a chosen ruler, and which one.

The chosen profile goes declared in the report. Changing profiles between reassessments **invalidates
the comparison** — the skill must warn prominently if the current run's profile differs from the one
recorded in a previous run supplied by the operator.

---

## ACR and AES on a new asset — pending is not a gap

**An asset seen for the first time does not have an ACR or an AES yet.** Tenable computes these
values within 24 hours of the first scan. Before that the properties come back null, and that is
**not** a maturity gap and not a zero — it is a calculation in progress.

Mandatory check, before any indicator that touches ACR or AES:

```
pending = assets(asset_class = DEVICE) with acr absent
```

Behaviour:

| Situation | Behaviour |
|---|---|
| No pending asset | Proceed normally |
| Some pending | Compute the indicator **excluding the pending ones from the denominator** and declare how many were left out and why |
| All pending | The indicator becomes `pending calculation`, **not** a `gap` and **never** zero. The report states that re-running after 24 hours from the first scan will have the value |

**A mandatory warning at the top of the report** whenever anything is pending, in the chosen language:

> *"ACR and AES pending calculation on N of M DEVICE assets. Those assets were seen for the first
> time in the most recent scan and Tenable computes the values within 24 hours. Re-run after that
> window for the complete reading."*

**A design note that reduces the impact:** in this skill business context is measured by the
**criticality tag**, not by ACR — precisely because the ACR is automatic and the API does not reveal
whether it was human-adjusted. So in a freshly scanned tenant the only indicator without a base is
S4, which is informational and does not score. An assessment that depended on ACR to score would be
unusable in the first 24 hours of a new environment.

---

## Gap handling

| Situation | Behaviour |
|---|---|
| Empty or failed query | The indicator becomes a `gap`. **Never zero** — zero is a value, a gap is an absence |
| Filter rejected in the preflight | The indicator becomes a `gap`, and the report shows the filter and both totals |
| The operator answered "None" to a mapping | The indicator becomes a **gap with a named cause** — "the customer has no owner tag category" — which is a Scoping finding and a roadmap item, not a tool failure |
| The customer uses exception rules | No calculation changes, because the Exposure Management API does not expose the field. The Question 8 caveat enters the report |
| A stage with fewer than 2 indicators | The stage becomes a `gap` and leaves the effective and average calculation |
| `measured < ceil(0.625 × P)` scoring indicators with data | Do not classify. Deliver the indicators and what to enable |
| The MTTR export failed or timed out | M4 becomes a gap with a named cause, `P` drops to 16 and the gate adjusts. If there is an `export_uuid` in the cause, the gap is **recoverable**: resume. **Never** estimate an MTTR |
| `filters_diverged = true` | The server returns a **structured error**, not a number: the slice is not the request. M4 becomes a gap |
| The cadence guard fired | M4 becomes a gap. The number would measure cadence, which M1 and M2 already measure. The finding goes written into the report — it is a result, not a failure |
| A return without a declared batch cutoff, states or percentile method | Should not happen: the server declares all three. If one is missing, treat it as a gap. **Never** accept the summary's number without knowing the method |
| `modified_severity_other_than_none > 0` | Count per severity and declare it. Without that field the assessment is blind to recast and acceptance — with it, the caveat is mandatory in S3, P1, P2 and M4 |
| An unlicensed surface | A clear "surface not licensed" message. Never fail, never report zero |
| A tenant with no scan history | D1, M1 and M2 become gaps. Declare that the Mobilization stage was left without a base |
| Last assessment more than 30 days ago | Open the report with a stale-data warning and the date |
| ACR or AES absent on a new asset | `pending calculation`, never a gap and never zero. Exclude from the denominator and declare it |
| Plugin detail unavailable | Count it separately. **Never** treat absence of data as absence of an exploit |
| The sample's 95% CI crosses a cutoff at the N ceiling | **Do not classify** that indicator. Report the band and say the sample does not separate the two stages |
| Assets with repeated names | A naming-standard finding, **not** an inventory duplicate. If each has its own agent, they are distinct assets and the denominator is correct |

---

## Labels by language

| Element | EN | PT-BR | ES |
|---|---|---|---|
| Title | CTEM Maturity Assessment | Avaliação de Maturidade CTEM | Evaluación de Madurez CTEM |
| Effective stage | Effective stage | Estágio efetivo | Etapa efectiva |
| Average stage | Average stage | Estágio médio | Etapa promedio |
| Limiting stage | Limiting stage | Estágio que limita o conjunto | Etapa limitante |
| Tab 1 | Overview | Panorama | Panorama |
| Tab 2 | Indicators | Indicadores | Indicadores |
| Tab 3 | Official Tenable criteria | Critérios oficiais Tenable | Criterios oficiales de Tenable |
| Tab 4 | Roadmap | Roadmap | Hoja de ruta |
| Tab 5 | Methodology and limitations | Metodologia e limitações | Metodología y limitaciones |
| Stages | Ad Hoc · Defined · Standardized · Advanced · Optimized | Ad Hoc · Definido · Padronizado · Avançado · Otimizado | Ad Hoc · Definido · Estandarizado · Avanzado · Optimizado |
| Scoping | Scoping | Escopo | Alcance |
| Discovery | Discovery | Descoberta | Descubrimiento |
| Prioritization | Prioritization | Priorização | Priorización |
| Validation | Validation | Validação | Validación |
| Mobilization | Mobilization | Mobilização | Movilización |
| Declared gap | Declared gap | Lacuna declarada | Brecha declarada |
| Informational | Informational, not scored | Informativo, não pontua | Informativo, no puntúa |
| Threshold source | Threshold source | Origem do limiar | Origen del umbral |
| Export | Export HTML | Exportar HTML | Exportar HTML |
| File generated | File generated | Arquivo gerado | Archivo generado |
| Pending calculation | Pending calculation | Pendente de cálculo | Pendiente de cálculo |
| Skill criterion | Skill criterion, not Tenable's | Critério da skill, não da Tenable | Criterio de la skill, no de Tenable |
| Gap to next stage | Gap to next stage | Falta para o próximo estágio | Falta para la próxima etapa |
| Effort | Low · Medium · High | Baixo · Médio · Alto | Bajo · Medio · Alto |

---

## Precision notes

1. **Separate fact from interpretation.** The report distinguishes tenant data, skill calculation and
   recommendation. The indicator is data; the stage is a calculation; the roadmap is a recommendation.
2. **No per-stage threshold is official Tenable.** Label it indicator by indicator.
3. **A gap is not a zero.** An indicator without data never becomes zero, and never enters a mean.
4. **Round the stage down.** Maturity is demonstrated.
5. **BOD 26-04 is a reference**, not an obligation of the customer, unless they are a US federal
   agency.
6. **MTTR comes from outside the Exposure Management API, and the origin goes written.** That API
   exposes neither `last_fixed` nor `time_taken_to_fix` — both live in the Vulnerability Management
   API, in `POST /vulns/export`. M4 only scores when the cadence guard clears; otherwise it is a
   declared gap, never an estimate. When it scores, the report shows the native/derived composition
   and the `n` of each severity. Assessment cadence (M1, M2) continues to measure something else, and
   measures it well: **MTTR asks how long it takes to close; cadence asks whether anyone is looking.**
7. **A sample percentage is not a backlog percentage.** Declare the coverage.
8. **Do not convert maturity into a financial number** without a customer premise.

---

## Service hook for the partner

1. **A paid initial assessment.** The diagnosis is the product: nineteen measured indicators, the
   effective and average stage, and the blocking stage named.
2. **Execution of the gaps.** The three-quarter roadmap already comes ordered by effort and impact,
   and Q1 is the immediate statement of work.
3. **Quarterly reassessment.** Running it again shows stage movement against the same ruler. It is
   what turns the assessment into a recurring contract rather than a one-off delivery.

The strongest argument is the difference between the average and the effective stage: it shows the
customer they have already paid for capability they are not converting into results, and points at
exactly where.

---

## Sources citable in the report

- Tenable — Exploring the Exposure Management Maturity Model: https://www.tenable.com/blog/exploring-the-exposure-management-maturity-model
- Tenable — Exposure Management Maturity Assessment, the eight criteria: https://assess.tenable.com/exposure-management-maturity-assessment
- Tenable — How to chart a path to exposure management maturity: https://www.tenable.com/guides/how-to-chart-a-path-to-exposure-management-maturity
- Tenable Docs — Exposure Management Metrics, the CES, AES, ACR and VPR bands: https://docs.tenable.com/exposure-management/Content/getting-started/metrics.htm
- Tenable — CISO's guide to CISA BOD 26-04: https://www.tenable.com/blog/bod-26-04-ciso-reporting-risk-metrics
- Tenable — VPR Drivers: https://developer.tenable.com/docs/vpr-drivers-tio
