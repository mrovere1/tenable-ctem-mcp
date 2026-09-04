# Tenable CTEM Maturity Assessment — MCP server and skill

Two pieces that ship together and are useless apart.

| | What it is |
|---|---|
| **`tenable-ctem-mcp`** | A local MCP server. It talks to a Tenable One tenant and returns **finished, aggregated numbers** — 19 indicators plus MTTR — each with the literal filter that produced it |
| **`tenable-ctem-maturity-assessment`** | A Claude skill. It runs the conversation with the operator, applies the maturity thresholds, classifies the customer across the five official stages, and produces the report and dashboard |

The server measures. The skill judges. That separation is deliberate: the numbers are auditable and
the judgement is configurable, and neither can quietly contaminate the other.

> **Community / partner tooling. Not a Tenable product and not supported by Tenable.**
> Validated in a laboratory tenant. Test it in your own environment before using it with a customer.
> Read only — no write tool is ever called.

---

## Why it is built this way

Three design decisions carry the whole project, and each came from a problem measured in a real
tenant rather than anticipated on paper.

**1. The aggregation happens on the server.** The client asks for an indicator and receives a
finished number with the literal filter that produced it. This is not only about cost — it prevents
a class of error. The raw runs of a recurring scan gave a median assessment cadence of 1.42 days;
collapsed into distinct assessment days, 21. **Two maturity stages apart, with nothing in the output
signalling that anything was wrong.** Aggregation logic that lives on the client gets re-implemented,
slightly differently, every time someone touches it. Here it lives in one place and has a test.

**2. Only the fields that are used are returned.** The full detail of a single plugin is ~8,200
characters across 97 attributes; the assessment uses five of them. Returning five fields instead of
97 is what makes a **census** of every critical plugin affordable — and a census removes the
confidence interval, the weighting base and the allocation bias that a sample forces you to manage
and declare.

**3. Time-to-fix is inside a tool.** The fields that make MTTR computable are not part of the
inventory API this assessment otherwise reads; they live behind an export endpoint with polling and
chunked download. Wrapping that in a tool is what keeps the assessment to a single execution path,
instead of a script run by hand on the side with a CSV carried back in.

The result is the 19 indicators in roughly seven tool calls, with evidence attached to every number.

---

## Installation

### 1. The server

Requires **Python 3.12**.

```bash
git clone <repository>
cd mcp-ctem
uv venv --python 3.12
uv pip install .
```

> **Do not use `-e` (editable).** In a venv created by `uv`, hatchling's editable `.pth` is discarded
> by `_virtualenv.pth`, which sorts after it, and the package becomes unimportable through
> `python -m`. A consequence to remember while developing: the MCP client runs the copy in
> `site-packages`, so **run `uv pip install .` again after editing the source**, or the tests will be
> green while the running server is stale.

### 2. Credentials

**Environment variables only.** Never as a tool parameter, never in a config file, never in a log.
Generate the key in the tenant under **Settings › My Account › API Keys**.

```bash
export TIO_ACCESS_KEY=...
export TIO_SECRET_KEY=...
export TIO_URL=https://cloud.tenable.com     # optional, this is the default
```

Permission required: the **Basic [16]** role, or the `VM.VM_EXPLORE` and
`ASSET_INVENTORY.CYBER_ASSET_MANAGEMENT.READ` privileges.

On a network that inspects TLS, point at the corporate bundle:

```bash
export TIO_CA_BUNDLE=/path/to/company-ca.pem
export TIO_CA_KEYCHAIN=1          # macOS: use the Keychain as the trust source
```

### 3. Registering the server

```bash
claude mcp add tenable-ctem -- /path/to/mcp-ctem/.venv/bin/python -m tenable_ctem_mcp.server
claude                              # open the client FROM THIS shell
```

**Do not pass the keys with `--env`.** That writes them into `~/.claude.json`, and a credential in a
configuration file is exactly what this project forbids. A child process inherits its parent's
environment: export the keys in the shell and open the client from it, and the server receives them
without anyone writing them anywhere.

### 4. The skill

Install `the repository root (SKILL.md + references/)` — the directory or the `.skill.zip`. The skill
carries its own reference files and works standalone once installed.

---

## Running it

Check the connection before anything else:

```
ctem_diagnostics()
```

| `verdict` | Meaning |
|---|---|
| `ok` | proceed |
| `credential_missing` | the client did not inherit the environment — reopen it from the shell with the exports |
| `credential_invalid` | a key from another container, or a trailing space in the variable |
| `failure` / `tls_corporate_proxy` | set `TIO_CA_BUNDLE` |

It never prints the key, nor any part of it.

Then ask for the assessment in plain language — *"run a CTEM maturity assessment"*. The skill:

1. **Step 0 — discovers and confirms.** One call reads the tenant and the skill proposes a mapping:
   which tag category is criticality, which is owner, which scans represent the recurring
   assessment. **It proposes; the operator confirms.** It never guesses from a keyword alone.
2. **Step 1 — preflight.** Every filter it will use is tested live against the tenant.
3. **Step 2 — collects.** Five calls, one per CTEM stage, 19 indicators already aggregated.
4. **Steps 3–5 — classifies** each indicator into a stage, derives the stage of each CTEM stage,
   and orders the gaps into a three-quarter roadmap.
5. **Step 6 — delivers** a single self-contained HTML dashboard.

**Report language is chosen at Step 0 — EN, PT-BR or ES.** It governs the operator dialogue, the
report prose and the dashboard's initial language. Data read from the tenant — tag names, tag
values, scan names — is printed exactly as it exists there.

---

## Points of attention

**Read these before showing a report to a customer.**

### The thresholds are ours, not Tenable's

No official Tenable material publishes a numeric threshold per maturity stage. The model is
qualitative and the official assessment uses eight declarative criteria with no published score
bands. Every cutoff in this skill is labelled in the report with its origin: `Tenable official`,
`cited external (CISA BOD 26-04)`, `skill default` or `operator override`.

Presenting a percentage as if it were a Tenable criterion would be inaccurate. The report is built
to make that distinction impossible to miss.

### A gap is not a zero

A query that fails never becomes a number. It becomes a **declared gap with a named cause**, and the
indicator leaves the calculation. A silent partial number is forbidden — it is the central rule of
the project, because a wrong number that looks right carries no signal that it happened.

### M4 (MTTR) may come back as a gap, and that is the correct result

`time_taken_to_fix` measures detection to detection, not time to act. An asset scanned in June, not
scanned again, and seen clean in September produces 85 days for everything on it — including what
was fixed on the first day.

When the MTTR windows turn out to be made only of scan dates, the server declares M4 a gap. Scoring
it would measure the same thing the cadence indicators already measure, counting cadence twice and
calling remediation maturity what is in fact assessment maturity. **The report writes the finding in
prose, because it is worth more than the lost number** — and "increase assessment frequency on this
asset" becomes a roadmap item.

### The measurement scope is the whole tenant

v1 measures the complete corpus. There is no filtering by environment and no exclusion by tag. This
is stated rather than silently assumed: a field the operator fills in and nobody consumes is worse
than an absent field.

### Some filters are accepted and silently ignored

The API accepts filters it does not apply and returns no error — the query looks filtered and
returns the whole corpus. The server carries a deny-list that rejects those **before the request
leaves**, with the measured proof attached to the error, and `ctem_preflight()` re-tests everything
live against the tenant of the moment.

### New assets have no ACR or AES for 24 hours

Tenable computes those within 24 hours of the first scan. Before that they come back null, which is
**pending calculation**, not a gap and not a zero. The report says so and recommends re-running.

### One path, not two

There is no parallel collector. If the MCP fails, every indicator fails. That is deliberate: keeping
a fallback only for MTTR would not change the skill's outcome, and two paths mean two sets of
numbers to reconcile.

---

## The 13 tools

### Discovery and preflight

| Tool | What it does |
|---|---|
| `ctem_discover_tenant` | The tenant in one call: tag categories and values, asset counts by class, which exposure surfaces are present, scans with history, agents. Replaces ~10 calls. Cached |
| `ctem_preflight` | Tests every filter the skill uses, live, with a discriminant pair. Returns the finished table plus the deny-list, each rule with its measured proof |

### Indicators, one tool per CTEM stage

| Tool | Returns |
|---|---|
| `ctem_scoping` | S1–S4 |
| `ctem_discovery` | D1–D4 |
| `ctem_prioritization` | P1–P3, plus the three compared prioritisation queues |
| `ctem_validation` | V1–V4 |
| `ctem_mobilization` | M1–M4, with the MTTR cadence guard already applied |

Every stage tool accepts `indicators=["V2","V3"]` to recompute only a subset — useful for re-running
one indicator that came back as a gap without paying for all 19 again.

### Primitives

| Tool | What it does |
|---|---|
| `plugin_details_batch` | Detail for many plugins in one call, with **five fields only**. The project's largest token saving depends on this staying at five |
| `plugin_census` | The sampling frame: every plugin of a severity with its detection count, VPR and family. Cached |
| `scan_cadence` | Collapses scan runs into **distinct assessment days**. Always returns the uncollapsed median alongside, so the contrast stays visible |
| `mttr_collect` | MTTR through the export API, with polling and chunked download. Never blocks: on timeout it returns a ticket to resume |
| `mttr_cadence_guard` | Says whether an MTTR is really measuring the interval between scans |

### Diagnostics

| Tool | What it does |
|---|---|
| `ctem_diagnostics` | Can the server talk to the tenant? Separates a missing credential from an invalid one from an intercepted TLS connection. Never prints the key |

---

## The 19 indicators

Five CTEM stages. **17 score a stage; 2 are informational** and carry context without being
converted into maturity. Where a lower number is better, the indicator is marked *inverted*.

Formulas, cutoffs and threshold origins live in the skill's reference files. What follows is what
each indicator measures.

### Scoping — is the estate known and described?

| ID | Measures | Metric |
|---|---|---|
| S1 | Assets carrying at least one tag | % of assets |
| S2 | Assets carrying a business-criticality tag | % of assets |
| S3 | Assets carrying an owner tag | % of assets |
| S4 | Whether crown jewels are declared at all | yes/no · **informational** |

*S4 is informational because the API does not reveal whether an asset's criticality rating was set
by a human or computed automatically. It measures the declaration of context, not curation.*

### Discovery — is the estate actually being looked at?

| ID | Measures | Metric |
|---|---|---|
| D1 | Time since the most recent assessment | days · *inverted* |
| D2 | Licensed exposure surfaces that carry real data | % of licensed surfaces |
| D3 | Device assets covered by an agent | % of devices |
| D4 | Detections coming from authenticated (local) checks | % of plugins |

*D2 is a ratio, not a count: a customer licensing two surfaces and covering both is fully covered.
D3's denominator is devices only — identities, accounts and groups have no software installed.*

### Prioritization — does business context reach the decision?

| ID | Measures | Metric |
|---|---|---|
| P1 | Critical backlog sitting on assets that have declared criticality | % of the critical backlog |
| P2 | Backlog with a threat-based priority score available | % of the active backlog |
| P3 | Whether the customer's stated prioritisation criterion fits their data | composite stage |

*P1 is not the agreement between two scoring models — that has no defensible direction of maturity.
A customer with 27% of assets tagged but 100% of the critical backlog on tagged assets tagged the
right assets, and that is more mature than the reverse.*

*P3 combines what the customer says they do with what the data shows they could gain. "The customer
does not know which criterion they use" is itself the first stage, and the skill records it as such
rather than assuming a default.*

### Validation — is the risk picture accurate and durable?

| ID | Measures | Metric |
|---|---|---|
| V1 | Findings with a publicly available exploit | % of plugins · **informational** |
| V2 | How long known-exploited vulnerabilities have been present | median days · *inverted* |
| V3 | Fixes that did not hold — findings that came back | % recurrence · *inverted* |
| V4 | Devices running software the vendor no longer supports | % of devices · *inverted* |

*V1 is informational because a high exploit rate can mean a bad backlog or simply an environment
built on a popular stack, which concentrates exploit research. Without a customer premise, turning
it into a stage would be interpretation rather than measurement.*

*V2 is the strongest indicator of the set and the only one with a citable external anchor: its
cutoffs derive from the remediation tiers of CISA BOD 26-04. The report states that the directive
binds US federal agencies and is used here as a recognised deadline reference, not as an obligation
of the customer.*

### Mobilization — does anything actually get fixed?

| ID | Measures | Metric |
|---|---|---|
| M1 | How regularly the environment is assessed | median days between assessments · *inverted* |
| M2 | The longest stretch with no assessment at all | days · *inverted* |
| M3 | How long fixes have been available but not applied | median days · *inverted* |
| M4 | Time to close, for critical and high findings | median days · *inverted* |

*M1 counts distinct assessment days, not raw scan runs: a scan relaunched minutes later is the same
assessment, not a new cycle. This collapse happens on the server precisely because it once lived on
the client and produced a two-stage error that survived a whole run.*

*M4 scores as the **lower** of its two severities. Mature mobilisation closes both critical and
high; it does not offset one with the other. It becomes a declared gap when the cadence guard fires
— see the points of attention above.*

### How the stages are derived

Each indicator lands in one of the five stages by its own cutoffs. A CTEM stage is the mean of its
scoring indicators, **rounded down** — maturity is demonstrated, not presumed. The report then
publishes two numbers side by side:

- **Effective stage** — the lowest of the five. The CTEM stages are sequentially dependent: without
  business context at Scoping, downstream prioritisation is already compromised.
- **Average stage** — the arithmetic mean.

**The difference between them is the report's central argument.** A customer averaging Standardized
with an effective stage of Ad Hoc has paid for capability that one blocking stage is preventing from
turning into results — and the report names that stage, and the indicator responsible, in prose.

A confidence gate runs before any of this is published: below a proportional threshold of measured
indicators, the skill **declines to classify** and delivers the indicators with what needs enabling
in the tenant instead.

---

## Reference documents

| File | Purpose |
|---|---|
| `docs/tools.md` | The full contract of every tool: parameters, return, errors |
| `docs/limitations.md` | What the API does not deliver, with the measurement that proves it |
| `docs/troubleshooting.md` | Real cases: 401, 403, 409, TLS, empty collections, ignored filters |
| `docs/client-setup.md` | Registering the server without writing keys into a config file |
| `CLAUDE.md` | The project's closed decisions and why each one is closed |

## Licence and support

MIT — see `LICENSE`.

Community and partner tooling. GitHub issues are the channel, with no promised SLA. This is not a
Tenable product and Tenable does not support it.
