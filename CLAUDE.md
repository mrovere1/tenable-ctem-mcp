# tenable-ctem-mcp

**Local (stdio) MCP server** that delivers the 19 indicators of Tenable's CTEM assessment already
aggregated, plus MTTR — which the Exposure Management API does not reach directly.

Project reference documentation: `_docs/plano-mcp-ctem.md`. Read it before starting.

---

## Working language

**English is the base language of this repository.** Code, identifiers, docstrings, comments, tests,
documentation and the skill are written in English, because the repository is meant to be handed to
engineers in other countries.

Two deliberate exceptions:

1. **The Tenable vocabulary stays as Tenable writes it** — `plugin_id`, `first_found`, `last_fixed`,
   `severity`, `state`, `asset_class`, `exposure_classes`, `date_range`, `tag_count`. Those are the
   API's names, not ours, and translating them would break the mapping to the documentation.
2. **The tag-category hints in `scoping.py` are trilingual — EN, PT and ES** — and matching folds
   accents, so one unaccented entry covers every spelling (`classificacao` finds `Classificação`,
   `dueno` finds `Dueño`). The customer's tenant is almost always in the customer's language, so an
   English-only list would fail on exactly the tenants this skill exists to assess. Short hints
   (three characters or fewer) match a whole token only: `bu` as a substring was matching
   "Business Impact" and "backup".

The **report** produced by the skill is a separate matter: its language is chosen by the operator at
Step 0, among EN, PT-BR and ES. Data read from the tenant — tag names, tag values, scan names — is
printed exactly as it exists there, in whatever language it was created.

---

## What this server is and is not

**It is:** a local, stdio server that moves the aggregation to the server and delivers finished
numbers with `value`, `n`, `literal_filter`, `collected_at_utc`, `preflight_verdict`.

**It is not:** a generic MCP, a hosted server, or a Tenable product. Purpose-built for one
assessment, with no tools beyond it.

The performance gain comes from cutting the calls from ~40 to ~7 and from ~15,000 to ~1,500 tokens
for the 19 indicators plus 20 plugins. **Any change that undoes that gain is wrong.**

---

## Architecture — closed decisions. Do not reopen them.

| Decision | Value |
|---|---|
| Language | Python 3.12 |
| MCP framework | The official MCP Python SDK. In 2.x, FastMCP was renamed `MCPServer` — same ergonomics |
| Transport | **stdio**. No HTTP, no hosting, no network authentication |
| Granularity | One tool per CTEM stage + 5 primitives + discovery + preflight + diagnostics. **13 tools** |
| Subset parameter | Every stage tool accepts `indicators: list[str] \| None`. If `None`, it computes every indicator of the stage |
| Credentials | Only through the `TIO_ACCESS_KEY`, `TIO_SECRET_KEY`, `TIO_URL` environment variables. Never as a tool parameter, never in a log |
| Async export | `mttr_collect` with `max_wait_s`. Returns `status: pending` + `export_uuid` on timeout — it never blocks indefinitely |
| Cache | In memory, per process, short TTL, keyed by the literal filter. Mandatory in `ctem_discover_tenant` and `plugin_census` |
| Pagination | Internal, invisible to the caller. No tool exposes `offset` |
| Errors | Structured, never a silent partial number. A query that failed becomes a declared gap with a cause |
| Rate limit | Exponential backoff honouring the `retry-after` header. The Tenable limit is **dynamic**; do not hard-code a number |
| Single execution path | There is no parallel collector. If the MCP fails, every indicator fails. `mttr_collect` is the only path to MTTR |
| v1 scope | CTEM only. No generic tools for other skills. **The measurement scope is the whole tenant** — no filtering by environment or exclusion by tag |
| Support | Community. The README and the Exchange state: "community/partner tooling, not supported by Tenable" |

---

## Repository structure

```
mcp-ctem/
  CLAUDE.md                   # this file
  README.md                   # installation, keys, laboratory notice, scope, support
  LICENSE
  pyproject.toml
  .gitignore                  # see the Security section
  src/tenable_ctem_mcp/
    __init__.py               # the Indicator ENVELOPE
    server.py                 # registration of the 13 tools, nothing else
    client.py                 # HTTP for the Tenable API: auth, TLS, backoff, pagination, cache
    preflight.py              # discriminant pairs and the filter deny-list
    indicators/
      __init__.py
      scoping.py              # S1, S2, S3, S4
      discovery.py            # D1, D2, D3, D4 + discover_tenant
      prioritization.py       # P1, P2, P3
      validation.py           # V1, V2, V3, V4
      mobilization.py         # M1, M2, M3, M4
    mttr.py                   # port of tenable_mttr_export.py 1.1.0 — do not rewrite from scratch
    plugins.py                # plugin_details_batch, plugin_census, census and sampling
    cadence.py                # collapsing runs into distinct assessment days
  tests/
    fixtures/                 # recorded sandbox responses, sanitised
    test_indicators.py        # golden tests with the numbers measured 2026-09-02/03
    test_preflight.py
    test_mttr.py
    test_fixture_safety.py    # fails if any fixture looks like it holds a key, IP or hostname
  docs/
    tools.md                  # the contract of each tool: parameters, return, errors
    limitations.md            # what the API does not deliver, with proof
    troubleshooting.md        # real cases: 401, 409, TLS, empty collection, ignored filters
    client-setup.md           # registering the server without writing keys to a config file
```

---

## Tool surface

### Discovery and preflight

```
ctem_discover_tenant(use_cache=True)
  → tag categories and values, counts by asset_class, exposure_classes present,
    scans with history, agents
  → replaces ~10 calls of Step 0 Phase A
  → cached with a short TTL

ctem_preflight(workbenches_severity="critical")
  → the finished PREFLIGHT table: every filter the skill uses, tested with a discriminant pair
```

### Indicators by stage

```
ctem_scoping(mapping, indicators=None)                → S1–S4
ctem_discovery(indicators=None, ...)                  → D1–D4
ctem_prioritization(mapping, indicators=None, ...)    → P1–P3 + the compared queues
ctem_validation(mapping=None, indicators=None, ...)   → V1–V4
ctem_mobilization(mapping=None, indicators=None, ...) → M1–M4
```

`mapping` carries exactly three keys, and the server guesses none of them:
`criticality_category`, `owner_category`, `recurring_scans`.

### Primitives and diagnostics

```
plugin_details_batch(plugin_ids)      → five fields only. The project's biggest token win
plugin_census(severity)               → the sampling frame, cached
scan_cadence(scan_ids, ...)           → collapses runs into distinct assessment days
mttr_collect(days, severities, ...)   → POST /vulns/export with polling and chunked download
mttr_cadence_guard(windows, ...)      → detects "MTTR = the interval between scans"
ctem_diagnostics()                    → can the server talk to the tenant? Never prints the key
```

**`scan_cadence` warning:** without the collapse, the M1 median is 1.42 days; with it, 21. Two
stages of difference. **This collapse MUST happen on the server, never on the client.**

---

## The return contract of every indicator

Every indicator, in every tool, returns this envelope. Never deviate.

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

If the query fails, `value` is `null` and `gap` is `true` with `cause` filled in.
**A silent partial number is forbidden. It is the central rule of the project.**

---

## Units — the trap that already caught us once

**Every rate is a percentage**, and its cutoffs are whole numbers: S1 `[20, 50, 80, 95]`,
P2 `[40, 70, 90, 98]`, V3 `[25, 15, 8, 3]`. The one 0..1 fraction is `P3_opportunity`, because it is
a ratio and not a rate.

V3 carried fractional cutoffs `[0.25, 0.15, 0.08, 0.03]` while the collection returned `18.0`. Being
inverted, it fell into the worst bucket every time. Found in the audit of 2026-09-04, and latent
until then because V2 and V4 already bottomed out Validation. A test now pins the unit.

---

## `mttr_collect` rules — they must not be lost in the port

The `tenable_mttr_export.py` 1.1.0 collector already solved these three behaviours. Keep them:

1. `max_wait_s` exceeded → `{status: "pending", export_uuid: "<uuid>"}`. It does not raise.
2. `filters_diverged = true` → a structured error, not a number. The slice is not the request.
3. A TLS failure → a diagnosed cause ("corporate proxy intercepting TLS"), not a raw exception.
   **The server NEVER offers an option to disable certificate verification.**

`TIO_CA_BUNDLE` is the mechanism for networks with TLS inspection. Document it in
`docs/troubleshooting.md`.

---

## Filter deny-list (`preflight.py`)

The deny-list must reject before reaching the API. Confirmed cases:

- `filters` as free text → silently ignored by the API. The server rejects it with an error.
- an operator with an empty `value` → answers 400 "Missing value in filter". Rejected before sending.
- the relative date operators on findings → accepted and silently ignored.
- `authenticated`, `exploitable`, `resolvable`, `age` in workbenches → accepted and not applied.

Consult `_docs/matriz-confianca-filtros-mcp.md` for the source list, and `docs/limitations.md` for
the **four verdicts that differ on the direct API**. Do not duplicate the list here — import it and
keep it in one place.

---

## Tests

**Golden tests** with the numbers measured on 2026-09-02/03 (sources:
`_docs/execucao-maturidade-sandbox-2026-09-03.md` and
`_docs/validacao-dados-coleta-mttr-2026-09-03.md`). Any divergence is a failure — do not adjust the
test to make it pass, investigate the cause.

**Fixtures:** recorded sandbox responses, sanitised **structurally** (by key, not by value shape).
They must:
- contain no hostname, IP, real UUID or customer name
- allow `pytest` with no tenant at all
- be validated by `test_fixture_safety.py`, which also carries a guard test proving its own patterns
  catch the two cases that escaped a regex-based pass

`pytest` must pass in full before every commit. CI on GitHub checks this.

**Note on the install:** it is deliberately **not editable** (see `docs/troubleshooting.md`). Tests
read `src/` through `pythonpath`, but the MCP server runs the copy in `site-packages` — so `pytest`
can be green while the running server is stale. Run `uv pip install .` before restarting the client.

---

## Security — before the first `git push`

1. `.gitignore` includes: `*.csv`, `*_resumo_*.json`, `.env`, `__pycache__`, `*.key`, `*.pem`
2. Secret scanning and push protection enabled on the GitHub repository
3. Keys only in environment variables. Never in a parameter, a config file or a log
4. `test_fixture_safety.py` fails if any fixture contains a key pattern (`[A-Fa-f0-9]{32,}`), a long
   opaque identifier (16+ hex, with no left word boundary), any IP outside the RFC 5737
   documentation ranges, or a sandbox hostname

---

## Development order — milestones with a done criterion

All milestones M0–M6 are complete and validated against the sandbox tenant. The criteria are kept
because they are what a regression would break.

| Milestone | Done when |
|---|---|
| M0 | `ctem_discover_tenant` returns the sandbox's 9 tag categories through the Inspector |
| M1 | `pytest -k "scoping or discovery"` passes with the measured S1–S4 and D1–D4 |
| M2 | `pytest -k "prioritization or validation"` passes |
| M3 | `pytest tests/test_preflight.py` passes, including the two cases of 2026-09-03 |
| M4 | the three mandatory `mttr_collect` behaviours each have their own test |
| M5 | the M1 median is 21 days on the sandbox fixture, **not 1.42** |
| M6 | the 19 indicators appear in the final report with no unexpected gap; M4 is a gap **on merit** |

---

## Validation workflow

1. **MCP Inspector first:** `npx @modelcontextprotocol/inspector`. It shows the raw request and
   response JSON. Use it for every new tool before moving to the Claude client.
2. **`pytest` before every commit.** No exceptions.
3. **The Claude client only for end-to-end validation.** Every change to the server requires
   reinstalling and restarting the client — do not use it to iterate.

---

## What not to do

- **Do not rewrite `mttr.py` from scratch.** It is a port of `tenable_mttr_export.py` 1.1.0, which
  already solved corporate TLS, 409 resumption, chunked download, the interpolated percentile and
  the self-test.
- **Do not add generic tools** for other skills. v1 scope = CTEM.
- **Do not expose extra fields in `plugin_details_batch`.** The token saving depends on it.
- **Do not use synchronous polling in `mttr_collect`.** Return `status: pending` on timeout.
- **Do not redistribute the OpenAPI files** from the `API Specs` folder in the public repository.
  Reference the developer.tenable.com URL.
- **Do not invent rate limits.** The limit is dynamic; read the `retry-after` header.
- **Do not adjust golden tests to make them pass.** Investigate the divergence.
- **Do not let two agents edit at the same time.** One repository, small commits, one agent at a
  time. Finish and commit before handing over.
- **Do not add a profile field the indicators do not consume.** A field the operator fills in and
  nobody reads is worse than an absent field — it was that reasoning that removed `exclude` and
  `production_values` from the skill's profile.

---

## References

| File | Purpose |
|---|---|
| `_docs/plano-mcp-ctem.md` | Full briefing: scope, tool contract, milestones |
| `_docs/auditoria-mcp-ctem-2026-09-04.md` | External audit and what was done about each finding |
| `the repository root (SKILL.md + references/)` | The MCP's consumer; carries the formulas, cutoffs and thresholds |
| `_ferramentas/mttr-export/tenable_mttr_export.py` | The basis of `mttr.py`. Version 1.1.0 |
| `_docs/validacao-dados-coleta-mttr-2026-09-03.md` | MTTR numbers for the golden tests |
| `_docs/execucao-maturidade-sandbox-2026-09-03.md` | The 19 indicators' numbers for the golden tests |
| `_docs/matriz-confianca-filtros-mcp.md` | Deny-list, measured through the earlier collection path |
