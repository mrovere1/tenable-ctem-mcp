# Fixtures

`sandbox_2026-09-03.json` holds real responses from the Tenable API, recorded from the laboratory
tenant on 2026-09-03 and **sanitised structurally**. They let the whole of `pytest` run **with no
tenant at all** and with no key.

## How they were sanitised

Structurally, by looking at the **key** of each field — not with a regex over the text. A regex
already failed once: `"schedule_uuid": "template-01df1e4e-…"` got through because the identifier
carries a prefix and `\b` never matched, and `31.0.0.x` addresses got through because the pattern
only covered the private ranges.

| Goes out | Stays |
|---|---|
| `*uuid*`, `ip`, `ipv4/6`, `mac`, `fqdn`, `netbios`, `hostname`, `email`, `login`, `owner`, `target*` | plugin and scan ids (public Tenable identifiers, not the customer's) |
| `name` inside `/agents` and `/scans` (that is a machine name) | plugin name and family, tag category name and value |
| — | counts, totals, run dates, scores |

Without what stays there is no golden test. `tests/test_fixture_safety.py` fails if anything escapes.

## One declared reduction

The preflight calls `/workbenches/vulnerabilities` ten times varying parameters, and from every one
of them reads **only `len(vulnerabilities)`**. Keeping ten copies of the same 121 complete plugins
doubled the file without adding any proof, so in those responses each plugin became
`{"plugin_id": N}` — which preserves the count, the one piece of data that is read. They carry the
`_reduced` field saying so.

**The census's base call is intact**, with name, family, count and VPR: D4, V1, V2 and M3 come from
it.

## How they are consumed

`tests/conftest.py` replaces `client.call` and `client.paginate` with a replay indexed by the
`[method, path, body, params]` signature. A query that is not recorded **breaks the test** — it
never returns empty, because empty would become a wrong number.

## `mttr_export_2026-09-03.json`

The **normalised rows** of `POST /vulns/export`, not the raw response. The raw response holds 4,278
findings with dozens of fields each and would pass 10 MB; `summarise()` and `detect_batches()` read
**nine fields**. Recording only those preserves the whole proof — every number of the M4 golden test
comes from here — and fits in the repository.

Two reductions, both declared:

- **Columnar form.** One list of values per row, in the order of `fields`, instead of repeating the
  nine keys 4,278 times. 1,079 KB → 269 KB.
- **`asset_name` became a stable label** (`asset-001`…). The real name only matters for **grouping**
  `(asset, first_found, last_fixed)` windows, and the label preserves the grouping.

## Plugin details: one whole response, the rest trimmed

The census of the 121 critical plugins would bring 121 responses of ~8,200 characters with **97
attributes each** — nearly 1 MB to feed five fields. `_five_fields()` reads **six attributes**.

So: the response for plugin **314348 stays whole**, marked `_complete`, so the fixture goes on
proving the size that justifies `plugin_details_batch`. The other 120 keep only the attributes that
are read, marked `_trimmed`. The extraction is still under test — it goes through the same
`attributes` list.
