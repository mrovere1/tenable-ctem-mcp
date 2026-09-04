# tenable-ctem-mcp

**Local (stdio) MCP server** that delivers the 19 indicators of Tenable's CTEM assessment already
aggregated, plus MTTR — which the Exposure Management API does not reach directly.

> **Community / partner tooling. Not a Tenable product and not supported by Tenable.**
> Validated in a laboratory. Test it in your own environment before using it in production.
> GitHub issues are the channel, with no promised SLA.

> **New here?** [`OVERVIEW.md`](OVERVIEW.md) is the complete description: what the server and the
> skill are, how to install and run them, the points of attention before showing a report to a
> customer, the 13 tools and the 19 indicators. This README is the quick start.

## What it is

A local server that moves the aggregation to the server and returns finished numbers. Every
indicator comes with `value`, `n`, `literal_filter`, `collected_at_utc` and `preflight_verdict`. A
query that failed becomes a **declared gap with a cause** — a silent partial number is forbidden.

| | Through the official MCP | With this server |
|---|---|---|
| Calls for the 19 indicators | ~40 | ~7 (**4 for the 15 from S to V**, measured) |
| Detail of 20 plugins | 20 calls, ~31,900 tokens | 1 call, ~900 tokens (**−97.2%**, measured) |
| Plugin coverage | a sample of 20, with a 37-point CI | **a census of all 121 critical**, ~5,400 tokens, no CI |
| MTTR | impossible; requires an external Python script | 1 tool |
| Cadence (M1) | 12 raw runs, collapsed on the client | already collapsed: median **21 d**, not 1.42 |

## What it is not

A clone of Tenable's official MCP, a generic MCP, a hosted server, or a Tenable product.

## Installation

Requires Python 3.12.

```bash
uv venv --python 3.12
uv pip install .
```

> **Do not use `-e` (editable) here.** In a venv created by `uv`, the `.pth` from hatchling's
> editable install is discarded by `_virtualenv.pth`, which sorts after it, and the package becomes
> unimportable through `python -m`. To develop, use `uv run python -m tenable_ctem_mcp.server`,
> which resolves the project without depending on the `.pth`.
>
> A consequence worth knowing: the MCP client runs the copy in `site-packages`, while the tests read
> `src/`. **After editing the source, run `uv pip install .` before restarting the client** —
> otherwise `pytest` is green and the running server is stale.

## Credentials

**Environment variables only.** Never as a tool parameter, never in a config file, never in a log.
The key is generated in your tenant under **Settings › My Account › API Keys**.

```bash
export TIO_ACCESS_KEY=...
export TIO_SECRET_KEY=...
export TIO_URL=https://cloud.tenable.com     # optional
```

Permission required: the Basic [16] role, or the `VM.VM_EXPLORE` and
`ASSET_INVENTORY.CYBER_ASSET_MANAGEMENT.READ` privileges.

### On a network that inspects TLS

```bash
export TIO_CA_BUNDLE=/path/to/company-ca.pem
export TIO_CA_KEYCHAIN=1          # macOS: use the Keychain as the trust source
```

**There is no option to disable certificate verification, and there should not be.** Without
verification, the tenant's API keys travel over a channel that may be being read by a third party.
See `docs/troubleshooting.md`.

## Usage

```bash
# development: the Inspector shows the raw request and response JSON
npx @modelcontextprotocol/inspector uv run python -m tenable_ctem_mcp.server

# register in Claude Code, WITHOUT --env
claude mcp add tenable-ctem -- /path/to/.venv/bin/python -m tenable_ctem_mcp.server
```

**Do not pass the keys with `--env`:** that would write them into `~/.claude.json`, and a credential
in a configuration file is exactly what this project forbids. Export them in the shell and open the
client from it — a child process inherits its parent's environment. Step by step in
`docs/client-setup.md`.

## Tools

Twelve assessment tools, plus `ctem_diagnostics` for troubleshooting — thirteen in total. The full
contract is in `docs/tools.md`.

**Acceptance run, measured end to end over the stdio transport:** the 19 indicators in **6 tool
calls**, with M4 as the only gap — and a gap on merit, because the cadence guard fires.

| Group | Tools |
|---|---|
| Discovery and preflight | `ctem_discover_tenant`, `ctem_preflight` |
| Indicators by stage | `ctem_scoping`, `ctem_discovery`, `ctem_prioritization`, `ctem_validation`, `ctem_mobilization` |
| Primitives | `plugin_details_batch`, `plugin_census`, `scan_cadence`, `mttr_collect`, `mttr_cadence_guard` |
| Diagnostics | `ctem_diagnostics` |

## Language

The code, the documentation and the skill are in **English**. The Tenable vocabulary
(`plugin_id`, `first_found`, `severity`, …) is kept as Tenable writes it, and the tag-category hints
are **trilingual (EN, PT, ES) with accent folding**, because the customer's tenant is almost always
in the customer's language.

The **report** produced by the skill is generated in the language the operator chooses at Step 0 —
**EN, PT-BR or ES** — and the delivered dashboard carries all three behind a header selector. Data
read from the tenant is printed exactly as it exists there.

## Tests

```bash
.venv/bin/python -m pytest
```

Runs in full **with no tenant at all**: the fixtures are recorded, sanitised responses.
`tests/test_fixture_safety.py` fails if any fixture contains a key pattern, a real IP or a hostname
— and it carries a guard test proving its own patterns catch the two cases that once escaped.

## Licence

MIT. See `LICENSE`.
