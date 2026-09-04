# Registering the server in Claude Code

## The conflict, and how it resolves

`claude mcp add` writes the configuration into `~/.claude.json`. Passing the keys there with `--env`
would **write them into a configuration file** — exactly what this project's `CLAUDE.md` forbids:

> Credentials: only through the `TIO_ACCESS_KEY`, `TIO_SECRET_KEY`, `TIO_URL` environment variables.
> Never as a tool parameter, never in a log.

The way out is not to make an exception. It is that **a child process inherits its parent's
environment**: if the keys are exported in the shell that launches Claude Code, the MCP server
receives them without anyone having to write them down anywhere.

## The recommended path

```bash
# 1. in the shell, before opening the client
export TIO_ACCESS_KEY=...
export TIO_SECRET_KEY=...
# export TIO_URL=https://cloud.tenable.com        # only if it is not the default
# export TIO_CA_BUNDLE=/path/company-ca.pem       # only on a network that inspects TLS

# 2. register the server, WITHOUT --env
claude mcp add tenable-ctem -- /path/to/mcp-ctem/.venv/bin/python -m tenable_ctem_mcp.server

# 3. open the client FROM THAT shell
claude
```

To make it permanent, put the `export` lines in your `~/.zshrc` — or better, in a file loaded only
when you are working on this project, so the keys do not sit in the environment of everything.

## Check before running the skill

With the client open, call:

```
ctem_diagnostics()
```

| `verdict` | What to do |
|---|---|
| `ok` | proceed |
| `credential_missing` | the client did not inherit the environment — reopen it from the shell with the exports |
| `credential_invalid` | a key from another container, or a trailing space in the variable |
| `failure` with cause `tls_corporate_proxy` | set `TIO_CA_BUNDLE` — see `troubleshooting.md` |

`ctem_diagnostics` prints neither the key nor any part of it.

## Running the skill end to end

1. Install the skill from `the repository root (SKILL.md + references/)`.
2. Ask for the CTEM maturity assessment.
3. Check against this list:

| What to check | Expected |
|---|---|
| Step 0 Phase A | **one** call, `ctem_discover_tenant` — not ten |
| Step 1 | **one** call, `ctem_preflight`, and the table goes whole into the report |
| Step 2 | **five** calls, one per stage |
| Total collection calls | **~7**, against the ~40 of the old path |
| No CSV request | the skill must not ask for `tenable_mttr_findings_*.csv` |
| No credential request | the skill never asks for a key |
| D4/V1/V2/M3 | `context.mode` = `census`, with no confidence interval |
| M1 | the median computed over **distinct days**; the context carries `median_without_collapse_days` |
| M4 in the sandbox | a **gap**, with the cadence guard naming the cause |
| Indicators in the report | 19, of which 16 with data and M4 as a gap |

**M4 as a gap is the correct result in this tenant**, not a defect to fix: the 7 dates forming the
MTTR windows are 7 out of 7 scan execution dates.

## Restarting is mandatory

Every change to the server requires restarting the client, and — because the install is not
editable — reinstalling first:

```bash
uv pip install .
```

To iterate during development, use the Inspector, which reloads immediately and shows the raw JSON:

```bash
npx @modelcontextprotocol/inspector uv run python -m tenable_ctem_mcp.server
```
