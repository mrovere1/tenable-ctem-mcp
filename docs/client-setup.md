# Registering the server in a client

Two clients are supported: **Claude Code** and **Claude Desktop**. The credential rule is the same
in both — the keys reach the server through the environment, never through a configuration file —
but the mechanism differs, because a GUI application does not inherit the shell you launched it
from.

- [Claude Code](#claude-code) — the shell exports the keys, the client inherits them
- [Claude Desktop](#claude-desktop) — a launcher script supplies them

---

## Claude Code

### The conflict, and how it resolves

`claude mcp add` writes the configuration into `~/.claude.json`. Passing the keys there with `--env`
would **write them into a configuration file** — exactly what this project's `CLAUDE.md` forbids:

> Credentials: only through the `TIO_ACCESS_KEY`, `TIO_SECRET_KEY`, `TIO_URL` environment variables.
> Never as a tool parameter, never in a log.

The way out is not to make an exception. It is that **a child process inherits its parent's
environment**: if the keys are exported in the shell that launches Claude Code, the MCP server
receives them without anyone having to write them down anywhere.

### The recommended path

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

---

## Claude Desktop

### Why it is not the same as Claude Code

Claude Code is started from a terminal, so it inherits that shell's environment and the keys arrive
without being written anywhere. **Claude Desktop is started from the Dock or Finder**, by `launchd`,
and inherits nothing from your shell. The `export` lines in `~/.zshrc` do not reach it.

The obvious shortcut is the `env` block that `claude_desktop_config.json` accepts. It works, and it
is what most MCP documentation shows — including Tenable's own, for the hosted server. **This
project still does not use it**, for the reason stated in `CLAUDE.md`: a credential in a
configuration file is a credential in a file that gets backed up, synchronised and copied between
machines like any other file in your home directory. The launcher below costs three commands and
keeps the config free of secrets.

If you take the shortcut anyway, read the next section first — **where** you put the keys inside
that file matters more than most examples suggest.

### The launcher

A small script supplies the environment and then executes the server. The keys sit in one file that
you control the permissions of, and the MCP configuration holds no credential at all.

```bash
# 1. the credentials, outside the repository, readable only by you
mkdir -p ~/.config/tenable-ctem
cat > ~/.config/tenable-ctem/env <<'EOF'
export TIO_ACCESS_KEY=...
export TIO_SECRET_KEY=...
# export TIO_URL=https://cloud.tenable.com        # only if it is not the default
# export TIO_CA_BUNDLE=/path/company-ca.pem       # only on a network that inspects TLS
EOF
chmod 600 ~/.config/tenable-ctem/env

# 2. the launcher
mkdir -p ~/.local/bin
cat > ~/.local/bin/tenable-ctem-mcp <<'EOF'
#!/bin/sh
. "$HOME/.config/tenable-ctem/env"
exec /path/to/mcp-ctem/.venv/bin/python -m tenable_ctem_mcp.server
EOF
chmod 700 ~/.local/bin/tenable-ctem-mcp
```

Replace `/path/to/mcp-ctem` with the absolute path of your clone. **The path must be absolute in
both files** — `launchd` gives the process no useful working directory and a very short `PATH`.

### The shortcut, and what it costs

Plenty of MCP servers are set up by writing the keys straight into `claude_desktop_config.json`, and
Tenable's own **hosted** server is documented that way:

```json
"tenable": {
  "command": "npx",
  "args": ["mcp-remote", "https://cloud.tenable.com/mcp/",
           "--header", "X-ApiKeys: accessKey=…;secretKey=…"]
}
```

That server has no local process of yours to inherit an environment from — `mcp-remote` is a proxy
to an HTTP endpoint — so the configuration file is the only place the keys can go. This server is a
local stdio process, started as a child of the client, so it does have somewhere else to put them.

If you do choose the configuration file, one distinction is worth more than the choice itself:

| | Visibility |
|---|---|
| keys in `args` | **argv is public.** Any process running as you can read them — `ps aux \| grep mcp` prints the key on screen |
| keys in `env` | the environment of a running process is not readable by another unprivileged process on macOS |

So `env` over `args`, always — and never a key on a command line, in either client. Whichever you
pick, the file holds a live credential: `chmod 600` it, and keep it out of anything that syncs.

The server itself never changes behaviour here. It reads `TIO_ACCESS_KEY` / `TIO_SECRET_KEY` from
its environment and nowhere else — there is no tool parameter that accepts a key, and no code path
that logs one. What this section chooses is only *how the environment gets filled*.

### The configuration file

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Reachable through **Settings › Developer › Edit Config**, which also creates the file if it does not
exist yet.

```json
{
  "mcpServers": {
    "tenable-ctem": {
      "command": "/Users/you/.local/bin/tenable-ctem-mcp"
    }
  }
}
```

`~` is not expanded here — write the path out in full. Note what the entry does **not** contain:
no `env`, no key, no argument carrying a credential.

Then **quit Claude Desktop completely** — Cmd+Q on macOS, or File › Exit on Windows; closing the
window leaves the process running and the server is not reloaded — and open it again. The server
appears under the tools icon in the composer.

### Windows

`launchd` is a macOS detail; the rest holds. There is no `sh`, so the launcher is a `.cmd`:

```bat
@echo off
set TIO_ACCESS_KEY=...
set TIO_SECRET_KEY=...
"C:\path\to\mcp-ctem\.venv\Scripts\python.exe" -m tenable_ctem_mcp.server
```

Keep it outside the repository and restrict it to your user account. In the JSON, escape the
backslashes: `"command": "C:\\Users\\you\\bin\\tenable-ctem-mcp.cmd"`.

### When it does not connect

Desktop shows no stderr in the interface. The log is the first thing to read:

```bash
# macOS
tail -f ~/Library/Logs/Claude/mcp-server-tenable-ctem.log
```

| Symptom | Cause |
|---|---|
| the server does not appear at all | invalid JSON, or the client was not fully quit |
| `spawn ... ENOENT` | a relative path, or `~` in `command` — write it out in full |
| the log shows nothing | the launcher is not executable (`chmod 700`) |
| `ctem_diagnostics` → `credential_missing` | the launcher did not source the env file — check the path inside the script |
| `credential_invalid` | a trailing space, or a key from another container |
| `failure` / `tls_corporate_proxy` | set `TIO_CA_BUNDLE` in the env file — see `troubleshooting.md` |

The same `ctem_diagnostics` check below applies to both clients, and it prints no part of the key.

---

## Check before running the skill (both clients)

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
