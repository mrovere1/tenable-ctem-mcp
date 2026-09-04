# Execution guide

> **The old guide described running `tenable_mttr_export.py` by hand in the operator's terminal,
> with a CSV feeding M4. That path no longer exists** — `ctem_mobilization` calls `mttr_collect`
> internally, and the collector has left the skill's package. The old text was removed rather than
> updated: an obsolete procedure sitting under an "obsolete" banner still gets followed, because a
> reader who lands mid-file never sees the banner.

`SKILL.md` is the authoritative source for the procedure. This file carries only what an operator
needs before the first run.

---

## Prerequisites

1. **The `tenable-ctem` MCP server registered in the client** and connected. Check with
   `claude mcp get tenable-ctem` — the status must read `✔ Connected`.

2. **Credentials in the environment of the process that launches the client**, never as a tool
   parameter and never in a config file:

   ```bash
   export TIO_ACCESS_KEY=...
   export TIO_SECRET_KEY=...
   ```

   The server reads them from its own process environment, which it inherits from whatever launched
   it. Launching the client from the Dock or from a different shell means the server does not see
   them. The keys come from the tenant, under **Settings > My Account > API Keys**.

3. **A key with the Basic [16] role or the VM.VM_EXPLORE privilege.** Anything less answers 403.

4. **On a network that inspects TLS**, point at the corporate bundle before starting:

   ```bash
   export TIO_CA_BUNDLE=/path/to/ca.pem
   ```

   There is no option to disable certificate verification, and there must not be. See
   `docs/troubleshooting.md` in the server repository.

---

## Checking before you start

```
ctem_diagnostics()
```

It says whether the server can talk to the tenant without collecting a single indicator, and it
separates three causes that look identical from the client: credential missing, credential invalid,
and TLS intercepted by a corporate proxy. It never prints the key, nor any part of it.

Expected: `verdict: ok`.

---

## Delivery checklist

Before handing the report to the customer:

- [ ] The confirmed mapping from Step 0 is in the Methodology tab, with the "how I got there" column
- [ ] The `PREFLIGHT` table is complete, with no `undetermined` verdict
- [ ] Every gap carries a **named cause**, never a generic one
- [ ] The threshold profile used is declared, and so is the fact that thresholds are the skill's
      criterion and not Tenable's
- [ ] `measured / P` is printed, along with which confidence-gate branch was applied
- [ ] If M4 is a gap through the cadence guard, the finding is written in prose — it is worth more
      than the lost number
- [ ] The blocking stage is named in prose, with the indicator responsible
- [ ] The exported HTML opens offline, on the right language, with a single visible tab

---

## When to re-run

Quarterly, with the **same mapping and the same threshold profile**. Changing either between runs
invalidates the comparison — the skill warns about this, and the warning should be taken seriously
rather than clicked past.
