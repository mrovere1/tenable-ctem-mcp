# Troubleshooting

Real cases found in this project, not a speculative document.

## `401 unauthorized`

Two causes, in this order of frequency:

1. **A key from another container.** The key belongs to the tenant where it was generated. Check
   under Settings › My Account › API Keys of the right tenant.
2. **A trailing space in the environment variable.** An `export` copied from a document carries an
   invisible space. The server calls `.strip()` on both keys, but also check the variable has no
   line break.

`ctem_diagnostics()` separates a missing credential from an invalid one without printing the key.

## `403 forbidden`

The key needs the **Basic [16]** role, or the `VM.VM_EXPLORE` (Vulnerability Management) and
`ASSET_INVENTORY.CYBER_ASSET_MANAGEMENT.READ` (Exposure Management) privileges.

## `409` on the MTTR export

An export is already open for that key. **Do not ask for another** — resume through the
`export_uuid`:

```
mttr_collect(export_uuid="<uuid returned earlier>")
```

That is why `mttr_collect` returns `{status: "pending", export_uuid}` on exceeding `max_wait_s`
instead of raising.

## TLS certificate failure

A corporate network that inspects TLS presents a certificate signed by an internal CA, which is in
the macOS Keychain but not in Python's bundle. **It is the customer's proxy, not the MCP.**

```bash
export TIO_CA_BUNDLE=/path/to/company-ca.pem
export TIO_CA_KEYCHAIN=1        # macOS
```

If Python came from python.org without certificates, run
`/Applications/Python\ 3.12/Install\ Certificates.command` once.

**The server offers no option to disable verification.** Without it, the tenant's API keys travel
over a channel that may be being read by a third party.

## An empty collection

Not an error: a **result**. It becomes a declared gap, and the window used goes into the report.

## A number that looks filtered and is the whole corpus

The free-text `filters` case. `filters="tag_count >= 1"` returned the 30 assets of the corpus, with
no error; the same filter as a JSON array returned 9. The server's deny-list **rejects it before it
reaches the API** — see `src/tenable_ctem_mcp/preflight.py`.

## Empty `ACR` and `AES`

A new asset. They are computed about **24 h after the first scan**. Pending is not a gap: declare it
as pending and reassess later.

## A high `pct_in_batch` in the MTTR

**Not a defect.** It is the MTTR measuring the interval between scans rather than time to fix. In
the sandbox, the 9 `(first_found, last_fixed)` windows were all pairs drawn from 7 dates — the
tenant's scan dates. The skill declares M4 a gap on purpose in that case.

## `429 Too Many Requests`

Tenable's limit is **dynamic**: the platform computes how many requests it accepts per minute
according to load. The response carries `retry-after` in seconds, and the client honours that
header. There is no fixed number to tune. https://developer.tenable.com/docs/rate-limiting

## `ModuleNotFoundError: No module named 'tenable_ctem_mcp'`

An **editable** install (`uv pip install -e .`) in a venv created by `uv`. The `.pth` hatchling
writes (`_editable_impl_tenable_ctem_mcp.pth`) sorts **before** uv's `_virtualenv.pth`, which
rewrites `sys.path` and discards it. The exact symptom: `uv run python -m ...` works and
`.venv/bin/python -m ...` does not.

```bash
uv pip install .          # a normal install, without -e
```

To develop without reinstalling on every edit, launch with `uv run python -m tenable_ctem_mcp.server`.
The tests are unaffected: `pyproject.toml` sets `pythonpath = ["src"]` for pytest.

## The server behaves like an older version after an edit

Because the install is **not editable**, the MCP client runs the copy in `site-packages`, not `src/`.
Tests read `src/` through `pythonpath`, so `pytest` can be green while the running server is stale.

```bash
uv pip install .          # then restart the client
```
