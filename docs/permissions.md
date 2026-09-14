# API key permissions

What the user behind `TIO_ACCESS_KEY` / `TIO_SECRET_KEY` needs so that **every** indicator is
measured over the **whole** tenant.

Written after a production assessment on 2026-09-08/09 where the key's role was changed twice in two
days and each change opened some indicators and left others closed. A role is not the whole story:
Tenable Vulnerability Management also filters by **per-object permissions** (on assets, scans and
tags), and those do not answer 403. They answer a **shorter list**. That is the dangerous case,
because a shorter list looks like a real result.

---

## The short answer

Give the key's user **one** of these:

| Option | What to grant | Trade-off |
|---|---|---|
| **A. Administrator [64]** | the role alone | Simplest. Administrator bypasses the per-object permissions, so nothing is silently hidden. More privilege than a read-only tool needs |
| **B. Least privilege** | **Scan Manager [40]** role **+** `Can View` on **all assets** (access control) **+** `Can View` on **every tag** **+** `Can View` on **every scan** | Read-only in practice, but four grants, and each missing one is silent except the role |

The tool never writes to the tenant. Whichever option is chosen, create a **dedicated user** for the
assessment and remove it afterwards.

**Basic [16] is not enough.** Earlier versions of this README said it was. It is the documented
minimum for most endpoints, but not for the agent list (D3) nor the scan history (D1, M1, M2).

---

## Endpoint by endpoint

Requirements quoted from developer.tenable.com, checked on 2026-09-14. "Measured" is what the
production tenant answered on 2026-09-09.

| Endpoint | Indicators | Documented requirement | Measured | Without it |
|---|---|---|---|---|
| `POST /api/v1/t1/inventory/assets/search` | snapshot, S1–S4, D2, D3 and V4 denominators | Basic [16], or `ASSET_INVENTORY.CYBER_ASSET_MANAGEMENT.READ` + `AD.TOGGLE_AD.USE` | worked at every role tried | 403 |
| `GET /tags/categories`, `GET /tags/values` | S2, S3, S4, P1 | Basic [16] **and** `Can View` on each tag | Basic [16] and Scan Manager [40]: **200 with an empty list**, while `pagination.total` said 47 | **silent**: categories missing, S2/S3 fall to a gap or a wrong category |
| `GET /workbenches/vulnerabilities` | P1, D4, V1, V2, preflight | Basic [16] | 403 at role 0; worked at Basic [16] | 403; with partial asset permissions, **silent** (only visible assets count) |
| `GET /scans` | D1, M1, M2 | Basic [16] **and** `Can View` on the scan, or `VM.VM_SCAN.VM_SCAN.READ`. Returns only scans the user can view | 403 at role 0; worked at Basic [16] (60 scans) | **silent**: scans the user cannot see are not listed |
| `GET /scans/{id}/history` | D1, M1, M2, `scan_cadence` | **Scan Operator [24]** and `Can View` on the scan | — | 403 per scan, which becomes a cause on that scan |
| `GET /scanners/null/agents` | D3 | **Scan Manager [40]** | **403 at Basic [16]**; worked at Scan Manager [40] (5,214 agents) | 403, D3 is a gap |
| `GET /plugins/plugin/{id}` | D4, V1, V2, M3 | Basic [16] | worked | 403 |
| `POST /vulns/export` + status + chunks | M4 (`mttr_collect`) | Basic [16] or `VM.VM_EXPLORE.VM_EXPLORE.EXPORT`, **and** `Can View` on the exported assets (not needed for Administrator) | 403 at role 0; worked at Basic [16] | 403; with partial asset permissions, **silent** (only visible assets export) |

Attack Surface Management is **not** covered by these keys: it has its own base URL and its own API
keys, generated in the ASM user profile. It is outside v1.

---

## How to check a key before an assessment

1. `ctem_diagnostics()` — confirms the credential is valid and TLS is sound.
2. `GET /session` — the `permissions` field is the role number: 64 Administrator, 40 Scan Manager,
   32 Standard, 24 Scan Operator, 16 Basic. Anything below 40 leaves D3 closed.
3. `ctem_discover_tenant()` — compare the tag category count with what the customer sees in the
   console. **Fewer categories than the console shows is the missing tag permission**, not an
   untagged tenant.
4. Compare the scan count with the console's scan list. Fewer means scans the user cannot view.

---

## What happened on 2026-09-08/09

| `/session` permissions | Workbenches, scans, export | Agents (D3) | Tag catalog (S2, S3) |
|---|---|---|---|
| 0 | 403 | read (unexplained — possibly another key) | empty |
| Basic [16] | open | **403** | **empty**, total 47 |
| Scan Manager [40] | open | open | **still empty**, total 47 |

The last row is the one to remember: a higher role did not fix the tags, because tag visibility is
a permission on the tag, granted automatically only to the user who created it
(https://docs.tenable.com/vulnerability-management/Content/Settings/access-control/Permissions.htm).
Full record: `_docs/pendencia-denominador-licenciado-2026-09-08.md`.
