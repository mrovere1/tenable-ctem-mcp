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
| **B. Least privilege** | **Scan Manager [40]** role **+** a permission on **All Assets** with `Can View` **+** a permission on **All Tags** with `Can Use` **+** `Can View` on **every scan** used in the cadence | Read-only in practice, but four grants, and each missing one is silent except the role |

The tool never writes to the tenant. Whichever option is chosen, create a **dedicated user** for the
assessment and remove it afterwards.

**Basic [16] is not enough.** Earlier versions of this README said it was. It is the documented
minimum for most endpoints, but not for the agent list (D3) nor the scan history (D1, M1, M2).

---

## Reading the whole tag catalog — categories **and** values

S2, S3 and P1 need the **values** of the criticality and owner categories, exactly as they are
spelled, because the findings endpoint only matches tags with `=` (`contains` is ignored — see
`docs/limitations.md`). A key that sees the category names but not the values cannot measure them.

Tag visibility is not part of the role. Tenable gives the creator of a tag its owner permissions
automatically; everybody else, including a Scan Manager, has to be granted it. In the console, as an
Administrator:

1. **Settings › Access Control › Permissions › Create Permission.**
2. **Users:** the assessment user. Do not pick *All Users*.
3. **Objects:** **All Tags** — Tenable describes it as allowing "users and groups on your instance
   to edit or use all objects on your instance". Pick **All Assets** in the same configuration, or a
   second one, for the asset side.
4. **Permissions:** **Can Use** for All Tags, **Can View** for All Assets. **Do not add Can Edit**:
   Tenable adds Can Use to it automatically, and warns that Can Edit next to Can View lets the user
   change the scope of what they can see.
5. Save, then run `ctem_diagnostics()`. `tag_catalog.complete` must be `true`, and
   `values.listed` must equal `values.declared_total`.

Source: [Create and Add a Permission Configuration](https://docs.tenable.com/vulnerability-management/Content/Settings/access-control/CreateAndAddAPermission.htm),
[Permissions](https://docs.tenable.com/vulnerability-management/Content/Settings/access-control/Permissions.htm).
**Not yet measured end to end:** the sandbox key is Administrator, so this grant was taken from the
documentation, not observed on a restricted key. Step 5 is the check that it worked.

**When the grant is not possible**, the operator can declare the values in the mapping
(`criticality_values`, `owner_values`), typed from the console. The report then says the values
were declared, not read. Without either, S2, S3 and P1 are gaps whose cause names this permission.

---

## Endpoint by endpoint

Requirements quoted from developer.tenable.com, checked on 2026-09-14. "Measured" is what the
production tenant answered on 2026-09-09.

| Endpoint | Indicators | Documented requirement | Measured | Without it |
|---|---|---|---|---|
| `POST /api/v1/t1/inventory/assets/search` | snapshot, S1–S4, D2, D3 and V4 denominators | Basic [16], or `ASSET_INVENTORY.CYBER_ASSET_MANAGEMENT.READ` + `AD.TOGGLE_AD.USE` | worked at every role tried | 403 |
| `GET /tags/categories`, `GET /tags/values` | S2, S3, S4, P1 | Basic [16] **and** a permission on the tags (All Tags, `Can Use`) | Basic [16] and Scan Manager [40]: **200 with an empty list**, while `pagination.total` said 47 | **silent**: categories missing, S2/S3 fall to a gap or a wrong category |
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

1. `ctem_diagnostics()` — confirms the credential and TLS, and reports:
   - `api_key_role`: the role from `/session` (64 Administrator, 40 Scan Manager, 32 Standard,
     24 Scan Operator, 16 Basic);
   - `tag_catalog`: what the catalog lists against what it declares. `complete: false` is the
     missing tag permission, not an untagged tenant;
   - `permission_warnings`: every gap the role or the catalog already predicts.
2. Compare the scan count in `ctem_discover_tenant()` with the console's scan list. Fewer means
   scans the user cannot view — the one check the server cannot make on its own.

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
