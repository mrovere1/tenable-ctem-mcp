"""Stage 1 - Scoping (S1, S2, S3, S4).

Matching official criteria: Asset Visibility and People | Process.

S2 and S3 require the category MAPPING as an explicit parameter. The server does
not guess the category name: if the caller does not say which one is criticality
and which is owner, the indicator becomes a gap and the return lists the
categories that exist, so the consultant can point at the right one.

Filter properties confirmed against the direct API on 2026-09-03:
  tag_count  ops: = != >= > <= < exists not exists
  tag_names  ops: contains not contains = != exists not exists size...
  acr        ops: = != >= > <= < exists not exists

FINDING from validation: `tag_names` holds the tag VALUE, not "Category:Value".
`contains "Criticidade"` returns 0; `= ["Alta","Baixa","Crown Jewel","Media"]`
returns 8. An array of values has OR semantics and already deduplicates an asset
carrying two tags of the same category.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from .. import Indicator
from ..client import ApiError, call, total_of
from ..preflight import validate_filters, verdict

ASSETS_SEARCH = "/api/v1/t1/inventory/assets/search"

INDICATORS = ("S1", "S2", "S3", "S4")

# Hints in the three languages the skill reports in: EN, PT and ES. The customer's
# tenant is almost always in the customer's language, so an English-only list
# would fail on exactly the tenants this skill exists to assess.
#
# Written WITHOUT accents, on purpose. `_fold` strips diacritics before matching,
# so one entry covers every spelling: "criticidade" also matches "Criticidade",
# "classificacao" also matches "Classificação", "dueno" also matches "Dueño".
#
# Before this, matching was a plain .lower() while the comment claimed accents
# were ignored - it only worked because someone had hand-listed "importancia"
# AND "importância". Any accented term nobody thought to duplicate failed in
# silence: "Classificação", "Priorização", "Dueño" and "Criticidad" were all
# invisible. The suggestion is not load-bearing - the operator still confirms the
# mapping - but a suggestion that silently skips the right category makes the
# operator read nine categories, which is the work this function exists to save.
CRITICALITY_HINTS = (
    # EN
    "criticality", "criticality tier", "business criticality", "business impact",
    "crown jewel", "tier", "importance", "severity class", "classification",
    # PT
    "criticidade", "importancia", "impacto", "impacto no negocio", "classificacao",
    "priorizacao", "nivel de risco",
    # ES
    "criticidad", "importancia del negocio", "impacto de negocio", "clasificacion",
    "nivel de criticidad",
)
OWNER_HINTS = (
    # EN
    "owner", "responsible", "custodian", "team", "squad", "department",
    "business unit", "bu", "accountable", "steward",
    # PT
    "dono", "responsavel", "departamento", "area", "equipe", "time",
    "unidade de negocio", "gestor",
    # ES
    "dueno", "propietario", "equipo", "departamento", "area responsable",
    "unidad de negocio", "encargado",
)


def _count(filters: list[dict] | None) -> int | None:
    body = {"filters": validate_filters(filters)} if filters else {}
    return total_of(call("POST", ASSETS_SEARCH, body=body, params={"limit": 1}))


def _literal(filters: list[dict] | None) -> str:
    return (json.dumps(filters, separators=(",", ":"), ensure_ascii=False)
            if filters else "no filter (corpus)")


def _pct(numerator: int, denominator: int) -> float | None:
    return round(100.0 * numerator / denominator, 1) if denominator else None


def _fold(text: str) -> str:
    """Lower-cases and strips diacritics, so one hint covers every spelling.

    "Criticidade", "CRITICIDADE" and "Criticidád" all fold to the same string,
    and so do "Classificação" -> "classificacao" and "Dueño" -> "dueno".
    """
    decomposed = unicodedata.normalize("NFKD", text.strip().lower())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def suggest_categories(categories: dict[str, list[str]]) -> dict[str, list[str]]:
    """Suggests which category is criticality and which is owner, without deciding.

    The decision stays with the operator: the mapping is an explicit parameter.
    This only saves them from reading nine categories to find two.

    Hints cover EN, PT and ES, and matching folds accents - see the note above
    the hint lists.
    """
    def matches(name: str, hints: tuple[str, ...]) -> bool:
        n = _fold(name)
        tokens = set(re.split(r"[^a-z0-9]+", n))
        # Short hints match a whole token only. `bu` as a substring matched
        # "Business Impact" and put a criticality category into the owner list;
        # it would also match "backup" and "distribuicao". Longer hints stay as
        # substrings, so "criticality tier" still finds "Criticality Tier (BIA)".
        return any(h in tokens if len(h) <= 3 else h in n for h in hints)

    return {
        "criticality": [c for c in categories if matches(c, CRITICALITY_HINTS)],
        "owner": [c for c in categories if matches(c, OWNER_HINTS)],
    }


def _by_category(mapping: dict, key: str, categories: dict[str, list[str]]
                 ) -> tuple[str | None, list[str]]:
    """Returns (category name, its values) from the mapping."""
    name = mapping.get(key)
    if not name:
        return None, []
    values = categories.get(name)
    if values is None:
        # Match case-insensitively before giving up.
        for k, v in categories.items():
            if k.strip().lower() == str(name).strip().lower():
                return k, list(v)
        return name, []
    return name, list(values)


def compute(mapping: dict, indicators: list[str] | None = None,
            snapshot: dict | None = None) -> list[dict]:
    """S1 to S4. `indicators=None` computes all four.

    `mapping` accepts:
      criticality_category: str
      owner_category: str
    """
    requested = [i.upper() for i in (indicators or INDICATORS)]
    out: list[Indicator] = []

    from .discovery import discover_tenant
    snapshot = snapshot or discover_tenant()
    categories = snapshot["tags"]["categories"]
    total_assets = snapshot["assets"]["total"]

    # --- S1: % of assets with at least one tag --------------------------
    if "S1" in requested:
        f = [{"property": "tag_count", "operator": ">=", "value": ["1"]}]
        try:
            tagged = _count(f)
            out.append(Indicator.ok(
                "S1", _pct(tagged, total_assets), n=total_assets,
                literal_filter=f"{_literal(f)} over a corpus of {total_assets} assets",
                preflight_verdict=verdict(total_assets, tagged),
                context={"tagged": tagged, "total": total_assets}))
        except ApiError as e:
            out.append(Indicator.declared_gap("S1", cause=str(e),
                                              literal_filter=_literal(f)))

    # --- S2 and S3: coverage by tag category ----------------------------
    for ind, key, label in (("S2", "criticality_category", "criticality"),
                            ("S3", "owner_category", "owner")):
        if ind not in requested:
            continue
        name, values = _by_category(mapping, key, categories)
        if not name:
            out.append(Indicator.declared_gap(
                ind,
                cause=(f"the mapping did not provide `{key}`. The server does not "
                       f"guess the name of the {label} category."),
                literal_filter="not executed"))
            continue
        if not values:
            out.append(Indicator.declared_gap(
                ind,
                cause=(f"the category {name!r} does not exist in the tenant, or has "
                       "no values. Available categories: "
                       + ", ".join(sorted(categories))),
                literal_filter="not executed"))
            continue
        f = [{"property": "tag_names", "operator": "=", "value": values}]
        try:
            n = _count(f)
            out.append(Indicator.ok(
                ind, _pct(n, total_assets), n=total_assets,
                literal_filter=(f"{_literal(f)} (category {name!r}) over a corpus "
                                f"of {total_assets} assets"),
                preflight_verdict=verdict(total_assets, n),
                context={"category": name, "values": values,
                         "tagged": n, "total": total_assets}))
        except ApiError as e:
            out.append(Indicator.declared_gap(ind, cause=str(e),
                                              literal_filter=_literal(f)))

    # --- S4: declared Crown Jewels (informational) ----------------------
    if "S4" in requested:
        f = [{"property": "acr", "operator": ">=", "value": ["9"]}]
        crit_name, _ = _by_category(mapping, "criticality_category", categories)
        try:
            high_acr = _count(f)
            declared = bool(crit_name) and (high_acr or 0) >= 1
            out.append(Indicator.ok(
                "S4", declared, n=total_assets,
                literal_filter=(f"{_literal(f)} AND a criticality category exists "
                                f"({crit_name!r})"),
                preflight_verdict=verdict(total_assets, high_acr),
                context={
                    "assets_with_acr_gte_9": high_acr,
                    "criticality_category": crit_name,
                    "informational": True,
                    "structural_gap": (
                        "The API does not expose whether the ACR was adjusted by a "
                        "human or is Tenable's automatic value. S4 measures the "
                        "DECLARATION of context, not curation. That is why it is "
                        "informational and does not score a stage."),
                }))
        except ApiError as e:
            out.append(Indicator.declared_gap("S4", cause=str(e),
                                              literal_filter=_literal(f)))

    return [i.to_dict() for i in out]
