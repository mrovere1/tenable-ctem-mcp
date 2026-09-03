"""Estagio 2 - Discovery (D1, D2, D3, D4) e a descoberta de tenant do Passo 0.

`descobrir_tenant()` mora aqui, e nao num modulo proprio, porque coleta
exatamente a materia-prima que D1, D2 e D3 consomem: os scans com historico
(D1), as exposure_classes presentes (D2) e os agentes contra os ativos DEVICE
(D3). Modulo unico, cache compartilhado, e a consulta nao sai duas vezes.

Substitui as ~10 chamadas da Fase A do Passo 0 da skill por uma so.

Endpoints, confirmados em developer.tenable.com em 2026-09-03:
  POST /api/v1/t1/inventory/assets/search   (Exposure Management, BETA)
  GET  /tags/categories                     (Vulnerability Management)
  GET  /tags/values                         (Vulnerability Management)
  GET  /scans                               (Vulnerability Management)
  GET  /scans/{scan_id}/history             (Vulnerability Management)
  GET  /scanners/null/agents                (Vulnerability Management)

Os endpoints de Exposure Management estao em BETA e a estrutura da resposta
pode mudar - por isso a leitura e defensiva e o formato nunca e presumido.
"""

from __future__ import annotations

import json
from typing import Any

from .. import agora_utc
from ..client import CACHE, ErroApi, chamar, total_de

# Valores possiveis de exposure_classes. ATENCAO: asset_class NAO e
# exposure_classes. No sandbox existem ativos com asset_class = IDENTITY, mas
# exposure_classes = IDENTITY retorna zero - os ativos de identidade estao no
# inventario sem carregar achados de Identity Exposure. D2 usa exposure_classes.
EXPOSURE_CLASSES = ("VM", "WAS", "CLOUD", "IDENTITY", "OT", "AI", "CODE")

ASSET_CLASSES = ("DEVICE", "IDENTITY", "ACCOUNT", "GROUP", "WEB_APPLICATION",
                 "CLOUD_RESOURCE")

BUSCA_ATIVOS = "/api/v1/t1/inventory/assets/search"


def _contar_ativos(filters: list[dict] | None = None) -> int | None:
    """Conta ativos lendo so o campo `total`. limit=1 de proposito: o pre-voo
    e barato porque so o total importa."""
    corpo: dict[str, Any] = {}
    if filters:
        corpo["filters"] = filters
    resp = chamar("POST", BUSCA_ATIVOS, corpo=corpo, params={"limit": 1, "offset": 0})
    return total_de(resp)


def _filtro_literal(filters: list[dict] | None) -> str:
    return json.dumps(filters, separators=(",", ":"), ensure_ascii=False) if filters else "sem filtro"


def _categorias_e_valores() -> dict[str, Any]:
    cats = chamar("GET", "/tags/categories").get("categories", []) or []
    vals = chamar("GET", "/tags/values").get("values", []) or []
    por_categoria: dict[str, list[str]] = {}
    for c in cats:
        nome = c.get("name")
        if nome:
            por_categoria.setdefault(nome, [])
    for v in vals:
        nome = v.get("category_name")
        if nome is None:
            continue
        por_categoria.setdefault(nome, []).append(v.get("value"))
    return {
        "quantidade": len(por_categoria),
        "categorias": {k: sorted(x for x in v if x) for k, v in sorted(por_categoria.items())},
    }


def _scans_com_historico() -> dict[str, Any]:
    """Lista os scans e, para cada um, quantas execucoes tem.

    Nao colapsa runs aqui: o colapso em dias distintos de avaliacao e trabalho
    de `scan_cadence` (marco M4), e e o que separa mediana de 1,42 dia de
    mediana de 21 dias em M1.
    """
    scans = chamar("GET", "/scans").get("scans") or []
    resumo = []
    for s in scans:
        sid = s.get("id")
        if sid is None:
            continue
        item = {
            "scan_id": sid,
            "nome": s.get("name"),
            "status": s.get("status"),
            "ultima_modificacao_epoch": s.get("last_modification_date"),
            "runs": None,
        }
        try:
            hist = chamar("GET", f"/scans/{sid}/history",
                          params={"limit": 200, "offset": 0})
            runs = hist.get("history") or []
            item["runs"] = len(runs)
            item["runs_completed"] = sum(1 for r in runs if r.get("status") == "completed")
        except ErroApi as e:
            # Falha por scan nao contamina o resto: vira causa nomeada no item.
            item["runs"] = None
            item["causa"] = str(e)
        resumo.append(item)
    com_historico = [s for s in resumo if (s.get("runs") or 0) > 0]
    return {"total_scans": len(resumo), "com_historico": len(com_historico),
            "scans": resumo}


def _agentes() -> dict[str, Any]:
    ags = chamar("GET", "/scanners/null/agents",
                 params={"limit": 5000, "offset": 0}).get("agents") or []
    ativos = [a for a in ags if str(a.get("status", "")).lower() == "on"]
    return {"total": len(ags), "ativos": len(ativos),
            "por_status": _contar_por(ags, "status")}


def _contar_por(itens: list[dict], chave: str) -> dict[str, int]:
    saida: dict[str, int] = {}
    for i in itens:
        v = str(i.get(chave, "desconhecido"))
        saida[v] = saida.get(v, 0) + 1
    return dict(sorted(saida.items()))


def descobrir_tenant(usar_cache: bool = True) -> dict[str, Any]:
    """Retrato do tenant numa chamada. Resultado em cache por TTL curto.

    Cache obrigatorio (CLAUDE.md): varios indicadores consultam este retrato, e
    sem cache a mesma consulta sai quatro vezes.
    """
    chave = "ctem_discover_tenant/v1"
    if usar_cache:
        achou, valor = CACHE.get(chave)
        if achou:
            return dict(valor, servido_do_cache=True)

    total_ativos = _contar_ativos()

    por_asset_class = {}
    for classe in ASSET_CLASSES:
        f = [{"property": "asset_class", "operator": "=", "value": [classe]}]
        n = _contar_ativos(f)
        if n:
            por_asset_class[classe] = n

    # Uma consulta por classe, com limit=1, lendo so o total. E o jeito de saber
    # quais superficies existem de fato - nao ha endpoint que liste isso.
    exposure = {}
    for classe in EXPOSURE_CLASSES:
        f = [{"property": "exposure_classes", "operator": "=", "value": [classe]}]
        exposure[classe] = _contar_ativos(f)

    retrato = {
        "tags": _categorias_e_valores(),
        "ativos": {
            "total": total_ativos,
            "por_asset_class": por_asset_class,
            "filtro_literal_total": _filtro_literal(None),
        },
        "exposure_classes": exposure,
        "scans": _scans_com_historico(),
        "agentes": _agentes(),
        "coletado_em_utc": agora_utc(),
        "servido_do_cache": False,
        "aviso": ("Os endpoints de Exposure Management estao em BETA na "
                  "documentacao da Tenable; a estrutura da resposta pode mudar."),
    }
    CACHE.set(chave, retrato)
    return retrato
