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

from datetime import datetime, timezone

from .. import Indicador, agora_utc
from ..client import CACHE, ErroApi, chamar, paginar, total_de
from ..plugins import amostrar_estratificado, plugin_census, plugin_details_batch, taxa_ponderada
from ..preflight import validar_filters, veredito

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
            # Paginado. Sem isso o scan recorrente com muitos runs volta
            # truncado no tamanho da pagina - contagem errada com aparencia de
            # certa, que e exatamente o que este projeto proibe. Medido no
            # sandbox: o scan 13 tem mais de 200 runs.
            runs = paginar("GET", f"/scans/{sid}/history", campo="history")
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
    ags = paginar("GET", "/scanners/null/agents", campo="agents")
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


# ----------------------------------------------------------------------------
# Indicadores D1 a D4
# ----------------------------------------------------------------------------

INDICADORES = ("D1", "D2", "D3", "D4")


def _agora() -> datetime:
    return datetime.now(timezone.utc)


def _ultimo_run(retrato: dict) -> tuple[int | None, int]:
    """Devolve (epoch do run mais recente, quantidade de scans consultados).

    Le o historico de cada scan que tem historico. `time_start` e o inicio real
    do run - e a fonte correta, porque filtro de data em findings e ignorado e
    o parametro `age` de workbenches e recencia, nao idade.
    """
    mais_recente = None
    consultados = 0
    for s in retrato["scans"]["scans"]:
        if not (s.get("runs") or 0):
            continue
        consultados += 1
        try:
            hist = paginar("GET", f"/scans/{s['scan_id']}/history", campo="history")
        except ErroApi:
            continue
        for r in hist:
            ts = r.get("time_start")
            if isinstance(ts, int) and (mais_recente is None or ts > mais_recente):
                mais_recente = ts
    return mais_recente, consultados


def calcular(indicadores: list[str] | None = None,
             superficies_licenciadas: list[str] | None = None,
             corte_vpr_amostra: float = 7.0,
             n_amostra: int = 30,
             retrato: dict | None = None,
             agora: datetime | None = None) -> list[dict]:
    """D1 a D4. `indicadores=None` calcula os quatro.

    `agora` existe para o golden test poder congelar o relogio: D1 e uma
    diferenca contra o instante da coleta, entao sem relogio fixo nao ha teste
    de regressao possivel.
    """
    pedidos = [i.upper() for i in (indicadores or INDICADORES)]
    licenciadas = [s.upper() for s in (superficies_licenciadas or ["VM"])]
    agora = agora or _agora()
    retrato = retrato or descobrir_tenant()
    saida: list[Indicador] = []

    # --- D1: dias desde a ultima avaliacao (invertido) ------------------
    if "D1" in pedidos:
        ts, consultados = _ultimo_run(retrato)
        if ts is None:
            saida.append(Indicador.lacuna_declarada(
                "D1", causa="nenhum scan com historico de execucao no tenant.",
                filtro_literal=f"scan_history de {consultados} scans"))
        else:
            inicio = datetime.fromtimestamp(ts, timezone.utc)
            dias = round((agora - inicio).total_seconds() / 86400.0, 2)
            saida.append(Indicador.ok(
                "D1", dias, n=consultados,
                filtro_literal=(f"scan_history de {consultados} scans com historico; "
                                f"run mais recente em {inicio.strftime('%Y-%m-%dT%H:%M:%SZ')}"),
                veredito_preflight="ok",
                contexto={"run_mais_recente_utc": inicio.strftime("%Y-%m-%dT%H:%M:%SZ"),
                          "invertido": True}))

    # --- D2: cobertura das superficies licenciadas ----------------------
    if "D2" in pedidos:
        presentes = [c for c, n in retrato["exposure_classes"].items() if (n or 0) > 0]
        cobertas = [c for c in licenciadas if c in presentes]
        pct = round(100.0 * len(cobertas) / len(licenciadas), 1) if licenciadas else None
        nao_licenciadas = [c for c in presentes if c not in licenciadas]
        saida.append(Indicador.ok(
            "D2", pct, n=len(licenciadas),
            filtro_literal=("exposure_classes com total > 0, uma consulta por classe "
                            f"com limit=1; licenciadas={licenciadas}"),
            veredito_preflight="ok",
            contexto={"presentes": presentes, "cobertas": cobertas,
                      "licenciadas": licenciadas,
                      "presentes_nao_licenciadas": nao_licenciadas,
                      "nota": ("asset_class nao e exposure_classes: o tenant pode ter "
                               "ativos com asset_class=IDENTITY e exposure_classes="
                               "IDENTITY em zero.")}))

    # --- D3: % de ativos DEVICE com agente ------------------------------
    if "D3" in pedidos:
        devices = retrato["ativos"]["por_asset_class"].get("DEVICE", 0)
        ativos = retrato["agentes"]["ativos"]
        if not devices:
            saida.append(Indicador.lacuna_declarada(
                "D3", causa="nenhum ativo com asset_class=DEVICE; denominador zero.",
                filtro_literal="asset_class=DEVICE"))
        else:
            saida.append(Indicador.ok(
                "D3", round(100.0 * ativos / devices, 1), n=devices,
                filtro_literal=("agentes com status=on sobre "
                                "[{\"property\":\"asset_class\",\"operator\":\"=\","
                                "\"value\":[\"DEVICE\"]}]"),
                veredito_preflight="ok",
                contexto={"agentes_ativos": ativos, "devices": devices}))

    # --- D4: % da amostra detectada por plugin local --------------------
    if "D4" in pedidos:
        try:
            censo = plugin_census("critical")
            am = amostrar_estratificado(censo["plugins"], n=n_amostra,
                                        corte_vpr=corte_vpr_amostra)
            ids = [p["plugin_id"] for p in am["amostra"]]
            lote = plugin_details_batch(ids)
            detalhes = {d["plugin_id"]: d for d in lote["plugins"]}
            r = taxa_ponderada(am["amostra"], detalhes,
                               lambda d: str(d.get("scan_type", "")).lower() == "local",
                               am["estratos"], base="por_deteccao")
            saida.append(Indicador.ok(
                "D4", round(100.0 * r["taxa_ponderada"], 1), n=r["n"],
                filtro_literal=(f"amostra estratificada de {am['n']} sobre "
                                f"{censo['plugins_distintos']} plugins criticos, "
                                f"alocacao proporcional, corte VPR {corte_vpr_amostra}, "
                                f"semente {am['semente']}"),
                veredito_preflight="ok",
                contexto={
                    "estratos": am["estratos"], "por_estrato": r["por_estrato"],
                    "ic95_amostra_inteira": r["ic95_amostra_inteira"],
                    "piso_estrato_b_acionado": am["piso_estrato_b_acionado"],
                    "plugins_sem_detalhe": lote["lacunas"],
                    "proxy_declarado": ("plugin de tipo `local` so retorna resultado "
                                        "com credencial valida ou agente. Nao e leitura "
                                        "de status de credencial. O parametro "
                                        "`authenticated` de workbenches e ignorado."),
                }))
        except (ErroApi, ValueError) as e:
            saida.append(Indicador.lacuna_declarada(
                "D4", causa=str(e), filtro_literal="censo critical + amostra"))

    return [i.para_dict() for i in saida]
