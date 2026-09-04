"""Estagio 5 - Mobilization (M1, M2, M3, M4).

Criterios oficiais: Mobilization e Metrics | Reporting.

M1 e M2 exigem que o operador DECLARE quais scans representam a cadencia de
avaliacao. O servidor nao escolhe, e a razao esta medida: no sandbox, so o scan
recorrente da mediana 21 dias e maximo 140; somando todos os scans com
historico da mediana 1,0 e maximo 89, porque um dos scans roda quase todo dia e
nao representa a avaliacao dos ativos em escopo. Dois estagios de diferenca
saindo de uma escolha que ninguem declarou e o pior tipo de numero.

M4 e o unico indicador que nao sai da API de Exposure Management, e continua
assim depois do M3: `last_fixed`, `time_taken_to_fix` e
`severity_modification_type` nao estao entre as 44 propriedades de findings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .. import Indicador
from ..cadence import scan_cadence
from ..client import ErroApi
from ..mttr import mttr_cadence_guard, mttr_collect
from ..plugins import LIMITE_CENSO, amostra_com_detalhes

INDICADORES = ("M1", "M2", "M3", "M4")

# Cortes de M4, so para a leitura do contexto. O ESTAGIO e calculado pela
# skill: aqui vai o numero e a informacao de que M4 e o MENOR dos dois.
CORTES_M4 = {"critical": [90, 30, 15, 7], "high": [180, 60, 30, 14]}


def _mediana(v: list[float]) -> float | None:
    if not v:
        return None
    s = sorted(v)
    m = len(s) // 2
    return float(s[m]) if len(s) % 2 else (s[m - 1] + s[m]) / 2


def _dias_desde_publicacao(data: str, agora: datetime) -> float | None:
    """`Published` vem como AAAA/MM/DD."""
    try:
        d = datetime.strptime(str(data).strip(), "%Y/%m/%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
    return (agora - d).total_seconds() / 86400.0


def calcular(mapeamento: dict | None = None, indicadores: list[str] | None = None,
             corte_vpr_amostra: float = 7.0, n_amostra: int = 30,
             modo_plugins: str = "auto", limite_censo: int = LIMITE_CENSO,
             mttr_days: int = 180,
             mttr_severities: list[str] | None = None,
             mttr_max_wait_s: int = 240,
             mttr_export_uuid: str | None = None,
             corte_lote: int = 2, pct_em_lote_max: float = 40.0,
             retrato: dict | None = None,
             agora: datetime | None = None) -> list[dict]:
    """M1 a M4. `indicadores=None` calcula os quatro.

    `mapeamento["scans_recorrentes"]` e obrigatorio para M1 e M2.
    """
    pedidos = [i.upper() for i in (indicadores or INDICADORES)]
    mapeamento = mapeamento or {}
    agora = agora or datetime.now(timezone.utc)
    saida: list[Indicador] = []

    from .discovery import descobrir_tenant
    retrato = retrato or descobrir_tenant()

    # --- M1 e M2 saem da mesma leitura de cadencia ----------------------
    if {"M1", "M2"} & set(pedidos):
        scans = mapeamento.get("scans_recorrentes") or []
        if not scans:
            com_hist = [s["scan_id"] for s in retrato["scans"]["scans"]
                        if (s.get("runs") or 0) > 0]
            causa = ("mapeamento nao informou `scans_recorrentes`. O servidor nao "
                     "escolhe: no sandbox, so o scan recorrente da mediana 21 dias "
                     "e maximo 140, e somando todos os scans com historico da "
                     "mediana 1,0 e maximo 89, porque um deles roda quase todo dia. "
                     f"Scans com historico neste tenant: {com_hist}.")
            for ind in ("M1", "M2"):
                if ind in pedidos:
                    saida.append(Indicador.lacuna_declarada(
                        ind, causa=causa, filtro_literal="nao executado"))
        else:
            try:
                cad = scan_cadence(scans)
                intervalos = cad["intervalos_dias"]
                literal = (f"scan_ids={scans}, runs colapsados em "
                           f"{cad['dias_distintos_de_avaliacao']} dias distintos de "
                           f"avaliacao; intervalos {intervalos}")
                if "M1" in pedidos:
                    if not intervalos:
                        saida.append(Indicador.lacuna_declarada(
                            "M1", causa=("menos de dois dias distintos de avaliacao: "
                                         "nao ha intervalo para medir."),
                            filtro_literal=literal, n=cad["dias_distintos_de_avaliacao"]))
                    else:
                        saida.append(Indicador.ok(
                            "M1", cad["mediana_dias"], n=len(intervalos),
                            filtro_literal=literal, veredito_preflight="ok",
                            contexto={
                                "invertido": True,
                                "dias_distintos": cad["dias_distintos_de_avaliacao"],
                                "intervalos_dias": intervalos,
                                "mediana_sem_colapso_dias": {
                                    k: v["mediana_sem_colapso_dias"]
                                    for k, v in cad["scans"].items()},
                                "por_que_colapsar": (
                                    "Um scan relancado minutos depois e a MESMA "
                                    "avaliacao. Sem colapso a mediana do sandbox e "
                                    "1,42 dia; com colapso, 21 - Standardized em vez "
                                    "de Optimized, dois estagios de diferenca."),
                                "lacunas": cad["lacunas"],
                            }))
                if "M2" in pedidos:
                    if not intervalos:
                        saida.append(Indicador.lacuna_declarada(
                            "M2", causa="menos de dois dias distintos de avaliacao.",
                            filtro_literal=literal))
                    else:
                        saida.append(Indicador.ok(
                            "M2", float(cad["maximo_dias"]), n=len(intervalos),
                            filtro_literal=literal, veredito_preflight="ok",
                            contexto={"invertido": True,
                                      "nota": ("M2 nao muda com o colapso de runs: o "
                                               "maior intervalo e o mesmo."),
                                      "lacunas": cad["lacunas"]}))
            except ErroApi as e:
                for ind in ("M1", "M2"):
                    if ind in pedidos:
                        saida.append(Indicador.lacuna_declarada(
                            ind, causa=str(e), filtro_literal=f"scan_ids={scans}"))

    # --- M3: idade da correcao disponivel, da amostra -------------------
    if "M3" in pedidos:
        try:
            pac = amostra_com_detalhes(n=n_amostra, corte_vpr=corte_vpr_amostra,
                                       modo=modo_plugins, limite_censo=limite_censo)
            dias, sem_data = [], 0
            for p in pac["amostra"]["amostra"]:
                d = pac["detalhes"].get(p["plugin_id"])
                v = _dias_desde_publicacao(d.get("published"), agora) if d else None
                if v is None:
                    sem_data += 1
                else:
                    dias.append(v)
            n_am = pac["amostra"]["n"]
            if not dias:
                saida.append(Indicador.lacuna_declarada(
                    "M3", causa="nenhum plugin da amostra tem data de publicacao.",
                    filtro_literal=f"amostra de {n_am} plugins", n=n_am))
            else:
                saida.append(Indicador.ok(
                    "M3", round(_mediana(dias), 1), n=len(dias),
                    filtro_literal=(
                        f"mediana de (agora - Published) em {len(dias)} de {n_am} "
                        + ("plugins criticos (CENSO)" if pac["amostra"]["modo"] == "censo"
                           else f"plugins da amostra estratificada, "
                                f"semente {pac['amostra']['semente']}")),
                    veredito_preflight="ok",
                    contexto={
                        "invertido": True,
                        "modo": pac["amostra"]["modo"],
                        "populacao": pac["amostra"]["populacao"],
                        "plugins_sem_data": sem_data,
                        "proxy_declarado": (
                            "`Published` e a data de publicacao do PLUGIN DE "
                            "DETECCAO, nao a do patch do fabricante - diferenca de "
                            "dias. Rotular como proxy no relatorio. "
                            "`patch_publication_date` e alcancavel pela API direta, "
                            "mas plugin_details_batch expoe cinco campos por regra "
                            "fechada; trocar o proxy pelo dado real e decisao da "
                            "skill. Ver docs/limitacoes.md."),
                    }))
        except (ErroApi, ValueError) as e:
            saida.append(Indicador.lacuna_declarada(
                "M3", causa=str(e), filtro_literal="censo critical + amostra"))

    # --- M4: MTTR, com a guarda de cadencia -----------------------------
    if "M4" in pedidos:
        try:
            r = mttr_collect(days=mttr_days,
                             severities=mttr_severities or ["critical", "high"],
                             max_wait_s=mttr_max_wait_s, export_uuid=mttr_export_uuid,
                             corte_lote=corte_lote)
            if r.get("status") == "pendente":
                saida.append(Indicador.lacuna_declarada(
                    "M4",
                    causa=(f"export ainda em andamento ({r.get('status_do_job')}). "
                           "Isto e recuperavel: chame de novo passando "
                           f"mttr_export_uuid='{r['export_uuid']}'. Abrir outro "
                           "export responderia 409."),
                    filtro_literal=f"POST /vulns/export, {mttr_days} dias"))
            else:
                cad_mttr = r["cadencia_de_scan"]
                datas_scan = None
                scans = (mapeamento or {}).get("scans_recorrentes")
                if scans:
                    try:
                        datas_scan = scan_cadence(scans)["datas"]
                    except ErroApi:
                        datas_scan = None
                guarda = mttr_cadence_guard(cad_mttr["janelas"], datas_scan,
                                            pct_em_lote_max)
                sev = r["mttr_por_severidade"]
                p50c = (sev.get("critical") or {}).get("mttr_dias_p50")
                p50h = (sev.get("high") or {}).get("mttr_dias_p50")
                contexto = {
                    "invertido": True,
                    "p50_critical": p50c, "p50_high": p50h,
                    # Evidencia por severidade. A skill exige `n`, a origem do
                    # dado (nativo vs derivado) e os reabertos para poder
                    # declarar o metodo no relatorio; sem isso ela pediria uma
                    # conclusao metodologica que o servidor nao entregou.
                    "por_severidade": sev,
                    "cortes": CORTES_M4,
                    "como_pontuar": (
                        "M4 e o MENOR dos dois estagios - mobilizacao madura fecha as "
                        "duas severidades, nao compensa uma com a outra. O estagio e "
                        "calculado pela skill; aqui vao os dois p50."),
                    "guarda_de_cadencia": guarda,
                    "metodo_percentil": r["metodo_percentil"],
                    "estados_incluidos": r["estados_incluidos_no_mttr"],
                    "severidade_modificada_diferente_de_none":
                        r["severidade_modificada_diferente_de_none"],
                    "export_uuid": r["export_uuid"],
                }
                if guarda["veredito"] == "lacuna":
                    saida.append(Indicador.lacuna_declarada(
                        "M4",
                        causa=("o MTTR aqui mede cadencia de avaliacao, nao tempo de "
                               "correcao: " + "; ".join(guarda["motivos"]) +
                               ". Com cadencia dominante, M4 mediria a mesma coisa que "
                               "M1 e M2 - contaria cadencia duas vezes chamando de "
                               "maturidade de remediacao o que e maturidade de "
                               "avaliacao."),
                        filtro_literal=(f"POST /vulns/export, {mttr_days} dias, "
                                        f"corte de lote {corte_lote}"),
                        n=cad_mttr["findings_com_mttr"]))
                    saida[-1].contexto = contexto
                else:
                    saida.append(Indicador.ok(
                        "M4", {"p50_critical": p50c, "p50_high": p50h},
                        n=cad_mttr["findings_com_mttr"],
                        filtro_literal=(f"POST /vulns/export, {mttr_days} dias, "
                                        f"corte de lote {corte_lote}"),
                        veredito_preflight="ok", contexto=contexto))
        except (ErroApi, ValueError) as e:
            saida.append(Indicador.lacuna_declarada(
                "M4", causa=str(e), filtro_literal="POST /vulns/export"))

    return [i.para_dict() for i in saida]
