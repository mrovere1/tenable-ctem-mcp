"""Estagio 4 - Validation (V1, V2, V3, V4).

Criterio oficial: Risk Detection.

V1 e INFORMATIVO. Um percentual alto de exploit disponivel pode indicar backlog
ruim ou apenas ambiente montado sobre stack popular, que concentra pesquisa de
exploit. Sem premissa do cliente, virar estagio seria interpretacao.

V2 e o indicador mais forte do conjunto e o unico com ancora externa citavel:
os cortes de 14 e 30 dias derivam dos tiers de remediacao da CISA BOD 26-04.
O relatorio declara que a diretiva se aplica a agencias federais dos EUA e aqui
e referencia de prazo reconhecida, nao obrigacao regulatoria do cliente.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .. import Indicador
from ..client import ErroApi, chamar, total_de
from ..plugins import LIMITE_CENSO, amostra_com_detalhes, taxa, wilson
from ..preflight import validar_filters, veredito

BUSCA_FINDINGS = "/api/v1/t1/inventory/findings/search"

INDICADORES = ("V1", "V2", "V3", "V4")

# Busca textual e o caminho valido: `unsupported_by_vendor` existe na API mas
# nao e alcancavel, e `query_text`/`finding_name contains` e filtro aplicado.
TERMOS_EOL = ("Unsupported Version Detection", "SEoL")


def _contar(filters: list[dict] | None) -> int | None:
    corpo = {"filters": validar_filters(filters)} if filters else {}
    return total_de(chamar("POST", BUSCA_FINDINGS, corpo=corpo, params={"limit": 1}))


def _buscar(filters: list[dict], limite: int = 500) -> list[dict]:
    corpo = {"filters": validar_filters(filters)}
    resp = chamar("POST", BUSCA_FINDINGS, corpo=corpo, params={"limit": limite})
    d = resp.get("data")
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        for k in ("items", "findings", "results"):
            if isinstance(d.get(k), list):
                return d[k]
    return []


def _literal(filters: list[dict] | None) -> str:
    return (json.dumps(filters, separators=(",", ":"), ensure_ascii=False)
            if filters else "sem filtro (corpus)")


def _estado(v: str) -> dict:
    return {"property": "state", "operator": "=", "value": [v]}


def _mediana(valores: list[float]) -> float | None:
    if not valores:
        return None
    v = sorted(valores)
    meio = len(v) // 2
    return v[meio] if len(v) % 2 else (v[meio - 1] + v[meio]) / 2


def _dias_desde(data_kev: str, agora: datetime) -> float | None:
    """As datas de CISA-KNOWN-EXPLOITED vem como AAAA/MM/DD."""
    try:
        d = datetime.strptime(data_kev.strip(), "%Y/%m/%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
    return (agora - d).total_seconds() / 86400.0


def calcular(mapeamento: dict | None = None, indicadores: list[str] | None = None,
             corte_vpr_amostra: float = 7.0, n_amostra: int = 30,
             ponderar: str = "por_deteccao",
             modo_plugins: str = "auto",
             limite_censo: int = LIMITE_CENSO,
             retrato: dict | None = None,
             agora: datetime | None = None) -> list[dict]:
    """V1 a V4. `indicadores=None` calcula os quatro.

    `agora` existe para o golden test congelar o relogio: V2 e uma diferenca
    contra o instante da coleta e cresce sozinha a cada dia.

    `ponderar` e `por_deteccao` (default da skill) ou `por_plugin`. A escolha
    muda o numero: na amostra de n=20 do sandbox, V1 da 59,3% por deteccao e
    54,6% por plugin. Por isso a base vai declarada no contexto - taxa
    ponderada sem base declarada nao e verificavel.
    """
    pedidos = [i.upper() for i in (indicadores or INDICADORES)]
    agora = agora or datetime.now(timezone.utc)
    saida: list[Indicador] = []

    from .discovery import descobrir_tenant
    retrato = retrato or descobrir_tenant()

    # --- V1 e V2 saem da mesma amostra ----------------------------------
    if {"V1", "V2"} & set(pedidos):
        try:
            pac = amostra_com_detalhes(n=n_amostra, corte_vpr=corte_vpr_amostra,
                                       modo=modo_plugins, limite_censo=limite_censo)
            am, detalhes = pac["amostra"], pac["detalhes"]
        except (ErroApi, ValueError) as e:
            for ind in ("V1", "V2"):
                if ind in pedidos:
                    saida.append(Indicador.lacuna_declarada(
                        ind, causa=str(e), filtro_literal="censo critical + amostra"))
            am = None

        if am is not None and "V1" in pedidos:
            r = taxa(am, detalhes, lambda d: bool(d.get("exploit_available")),
                     base=ponderar)
            saida.append(Indicador.ok(
                "V1", round(100.0 * r["taxa_ponderada"], 1), n=r["n"],
                filtro_literal=(
                    f"CENSO dos {am['n']} plugins criticos"
                    if am["modo"] == "censo" else
                    f"amostra estratificada de {am['n']} de {am['populacao']}, "
                    f"alocacao proporcional, corte VPR {corte_vpr_amostra}, "
                    f"semente {am['semente']}"),
                veredito_preflight="ok",
                contexto={
                    "informativo": True,
                    "modo": am["modo"], "populacao": am["populacao"],
                    "nota_do_conjunto": am["nota"],
                    "base_dos_pesos": r["base_dos_pesos"],
                    "por_estrato": r["por_estrato"],
                    "ic95_amostra_inteira": r["ic95_amostra_inteira"],
                    "por_que_informativo": (
                        "Percentual alto de exploit disponivel pode indicar backlog "
                        "ruim ou apenas ambiente sobre stack popular, que concentra "
                        "pesquisa de exploit. Sem premissa do cliente, virar estagio "
                        "seria interpretacao."),
                }))

        if am is not None and "V2" in pedidos:
            dias = []
            com_kev = 0
            for p in am["amostra"]:
                d = detalhes.get(p["plugin_id"])
                if not d or not d.get("cisa_known_exploited"):
                    continue
                com_kev += 1
                valores = [x for x in (_dias_desde(k, agora)
                                       for k in d["cisa_known_exploited"]) if x is not None]
                if valores:
                    dias.append(max(valores))   # min(data) => max(dias)
            n_am = am["n"]
            if not dias:
                saida.append(Indicador.lacuna_declarada(
                    "V2", causa=("nenhum plugin da amostra tem data de "
                                 "CISA-KNOWN-EXPLOITED."),
                    filtro_literal=f"{am['modo']} de {n_am} plugins", n=n_am))
            else:
                saida.append(Indicador.ok(
                    "V2", round(_mediana(dias), 1), n=len(dias),
                    filtro_literal=(f"mediana de (agora - menor data CISA-KNOWN-EXPLOITED) "
                                    f"em {len(dias)} de {n_am} plugins ({am['modo']})"),
                    veredito_preflight="ok",
                    contexto={
                        "modo": am["modo"],
                        "plugins_com_kev": com_kev,
                        "plugins_na_amostra": n_am,
                        "proporcao_com_kev": round(com_kev / n_am, 3) if n_am else None,
                        "ic95_proporcao_com_kev": (None if am["modo"] == "censo"
                                                   else wilson(com_kev, n_am)),
                        "invertido": True,
                        "origem_do_limiar": (
                            "Os cortes de 14 e 30 dias derivam dos tiers de remediacao "
                            "da CISA BOD 26-04. A diretiva se aplica a agencias federais "
                            "dos EUA; aqui e referencia de prazo reconhecida, nao "
                            "obrigacao regulatoria do cliente."),
                    }))

    # --- V3: taxa de reincidencia ---------------------------------------
    if "V3" in pedidos:
        f_r, f_f = [_estado("RESURFACED")], [_estado("FIXED")]
        try:
            n_r, n_f = _contar(f_r), _contar(f_f)
            den = (n_r or 0) + (n_f or 0)
            if not den:
                saida.append(Indicador.lacuna_declarada(
                    "V3", causa="nenhum finding RESURFACED nem FIXED; denominador zero.",
                    filtro_literal=f"{_literal(f_r)} e {_literal(f_f)}", n=0))
            else:
                saida.append(Indicador.ok(
                    "V3", round(100.0 * n_r / den, 1), n=den,
                    filtro_literal=f"{_literal(f_r)} sobre ({_literal(f_r)} + {_literal(f_f)})",
                    veredito_preflight="ok",
                    contexto={
                        "resurfaced": n_r, "fixed": n_f, "invertido": True,
                        "leitura": ("`state` e estado do registro, nao calculo. "
                                    "Reincidencia alta indica correcao que nao se "
                                    "sustenta: patch revertido, imagem base nao "
                                    "corrigida, reprovisionamento a partir de "
                                    "template vulneravel."),
                    }))
        except ErroApi as e:
            saida.append(Indicador.lacuna_declarada("V3", causa=str(e),
                                                    filtro_literal=_literal(f_r)))

    # --- V4: % de DEVICE com software fora de suporte -------------------
    if "V4" in pedidos:
        devices = retrato["ativos"]["por_asset_class"].get("DEVICE", 0)
        if not devices:
            saida.append(Indicador.lacuna_declarada(
                "V4", causa="nenhum ativo DEVICE; denominador zero.",
                filtro_literal="asset_class=DEVICE", n=0))
        else:
            f_device = {"property": "asset_class", "operator": "=", "value": ["DEVICE"]}
            ativos_eol: set[str] = set()
            por_termo: dict[str, int] = {}
            usados = []
            try:
                for termo in TERMOS_EOL:
                    f = [{"property": "finding_name", "operator": "contains",
                          "value": [termo]}, f_device]
                    usados.append(_literal(f))
                    itens = _buscar(f)
                    ids = {i.get("asset_id") for i in itens if i.get("asset_id")}
                    por_termo[termo] = len(ids)
                    ativos_eol |= ids
                saida.append(Indicador.ok(
                    "V4", round(100.0 * len(ativos_eol) / devices, 1), n=devices,
                    filtro_literal=" UNIAO ".join(usados),
                    veredito_preflight=veredito(devices, len(ativos_eol)),
                    contexto={
                        "devices_com_eol": len(ativos_eol), "devices": devices,
                        "ativos_distintos_por_termo": por_termo,
                        "invertido": True,
                        "denominador": ("DEVICE, nao o total de ativos: o inventario "
                                        "inclui IDENTITY, ACCOUNT e GROUP, que nao tem "
                                        "software instalado. No sandbox a diferenca e "
                                        "de dois estagios - 7/30 da 23%, 7/8 da 87,5%."),
                        "caminho": ("`unsupported_by_vendor` existe na API mas nao e "
                                    "alcancavel. Busca textual em finding_name e filtro "
                                    "comprovadamente aplicado."),
                    }))
            except ErroApi as e:
                saida.append(Indicador.lacuna_declarada(
                    "V4", causa=str(e), filtro_literal=" UNIAO ".join(usados)))

    return [i.para_dict() for i in saida]
