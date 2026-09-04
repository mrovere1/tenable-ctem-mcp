"""Primitivas de plugin: detalhe em lote, censo e amostragem estratificada.

`plugin_details_batch` e o maior ganho de token do projeto. O detalhe completo
de um plugin tem ~8.200 caracteres (97 atributos: descricao, lista de CVEs,
sinopse, solucao). A skill usa CINCO campos. Vinte plugins pelo caminho completo
sao ~164.000 caracteres; pelos cinco campos, ~1.500 tokens.

NAO EXPONHA CAMPOS EXTRAS AQUI. A economia depende disso, e e regra fechada.

O censo por busca nao existe: `plugins_search_plugins` aceita palavra-chave e
CVE, nao lista de IDs. O quadro de amostragem certo e
GET /workbenches/vulnerabilities, que devolve plugin, contagem de deteccoes,
VPR e familia de todos os plugins daquela severidade numa chamada - 121 plugins
criticos no sandbox.
"""

from __future__ import annotations

import math
import random
from typing import Any

from .client import CACHE, chamar
from .preflight import validar_parametros_workbenches

SEVERIDADES = ("info", "low", "medium", "high", "critical")

# Semente fixa: a amostra tem de ser reproduzivel entre execucoes, senao o
# mesmo tenant pontua diferente a cada rodada e o golden test nao existe.
SEMENTE_AMOSTRA = 20260903


# ----------------------------------------------------------------------------
# Detalhe em lote - cinco campos, nunca mais
# ----------------------------------------------------------------------------

def _cinco_campos(bruto: dict) -> dict[str, Any]:
    campos: dict[str, Any] = {
        "plugin_id": bruto.get("id"),
        "scan_type": None,        # local ou remote
        "published": None,        # data de publicacao do plugin
        "exploit_available": None,
        "exploitability": None,
        "cisa_known_exploited": [],
    }
    for a in bruto.get("attributes") or []:
        nome = a.get("attribute_name")
        valor = a.get("attribute_value")
        if nome == "plugin_type":
            campos["scan_type"] = valor
        elif nome == "plugin_publication_date":
            campos["published"] = valor
        elif nome == "exploit_available":
            campos["exploit_available"] = str(valor).lower() == "true"
        elif nome == "exploitability_ease":
            campos["exploitability"] = valor
        elif nome == "xref" and str(valor).startswith("CISA-KNOWN-EXPLOITED:"):
            campos["cisa_known_exploited"].append(str(valor).split(":", 1)[1])
    return campos


def plugin_details_batch(plugin_ids: list[int]) -> dict[str, Any]:
    """Detalhe de N plugins numa chamada do cliente, com so cinco campos.

    O servidor faz N requisicoes a API - o ganho e de token no transporte MCP,
    nao de requisicao na Tenable. Plugin que falhar entra em `lacunas` com a
    causa; os outros continuam. Numero parcial silencioso e proibido, mas
    resultado parcial DECLARADO e legitimo.
    """
    itens: list[dict] = []
    lacunas: list[dict] = []
    for pid in plugin_ids:
        chave = f"plugin_details/{pid}"
        achou, valor = CACHE.get(chave)
        if achou:
            itens.append(valor)
            continue
        try:
            bruto = chamar("GET", f"/plugins/plugin/{pid}")
        except Exception as e:  # noqa: BLE001
            lacunas.append({"plugin_id": pid, "causa": str(e)[:200]})
            continue
        campos = _cinco_campos(bruto)
        CACHE.set(chave, campos)
        itens.append(campos)
    return {"plugins": itens, "lacunas": lacunas,
            "n_pedidos": len(plugin_ids), "n_resolvidos": len(itens)}


# ----------------------------------------------------------------------------
# Censo - o quadro de amostragem
# ----------------------------------------------------------------------------

def plugin_census(severity: str = "critical") -> dict[str, Any]:
    """Quadro de amostragem: plugin, contagem de deteccoes, VPR e familia.

    Uma chamada, em cache por TTL curto. E o denominador de D4, M3, V1 e V2.
    """
    sev = str(severity).lower()
    if sev not in SEVERIDADES:
        raise ValueError(f"severidade invalida: {severity!r}. Use uma de {SEVERIDADES}.")

    chave = f"plugin_census/{sev}"
    achou, valor = CACHE.get(chave)
    if achou:
        return dict(valor, servido_do_cache=True)

    params = validar_parametros_workbenches({"severity": sev})
    resp = chamar("GET", "/workbenches/vulnerabilities", params={
        "filter.0.filter": "severity",
        "filter.0.quality": "eq",
        "filter.0.value": params["severity"],
        "filter.search_type": "and",
    })
    vs = resp.get("vulnerabilities") or []
    plugins = [{
        "plugin_id": v.get("plugin_id"),
        "plugin_name": v.get("plugin_name"),
        "family": v.get("plugin_family"),
        "count": v.get("count"),
        "vpr": (v.get("vpr_score") if isinstance(v.get("vpr_score"), (int, float))
                else None),
    } for v in vs]

    censo = {
        "severidade": sev,
        "plugins_distintos": len(plugins),
        "deteccoes": sum(p["count"] or 0 for p in plugins),
        "plugins": plugins,
        "filtro_literal": f"workbenches/vulnerabilities severity={sev}",
        "servido_do_cache": False,
    }
    CACHE.set(chave, censo)
    return censo


# ----------------------------------------------------------------------------
# Amostragem estratificada - alocacao proporcional, piso do estrato B,
# ponderacao por deteccao e intervalo de Wilson.
# Regras em _skills/.../references/mcp-preflight.md secao 4.
# ----------------------------------------------------------------------------

def wilson(sucessos: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """IC 95% de proporcao pelo metodo de Wilson.

    Com n=10 o intervalo tem ~50 pontos de largura - inutil para separar
    estagios. E por isso que o portao de confianca existe.
    """
    if n == 0:
        return (0.0, 1.0)
    p = sucessos / n
    d = 1 + z * z / n
    centro = (p + z * z / (2 * n)) / d
    margem = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centro - margem), min(1.0, centro + margem))


def amostrar_estratificado(plugins: list[dict], n: int = 30,
                           corte_vpr: float = 7.0,
                           piso_estrato_b: int = 4) -> dict[str, Any]:
    """Amostra estratificada por VPR, com alocacao PROPORCIONAL a populacao.

    Erro que esta funcao existe para nao repetir: na primeira execucao real a
    amostra foi alocada 60/40 por decisao de desenho enquanto a populacao era
    65/35. Deu quase certo por coincidencia. Num tenant onde o estrato B seja
    10% da populacao, uma alocacao de 40% enviesaria gravemente.

    O piso do estrato B e deliberado: o estrato B nao existe para estimar taxa,
    existe para ENCONTRAR casos de subpriorizado. Quando o piso e acionado o
    estrato fica sobre-representado de proposito - e a ponderacao por populacao
    e o que impede que isso contamine as taxas.
    """
    a = [p for p in plugins if (p.get("vpr") or 0) >= corte_vpr]
    b = [p for p in plugins if (p.get("vpr") or 0) < corte_vpr]
    total = len(plugins)
    if total == 0:
        return {"amostra": [], "estratos": {}, "n": 0}

    det_a = sum(p.get("count") or 0 for p in a)
    det_b = sum(p.get("count") or 0 for p in b)
    det_total = det_a + det_b

    share_a = len(a) / total
    n = min(n, total)
    n_a = round(n * share_a)
    n_b = n - n_a
    if b and n_b < piso_estrato_b:
        n_b = min(piso_estrato_b, len(b))
        n_a = min(n - n_b, len(a))
    n_a = min(n_a, len(a))
    n_b = min(n_b, len(b))

    rng = random.Random(SEMENTE_AMOSTRA)
    am_a = rng.sample(a, n_a) if n_a else []
    am_b = rng.sample(b, n_b) if n_b else []
    for p in am_a:
        p["estrato"] = "A"
    for p in am_b:
        p["estrato"] = "B"

    return {
        "amostra": am_a + am_b,
        "n": n_a + n_b,
        "estratos": {
            "A": {"populacao": len(a), "amostra": n_a,
                  "share_por_plugin": share_a,
                  "share_por_deteccao": (det_a / det_total) if det_total else 0.0},
            "B": {"populacao": len(b), "amostra": n_b,
                  "share_por_plugin": 1 - share_a,
                  "share_por_deteccao": (det_b / det_total) if det_total else 0.0},
        },
        "corte_vpr": corte_vpr,
        "piso_estrato_b_acionado": bool(b) and n_b == piso_estrato_b,
        "semente": SEMENTE_AMOSTRA,
    }


def taxa_ponderada(amostra: list[dict], detalhes: dict[int, dict],
                   predicado, estratos: dict, base: str = "por_deteccao"
                   ) -> dict[str, Any]:
    """Estima dentro de cada estrato e combina pelos pesos da POPULACAO.

    Nunca calcular a taxa sobre a amostra inteira misturada: os estratos tem
    peso diferente na populacao, e o piso do estrato B sobre-representa o B de
    proposito.
    """
    chave_peso = "share_por_deteccao" if base == "por_deteccao" else "share_por_plugin"
    por_estrato: dict[str, dict] = {}
    for nome in ("A", "B"):
        do_estrato = [p for p in amostra if p.get("estrato") == nome]
        vistos = [detalhes[p["plugin_id"]] for p in do_estrato
                  if p["plugin_id"] in detalhes]
        sucessos = sum(1 for d in vistos if predicado(d))
        n = len(vistos)
        por_estrato[nome] = {
            "n": n, "sucessos": sucessos,
            "taxa": (sucessos / n) if n else None,
            "ic95": wilson(sucessos, n) if n else None,
            "peso": estratos.get(nome, {}).get(chave_peso, 0.0),
        }
    combinada = sum((e["taxa"] or 0) * e["peso"] for e in por_estrato.values())
    n_total = sum(e["n"] for e in por_estrato.values())
    suc_total = sum(e["sucessos"] for e in por_estrato.values())
    return {
        "taxa_ponderada": combinada,
        "por_estrato": por_estrato,
        "n": n_total,
        "ic95_amostra_inteira": wilson(suc_total, n_total),
        "base_dos_pesos": base,
    }


# Acima deste numero de plugins, o censo sai caro demais e a amostra volta.
# O numero vem de medicao: 121 plugins levam 64 s e ~5.400 tokens de saida
# (528 ms por plugin, sequencial). 300 mantem o pior caso em ~2,6 min e
# ~13.000 tokens - ainda abaixo dos ~15.000 que o MCP oficial gastava para
# VINTE plugins. Paralelizar as chamadas e a alavanca para subir este limite.
LIMITE_CENSO = 300


def amostra_com_detalhes(n: int = 30, corte_vpr: float = 7.0,
                         severity: str = "critical",
                         limite_censo: int = LIMITE_CENSO,
                         modo: str = "auto") -> dict[str, Any]:
    """Detalhe dos cinco campos para TODOS os plugins, ou para uma amostra.

    Existe para que D4, V1, V2 e M3 falem do MESMO conjunto. Se cada indicador
    sorteasse o seu, o relatorio descreveria quatro amostras diferentes com um
    unico tamanho declarado - e o intervalo publicado nao valeria para nenhuma.

    `modo`:
      auto     censo se couber em `limite_censo`, senao amostra (default)
      censo    forca o censo, custe o que custar
      amostra  forca a amostra estratificada

    POR QUE O CENSO E O DEFAULT AGORA. A amostragem existia porque
    `plugins_search_plugins` aceita palavra-chave e CVE, nao lista de IDs - foi
    por isso que `censo_d4_m3` virou false em 2026-09-03. `plugin_details_batch`
    aceita lista de IDs, entao a restricao caiu.

    O censo elimina de uma vez quatro fontes de imprecisao que a amostra
    obrigava a administrar: o portao de Wilson, a base de ponderacao
    (por_deteccao contra por_plugin movia V1 em 5 pontos sozinha), o vies de
    alocacao entre estratos, e a irreprodutibilidade que impedia V1, V2 e M3 de
    terem golden test. Medido nos 121 plugins criticos do sandbox: a amostra de
    n=30 deu V1 62,7% e o censo deu 61,2% - a amostra estava certa, mas isso so
    se sabe TENDO o censo.
    """
    chave = f"conjunto/{severity}/{n}/{corte_vpr}/{modo}/{limite_censo}"
    achou, valor = CACHE.get(chave)
    if achou:
        return valor

    censo = plugin_census(severity)
    todos = censo["plugins"]
    fazer_censo = (modo == "censo"
                   or (modo == "auto" and len(todos) <= limite_censo))

    if fazer_censo:
        for p in todos:
            p["estrato"] = "censo"
        conjunto = {
            "modo": "censo",
            "amostra": todos,
            "n": len(todos),
            "populacao": len(todos),
            "estratos": {"censo": {"populacao": len(todos), "amostra": len(todos),
                                   "share_por_plugin": 1.0,
                                   "share_por_deteccao": 1.0}},
            "corte_vpr": corte_vpr,
            "piso_estrato_b_acionado": False,
            "semente": None,
            "nota": ("Censo: todos os plugins da severidade. Nao ha intervalo de "
                     "confianca porque nao ha inferencia - a taxa e a taxa."),
        }
    else:
        conjunto = amostrar_estratificado(todos, n=n, corte_vpr=corte_vpr)
        conjunto["modo"] = "amostra"
        conjunto["populacao"] = len(todos)
        conjunto["nota"] = (
            f"Amostra: a populacao tem {len(todos)} plugins, acima do limite de "
            f"{limite_censo} para censo. Taxas sao estimativas, com intervalo de "
            "Wilson por estrato e para o conjunto.")

    lote = plugin_details_batch([p["plugin_id"] for p in conjunto["amostra"]])
    pacote = {
        "censo": censo,
        "amostra": conjunto,
        "detalhes": {d["plugin_id"]: d for d in lote["plugins"]},
        "lacunas": lote["lacunas"],
    }
    CACHE.set(chave, pacote)
    return pacote


def taxa(conjunto: dict, detalhes: dict, predicado, base: str = "por_deteccao"
         ) -> dict[str, Any]:
    """Taxa exata no censo; ponderada com IC de Wilson na amostra.

    No censo nao ha o que ponderar nem o que inferir: a taxa e a contagem. O
    campo `base_dos_pesos` vem `nao_se_aplica`, e nao um rotulo que sugira que
    houve uma escolha de metodo onde nao houve.
    """
    if conjunto.get("modo") == "censo":
        vistos = [detalhes[p["plugin_id"]] for p in conjunto["amostra"]
                  if p["plugin_id"] in detalhes]
        sucessos = sum(1 for d in vistos if predicado(d))
        n = len(vistos)
        return {
            "modo": "censo",
            "taxa_ponderada": (sucessos / n) if n else None,
            "n": n, "sucessos": sucessos,
            "por_estrato": {"censo": {"n": n, "sucessos": sucessos,
                                      "taxa": (sucessos / n) if n else None,
                                      "ic95": None, "peso": 1.0}},
            "ic95_amostra_inteira": None,
            "base_dos_pesos": "nao_se_aplica",
            "nota": "Censo: taxa exata, sem intervalo de confianca.",
        }
    r = taxa_ponderada(conjunto["amostra"], detalhes, predicado,
                       conjunto["estratos"], base=base)
    r["modo"] = "amostra"
    return r
