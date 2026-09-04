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


def amostra_com_detalhes(n: int = 30, corte_vpr: float = 7.0,
                         severity: str = "critical") -> dict[str, Any]:
    """Censo + amostra + detalhe dos cinco campos, em cache.

    Existe para que D4, V1, V2 e M3 falem da MESMA amostra. Se cada indicador
    sorteasse a sua, o relatorio descreveria quatro amostras diferentes com um
    unico tamanho declarado - e o intervalo de confianca publicado nao valeria
    para nenhuma delas.
    """
    chave = f"amostra/{severity}/{n}/{corte_vpr}"
    achou, valor = CACHE.get(chave)
    if achou:
        return valor

    censo = plugin_census(severity)
    am = amostrar_estratificado(censo["plugins"], n=n, corte_vpr=corte_vpr)
    lote = plugin_details_batch([p["plugin_id"] for p in am["amostra"]])
    pacote = {
        "censo": censo,
        "amostra": am,
        "detalhes": {d["plugin_id"]: d for d in lote["plugins"]},
        "lacunas": lote["lacunas"],
    }
    CACHE.set(chave, pacote)
    return pacote
