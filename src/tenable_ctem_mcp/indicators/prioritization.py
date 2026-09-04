"""Estagio 3 - Prioritization (P1, P2, P3).

Criterios oficiais: Prioritization e Scoring Methodology.

P1 foi REDEFINIDO em 2026-09-02. A versao anterior era
`findings(VPR >= 9) / findings(CRITICAL)`, que e a concordancia entre dois
modelos de score e nao tem direcao de maturidade defensavel - classificaria
como Ad Hoc um tenant onde os dois modelos simplesmente concordam.

A definicao nova mede o que e maturidade de priorizacao: o contexto de negocio
chega ate a camada de decisao? De todo o backlog que a fila trata como critico
por VPR, quanto esta em ativo com criticidade declarada.

E diferente de S2, e a diferenca e informativa: S2 mede cobertura de tag sobre
o inventario todo; P1 mede cobertura ponderada por onde o risco critico esta.
Um cliente com 27% dos ativos tagueados e 100% do backlog critico em ativo
tagueado TAGUEOU OS ATIVOS CERTOS - isso e mais maduro que o inverso.
"""

from __future__ import annotations

import json
from typing import Any

from .. import Indicador
from ..client import ErroApi, chamar, total_de
from ..preflight import validar_filters, veredito

BUSCA_FINDINGS = "/api/v1/t1/inventory/findings/search"

INDICADORES = ("P1", "P2", "P3")

# O operador `exists` responde 400 em finding_vpr_score. O caminho valido e
# `>= 0.1`, que e aplicado e monotonico: 0,1 -> 4.462 - 7,0 -> 1.254 - 9,0 -> 586.
VPR_MINIMO_PARA_EXISTIR = "0.1"


def _contar(filters: list[dict] | None) -> int | None:
    corpo = {"filters": validar_filters(filters)} if filters else {}
    return total_de(chamar("POST", BUSCA_FINDINGS, corpo=corpo, params={"limit": 1}))


def _literal(filters: list[dict] | None) -> str:
    return (json.dumps(filters, separators=(",", ":"), ensure_ascii=False)
            if filters else "sem filtro (corpus)")


def _vpr(op: str, v: str) -> dict:
    return {"property": "finding_vpr_score", "operator": op, "value": [str(v)]}


def _cvss3(op: str, v: str) -> dict:
    return {"property": "finding_cvss3_base_score", "operator": op, "value": [str(v)]}


def _estado(v: str) -> dict:
    return {"property": "state", "operator": "=", "value": [v]}


def filas(corte: float = 7.0) -> dict[str, Any]:
    """As tres filas comparadas: CVSS >= corte, VPR >= corte, e a intersecao.

    Devolvidas junto com P3 porque sao o que sustenta a recomendacao de
    criterio - e a recomendacao tem de ser medida, nao preferida.
    """
    f_cvss = [_cvss3(">=", corte)]
    f_vpr = [_vpr(">=", corte)]
    f_inter = [_cvss3(">=", corte), _vpr(">=", corte)]
    n_cvss, n_vpr, n_inter = _contar(f_cvss), _contar(f_vpr), _contar(f_inter)
    n_cvss_com_vpr = _contar([_cvss3(">=", corte), _vpr(">=", VPR_MINIMO_PARA_EXISTIR)])
    return {
        "corte": corte,
        "cvss3_maior_igual_corte": n_cvss,
        "vpr_maior_igual_corte": n_vpr,
        "intersecao": n_inter,
        "so_cvss": (n_cvss - n_inter) if None not in (n_cvss, n_inter) else None,
        "so_vpr": (n_vpr - n_inter) if None not in (n_vpr, n_inter) else None,
        "cobertura_de_vpr_na_fatia_alta_pct": (
            round(100.0 * n_cvss_com_vpr / n_cvss, 1) if n_cvss else None),
        "filtro_literal": {"cvss": _literal(f_cvss), "vpr": _literal(f_vpr),
                           "intersecao": _literal(f_inter)},
        "nota": ("A cobertura de VPR que importa para recomendar criterio nao e a "
                 "do backlog inteiro (P2), e a da fatia que o criterio de CVSS "
                 "selecionaria. Onde essa cobertura for baixa, a recomendacao passa "
                 "a ser composta: VPR primario, CVSS ou severidade como fallback, "
                 "mais regra de excecao para CISA KEV e exploit disponivel."),
    }


def calcular(mapeamento: dict, indicadores: list[str] | None = None,
             corte_priorizacao_cliente: dict | None = None,
             p2_valor: float | None = None,
             retrato: dict | None = None) -> list[dict]:
    """P1 a P3. `indicadores=None` calcula os tres.

    `corte_priorizacao_cliente` = {"metrica": "vpr"|"cvss3", "valor": 7.0,
    "confirmado": bool}. Sem metrica declarada, P3 e lacuna - e nao um numero,
    porque "o cliente nao sabe qual criterio usa" e o proprio estagio 1.
    """
    pedidos = [i.upper() for i in (indicadores or INDICADORES)]
    saida: list[Indicador] = []
    corte_cfg = corte_priorizacao_cliente or {}

    from .discovery import descobrir_tenant
    retrato = retrato or descobrir_tenant()
    categorias = retrato["tags"]["categorias"]

    # --- P1: contexto de negocio no backlog critico ---------------------
    if "P1" in pedidos:
        nome_crit = mapeamento.get("categoria_criticidade")
        valores = categorias.get(nome_crit) if nome_crit else None
        if not valores:
            saida.append(Indicador.lacuna_declarada(
                "P1",
                causa=("mapeamento nao informou `categoria_criticidade`, ou a "
                       "categoria nao existe. Categorias: " + ", ".join(sorted(categorias))),
                filtro_literal="nao executado"))
        else:
            f_denominador = [_vpr(">=", "9")]
            f_numerador = f_denominador + [
                {"property": "tag_names", "operator": "=", "value": list(valores)}]
            try:
                den = _contar(f_denominador)
                num = _contar(f_numerador)
                if not den:
                    saida.append(Indicador.lacuna_declarada(
                        "P1", causa="nenhum finding com VPR >= 9; denominador zero.",
                        filtro_literal=_literal(f_denominador), n=0))
                else:
                    por_valor = {v: _contar(f_denominador + [
                        {"property": "tag_names", "operator": "=", "value": [v]}])
                        for v in valores}
                    saida.append(Indicador.ok(
                        "P1", round(100.0 * num / den, 1), n=den,
                        filtro_literal=f"{_literal(f_numerador)} sobre {_literal(f_denominador)}",
                        veredito_preflight=veredito(den, num),
                        contexto={
                            "backlog_vpr_maior_igual_9": den,
                            "em_ativo_com_criticidade": num,
                            "por_valor_de_tag": por_valor,
                            "categoria": nome_crit,
                            "diferenca_para_s1_e_s2": (
                                "S2 mede cobertura de tag sobre o inventario todo; P1 "
                                "mede cobertura ponderada por onde o risco critico esta. "
                                "Cobertura baixa em S2 com P1 alto significa que o "
                                "cliente tagueou os ativos certos."),
                        }))
            except ErroApi as e:
                saida.append(Indicador.lacuna_declarada("P1", causa=str(e),
                                                        filtro_literal=_literal(f_numerador)))

    # --- P2: % do backlog com VPR disponivel ----------------------------
    if "P2" in pedidos:
        f_den = [_estado("ACTIVE")]
        f_num = [_estado("ACTIVE"), _vpr(">=", VPR_MINIMO_PARA_EXISTIR)]
        try:
            den, num = _contar(f_den), _contar(f_num)
            if not den:
                saida.append(Indicador.lacuna_declarada(
                    "P2", causa="nenhum finding ACTIVE; denominador zero.",
                    filtro_literal=_literal(f_den), n=0))
            else:
                saida.append(Indicador.ok(
                    "P2", round(100.0 * num / den, 1), n=den,
                    filtro_literal=f"{_literal(f_num)} sobre {_literal(f_den)}",
                    veredito_preflight=veredito(den, num),
                    contexto={
                        "active": den, "active_com_vpr": num,
                        "nota_do_operador": (
                            "`exists` em finding_vpr_score responde HTTP 400. O "
                            f"caminho valido e >= {VPR_MINIMO_PARA_EXISTIR}, que e "
                            "aplicado e monotonico."),
                    }))
        except ErroApi as e:
            saida.append(Indicador.lacuna_declarada("P2", causa=str(e),
                                                    filtro_literal=_literal(f_num)))

    # --- P3: adequacao do criterio de priorizacao -----------------------
    if "P3" in pedidos:
        metrica = str(corte_cfg.get("metrica") or "").lower()
        valor_corte = corte_cfg.get("valor")
        if metrica not in ("vpr", "cvss3") or valor_corte is None:
            saida.append(Indicador.lacuna_declarada(
                "P3",
                causa=("o criterio de priorizacao do cliente nao foi declarado. "
                       "P3 nao vira numero sem ele: 'o cliente nao sabe qual criterio "
                       "usa' e o proprio estagio Ad Hoc, e cabe a skill classificar."),
                filtro_literal="nao executado"))
        else:
            try:
                q = filas(float(valor_corte))
                fila_cliente = (q["cvss3_maior_igual_corte"] if metrica == "cvss3"
                                else q["vpr_maior_igual_corte"])
                fila_vpr = q["vpr_maior_igual_corte"]
                oportunidade = (max(0.0, 1 - fila_vpr / fila_cliente)
                                if fila_cliente else None)
                saida.append(Indicador.ok(
                    "P3", round(oportunidade, 4) if oportunidade is not None else None,
                    n=fila_cliente,
                    filtro_literal=(f"metrica declarada={metrica} corte={valor_corte}; "
                                    f"{q['filtro_literal']['cvss']} vs "
                                    f"{q['filtro_literal']['vpr']}"),
                    veredito_preflight="ok",
                    contexto={
                        "criterio_declarado": metrica,
                        "corte_declarado": valor_corte,
                        "confirmado_pelo_operador": bool(corte_cfg.get("confirmado")),
                        "filas": q,
                        "p2_cobertura_de_vpr_pct": p2_valor,
                        "composto": (
                            "P3 nao pontua pelo delta puro. O delta VPR x CVSS mede "
                            "OPORTUNIDADE no ambiente, nao comportamento do cliente: "
                            "promove-lo a indicador puniria um cliente por ter parque "
                            "Windows antigo, que nao e escolha de processo. O estagio "
                            "vem da combinacao entre o criterio declarado e a "
                            "oportunidade medida, e depende de P2."),
                        "dependencia": "P3 exige P2 calculado. P2 em lacuna => P3 lacuna.",
                    }))
            except ErroApi as e:
                saida.append(Indicador.lacuna_declarada("P3", causa=str(e),
                                                        filtro_literal="filas"))

    return [i.para_dict() for i in saida]
