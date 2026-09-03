"""Deny-list de filtros e pares discriminantes.

Fonte: _docs/matriz-confianca-filtros-mcp.md, atualizada em 2026-09-03.
A lista vive AQUI e em nenhum outro lugar - o CLAUDE.md aponta para ca de
proposito, para nao existirem duas copias divergindo.

Por que este modulo existe. A API aceita filtros que nao aplica, e nao retorna
erro. A consulta parece filtrada, devolve o total do corpus inteiro, e o numero
sobe para o relatorio como se fosse resultado do filtro. Isso nao e dado
faltando: e numero errado com aparencia de certo, e nao ha sinal de que ocorreu.

Regra: filtro nao testado e filtro nao confiavel. A deny-list rejeita ANTES de
a requisicao sair - erro explicito, nunca contagem.

RESSALVA IMPORTANTE: os vereditos abaixo foram medidos atraves do MCP OFICIAL
da Tenable. Este servidor fala direto com a API REST, e o comportamento pode
diferir. `ctem_preflight` (marco M3) reexecuta os pares discriminantes contra o
caminho novo - nenhum veredito e herdado por confianca.
"""

from __future__ import annotations

from typing import Any


class ErroDenyList(ValueError):
    """Filtro proibido. Nunca vira numero: vira erro com a prova."""

    def __init__(self, mensagem: str, regra: str, prova: str):
        super().__init__(mensagem)
        self.regra = regra
        self.prova = prova

    def para_dict(self) -> dict[str, str]:
        return {"erro": "filtro_negado", "regra": self.regra,
                "detalhe": str(self), "prova": self.prova}


# Propriedades de data em findings. Aceitas, silenciosamente ignoradas, em
# TODO operador e formato testado (within last, older than, ISO 8601, epoch ms).
PROPRIEDADES_DE_DATA_EM_FINDINGS = frozenset({
    "last_updated", "first_observed_at", "last_observed_at",
    "first_found", "last_found", "last_seen", "first_seen",
})

# Booleanos de workbenches comprovadamente ignorados, mais o nao testado da
# mesma familia - presumido ignorado ate prova em contrario.
PARAMETROS_NEGADOS_EM_WORKBENCHES = frozenset({
    "authenticated", "exploitable", "resolvable",
})

# Operadores que a propriedade lista mas nao suporta.
OPERADORES_NEGADOS_POR_PROPRIEDADE = {
    "finding_vpr_score": frozenset({"exists"}),
}

PROVAS = {
    "data_em_findings":
        "last_updated 'older than 3650d' devolveu 1840 findings, o corpus inteiro, "
        "igual a 'within last 1d'. Revalidado em 2026-09-03: state=FIXED devolveu "
        "50, e within last 1d, older than 3650d e < 2020-01-01 devolveram os mesmos 50.",
    "booleano_em_workbenches":
        "authenticated true -> 20 e false -> 20, resultados identicos. exploitable "
        "true -> 20, incluindo Mozilla Firefox SEoL e checagem de Spectre, que nao "
        "tem exploit publico.",
    "filters_string":
        "filters='tag_count >= 1' como texto livre devolveu os 30 ativos do corpus, "
        "sem erro. O mesmo filtro como array JSON devolveu 9. Confirmado 2026-09-03.",
    "exists_em_vpr":
        "[{'property':'finding_vpr_score','operator':'exists'}] responde HTTP 400. "
        "Usar >= 0.1, que e aplicado e monotonico: 0,1 -> 4.462 - 7,0 -> 1.254 - "
        "9,0 -> 586.",
    "age_nao_e_idade":
        "O ultimo scan do sandbox foi 84 dias antes da coleta, e o corte ficou entre "
        "age=80 (zero) e age=90 (20) - na data do ultimo scan, nao na data de "
        "descoberta. age e recencia da ultima observacao, nao idade do finding.",
}


def validar_filters(filters: Any) -> list[dict]:
    """Valida o parametro `filters` e devolve o array normalizado.

    A validacao mais barata e mais valiosa do servidor: rejeitar string.
    A sintaxe 'tag_count >= 1' e exatamente a que list_inventory_properties
    sugere ao listar os operadores de cada propriedade - por isso e a armadilha
    mais facil de cometer do conjunto.
    """
    if filters is None:
        return []
    if isinstance(filters, str):
        raise ErroDenyList(
            "O parametro `filters` exige array JSON. Recebi uma string "
            f"({filters!r}), que a API descarta em silencio e devolve a consulta "
            "SEM filtro nenhum - o total do corpus inteiro com aparencia de "
            "resultado filtrado.",
            regra="filters_precisa_ser_array_json",
            prova=PROVAS["filters_string"])
    if not isinstance(filters, list):
        raise ErroDenyList(
            f"`filters` precisa ser um array JSON, recebi {type(filters).__name__}.",
            regra="filters_precisa_ser_array_json",
            prova=PROVAS["filters_string"])

    for clausula in filters:
        if not isinstance(clausula, dict):
            raise ErroDenyList(
                f"Cada clausula de `filters` precisa ser um objeto, recebi "
                f"{type(clausula).__name__}.",
                regra="filters_precisa_ser_array_json",
                prova=PROVAS["filters_string"])
        prop = str(clausula.get("property", ""))
        op = str(clausula.get("operator", ""))
        _negar_propriedade(prop)
        _negar_operador(prop, op)
    return filters


def _negar_propriedade(prop: str) -> None:
    if prop.lower() in PROPRIEDADES_DE_DATA_EM_FINDINGS:
        raise ErroDenyList(
            f"A propriedade de data `{prop}` e aceita pela API e silenciosamente "
            "ignorada: a consulta volta com o corpus inteiro. Nao existe filtro de "
            "data confiavel em findings. Para tempo de correcao use mttr_collect, "
            "que vai por POST /vulns/export.",
            regra="sem_filtro_de_data_em_findings",
            prova=PROVAS["data_em_findings"])


def _negar_operador(prop: str, op: str) -> None:
    negados = OPERADORES_NEGADOS_POR_PROPRIEDADE.get(prop.lower())
    if negados and op.lower() in negados:
        raise ErroDenyList(
            f"O operador `{op}` aparece na lista de operadores de `{prop}` mas "
            "responde HTTP 400 nela. Para contar findings com VPR use "
            "`>=` com valor '0.1'.",
            regra="exists_nao_funciona_em_finding_vpr_score",
            prova=PROVAS["exists_em_vpr"])


def validar_parametros_workbenches(params: dict[str, Any]) -> dict[str, Any]:
    """Rejeita os booleanos de workbenches que a API aceita e nao aplica."""
    for chave in params:
        if chave.lower() in PARAMETROS_NEGADOS_EM_WORKBENCHES:
            raise ErroDenyList(
                f"O parametro `{chave}` de workbenches e aceito e nao aplicado: "
                "true e false devolvem o mesmo conjunto. Usar como filtro produz "
                "numero do corpus inteiro com aparencia de filtrado.",
                regra="booleano_de_workbenches_ignorado",
                prova=PROVAS["booleano_em_workbenches"])
    return params


def veredito(total_corpus: int | None, total_filtrado: int | None) -> str:
    """O teste discriminante em uma linha.

    Se o total filtrado for identico ao corpus, o filtro esta ignorado e o
    indicador e lacuna - nunca se publica o numero.
    """
    if total_corpus is None or total_filtrado is None:
        return "indeterminado"
    if total_corpus == 0:
        return "corpus_vazio"
    if total_filtrado == total_corpus:
        return "ignorado"
    return "aplicado"
