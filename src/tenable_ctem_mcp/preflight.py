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

RESSALVA QUE SE CONFIRMOU: os vereditos da matriz foram medidos atraves do MCP
OFICIAL da Tenable. Este servidor fala direto com a API REST, e o comportamento
DIFERE em quatro pontos, todos reexecutados com par discriminante em
2026-09-03. Nenhum veredito foi herdado por confianca, e foi bom:

  1. Filtro de data em findings nao e ignorado em bloco. Os operadores
     RELATIVOS (`within last`, `older than`, `newer than`) sao ignorados; os de
     COMPARACAO (`<`, `<=`, `>`, `>=`, `=`) sao aplicados.
     Prova: state=FIXED da 50. Com `older than 3650d` da 50 e com
     `within last 1d` da 50 - mutuamente exclusivos, os dois com o corpus
     inteiro. Ja `< 2020-01-01` da 0 e `>= 2020-01-01` da 50: somam 50.

  2. `exists` em finding_vpr_score FUNCIONA, desde que `value` nao venha vazio.
     Prova: `exists` com value=["true"] da 4.462 e `not exists` da 1.024, que
     somam os 5.486 do corpus. O HTTP 400 vem de `value` vazio, e a mensagem da
     API e literalmente "Missing value in filter" - a regra real e sobre o
     valor ausente, nao sobre a propriedade.

  3. `resolvable` em workbenches era "presumido ignorado ate prova". Agora esta
     provado: true e false devolvem os mesmos 121 plugins.

  4. `age` nao e o nome do parametro na API; e `date_range`, e ele FUNCIONA
     (1 -> 17, 30 -> 118, 90 -> 121). `age` era o nome que o MCP oficial dava,
     e como parametro inexistente e descartado em silencio.

Isto NAO invalida a matriz: ela descreve o caminho do MCP oficial, e la os
vereditos dela valem. Aqui vale esta lista.
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


# Propriedades de data em findings.
PROPRIEDADES_DE_DATA_EM_FINDINGS = frozenset({
    "last_updated", "first_observed_at", "last_observed_at",
    "first_found", "last_found", "last_seen", "first_seen",
})

# Operadores RELATIVOS de data: aceitos e silenciosamente ignorados. Estes sao
# a deny-list. Os de comparacao contra data absoluta passam, porque o par
# discriminante prova que sao aplicados.
OPERADORES_DE_DATA_IGNORADOS = frozenset({
    "within last", "older than", "newer than",
})

# Booleanos de workbenches comprovadamente ignorados, mais o nao testado da
# mesma familia - presumido ignorado ate prova em contrario.
PARAMETROS_NEGADOS_EM_WORKBENCHES = frozenset({
    "authenticated", "exploitable", "resolvable",
    # `age` nao existe na API: o nome real e `date_range`, e ele funciona.
    # Parametro inexistente e descartado em silencio, que e o pior caso.
    "age",
})

# Operadores que exigem valor. A API responde 400 "Missing value in filter"
# quando `value` vem vazio - inclusive em operadores de existencia, onde o
# valor e semanticamente inutil mas sintaticamente obrigatorio.
OPERADORES_QUE_EXIGEM_VALOR = frozenset({
    "exists", "not exists", "=", "!=", ">=", ">", "<=", "<", "between",
    "contains", "not contains", "match",
})

PROVAS = {
    "data_em_findings":
        "last_updated 'older than 3650d' devolveu 1840 findings, o corpus inteiro, "
        "igual a 'within last 1d'. Revalidado em 2026-09-03: state=FIXED devolveu "
        "50, e within last 1d, older than 3650d e < 2020-01-01 devolveram os mesmos 50.",
    "booleano_em_workbenches":
        "Na API direta, com severity=critical (121 plugins): authenticated, "
        "exploitable e resolvable devolvem 121 tanto com true quanto com false. "
        "`resolvable` era 'presumido ignorado ate prova'; agora esta provado.",
    "age_nao_e_parametro":
        "`age` nao e o nome do parametro na API - e `date_range`, e ele FUNCIONA: "
        "1 -> 17, 30 -> 118, 80 -> 118, 90 -> 121, 365 -> 121. `age` era o nome do "
        "MCP oficial; como parametro inexistente, e descartado em silencio.",
    "filters_string":
        "filters='tag_count >= 1' como texto livre devolveu os 30 ativos do corpus, "
        "sem erro. O mesmo filtro como array JSON devolveu 9. Confirmado 2026-09-03.",
    "operador_sem_valor":
        "`exists` sem value responde HTTP 400 com a mensagem literal 'Missing "
        "value in filter'. Com value=['true'] funciona: exists da 4.462 e not "
        "exists da 1.024, que somam os 5.486 do corpus. Medido na API direta em "
        "2026-09-03; pelo MCP oficial o mesmo operador era inalcancavel.",
    "data_relativa_em_findings":
        "state=FIXED da 50. Com `older than 3650d` da 50 e com `within last 1d` "
        "tambem 50 - mutuamente exclusivos, os dois com o corpus inteiro. Ja "
        "`< 2020-01-01` da 0 e `>= 2020-01-01` da 50, que somam 50: os "
        "operadores de comparacao SAO aplicados.",
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
        _exigir_valor(prop, op, clausula.get("value"))
    return filters


def _negar_propriedade(prop: str) -> None:
    """Placeholder mantido para simetria; a regra de data e por operador."""
    return None


def _negar_operador(prop: str, op: str) -> None:
    if (prop.lower() in PROPRIEDADES_DE_DATA_EM_FINDINGS
            and op.lower() in OPERADORES_DE_DATA_IGNORADOS):
        raise ErroDenyList(
            f"O operador relativo `{op}` em `{prop}` e aceito pela API e "
            "silenciosamente ignorado: a consulta volta com o corpus inteiro. "
            "Use um operador de comparacao contra data absoluta "
            "(`<`, `>=`), que o par discriminante prova ser aplicado. "
            "Para tempo de correcao continua valendo mttr_collect, porque "
            "`last_fixed` e `time_taken_to_fix` nao existem nesta API.",
            regra="operador_relativo_de_data_e_ignorado",
            prova=PROVAS["data_relativa_em_findings"])


def _exigir_valor(prop: str, op: str, valor) -> None:
    """A API responde 400 'Missing value in filter' quando o valor falta.

    Rejeitar aqui poupa a viagem e, mais importante, evita que o 400 seja lido
    como "a propriedade nao suporta o operador" - foi essa leitura que colocou
    `exists` em finding_vpr_score na deny-list por engano.
    """
    if op.lower() in OPERADORES_QUE_EXIGEM_VALOR and not valor:
        raise ErroDenyList(
            f"O operador `{op}` em `{prop}` exige `value` nao vazio. A API "
            "responde HTTP 400 'Missing value in filter'. Para operadores de "
            "existencia, use value=[\"true\"].",
            regra="operador_exige_valor",
            prova=PROVAS["operador_sem_valor"])


def validar_parametros_workbenches(params: dict[str, Any]) -> dict[str, Any]:
    """Rejeita os booleanos de workbenches que a API aceita e nao aplica."""
    for chave in params:
        if chave.lower() == "age":
            raise ErroDenyList(
                "`age` nao e um parametro desta API - o nome real e `date_range`, "
                "e ele e aplicado. Parametro inexistente e descartado em silencio, "
                "e a consulta volta com o corpus inteiro parecendo filtrada. "
                "Atencao a semantica: `date_range` e recencia da ultima "
                "observacao, nao idade do finding.",
                regra="age_nao_existe_use_date_range",
                prova=PROVAS["age_nao_e_parametro"])
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


# ----------------------------------------------------------------------------
# O pre-voo executavel: roda os pares discriminantes contra a API e devolve a
# tabela pronta. Nao herda veredito de documento nenhum.
# ----------------------------------------------------------------------------

BUSCA_FINDINGS = "/api/v1/t1/inventory/findings/search"
BUSCA_ATIVOS = "/api/v1/t1/inventory/assets/search"
WORKBENCHES = "/workbenches/vulnerabilities"


def _f(prop: str, op: str, *valores: str) -> dict:
    return {"property": prop, "operator": op, "value": list(valores)}


def executar_preflight(severity_workbenches: str = "critical") -> dict[str, Any]:
    """Roda cada verificacao e devolve a tabela PREFLIGHT.

    Tres formas de prova, e a escolha depende do filtro:

    - `par_exclusivo`: duas consultas mutuamente exclusivas cujos totais tem de
      somar o corpus. E a prova mais forte, porque "reduziu" nao basta - um
      filtro pode reduzir por acaso.
    - `booleano`: true e false. Totais iguais significam parametro ignorado.
    - `monotonico`: uma escada de cortes que tem de ser estritamente decrescente.

    Custo: consultas com limit=1, porque so o campo `total` importa.
    """
    from .client import ErroApi, chamar, total_de

    def n_findings(filtros=None):
        corpo = {"filters": filtros} if filtros else {}
        return total_de(chamar("POST", BUSCA_FINDINGS, corpo=corpo, params={"limit": 1}))

    def n_ativos(filtros=None):
        corpo = {"filters": filtros} if filtros else {}
        return total_de(chamar("POST", BUSCA_ATIVOS, corpo=corpo, params={"limit": 1}))

    def n_workbenches(extra=None):
        p = {"filter.0.filter": "severity", "filter.0.quality": "eq",
             "filter.0.value": severity_workbenches, "filter.search_type": "and"}
        p.update(extra or {})
        return len(chamar("GET", WORKBENCHES, params=p).get("vulnerabilities") or [])

    linhas: list[dict[str, Any]] = []

    def registrar(id_, alvo, filtro, tipo, veredito_, detalhe, usar=None):
        linhas.append({"id": id_, "alvo": alvo, "filtro": filtro, "tipo": tipo,
                       "veredito": veredito_, "detalhe": detalhe,
                       "usar": usar})

    # --- pares exclusivos em findings -----------------------------------
    try:
        corpus_f = n_findings()
        fixed = n_findings([_f("state", "=", "FIXED")])
        registrar("state", "findings", "state = FIXED", "corpus_vs_filtrado",
                  veredito(corpus_f, fixed),
                  f"corpus {corpus_f}, filtrado {fixed}", usar=True)

        # data relativa: as duas exclusivas devolvem o corpus => ignorado
        base = [_f("state", "=", "FIXED")]
        velho = n_findings(base + [_f("last_updated", "older than", "3650d")])
        novo = n_findings(base + [_f("last_updated", "within last", "1d")])
        ignorado = (velho == fixed and novo == fixed)
        registrar("last_updated_relativo", "findings",
                  "last_updated com `older than` / `within last`", "par_exclusivo",
                  "ignorado" if ignorado else "aplicado",
                  f"older than 3650d -> {velho}; within last 1d -> {novo}; "
                  f"corpus FIXED {fixed}. Mutuamente exclusivos: nao podem estar "
                  f"os dois certos.", usar=False)

        # data absoluta: as duas exclusivas somam o corpus => aplicado
        antes = n_findings(base + [_f("last_updated", "<", "2020-01-01")])
        depois = n_findings(base + [_f("last_updated", ">=", "2020-01-01")])
        soma_bate = (antes + depois == fixed)
        registrar("last_updated_comparacao", "findings",
                  "last_updated com `<` / `>=` contra data absoluta", "par_exclusivo",
                  "aplicado" if soma_bate else "suspeito",
                  f"< 2020-01-01 -> {antes}; >= 2020-01-01 -> {depois}; "
                  f"somam {antes + depois} contra corpus FIXED {fixed}", usar=soma_bate)

        # exists / not exists em VPR
        tem = n_findings([_f("finding_vpr_score", "exists", "true")])
        nao_tem = n_findings([_f("finding_vpr_score", "not exists", "true")])
        soma_vpr = (tem + nao_tem == corpus_f)
        registrar("finding_vpr_score_exists", "findings",
                  "finding_vpr_score com `exists` / `not exists` (value obrigatorio)",
                  "par_exclusivo", "aplicado" if soma_vpr else "suspeito",
                  f"exists -> {tem}; not exists -> {nao_tem}; somam {tem + nao_tem} "
                  f"contra corpus {corpus_f}", usar=soma_vpr)

        # escada monotonica de VPR
        escada = [(v, n_findings([_f("finding_vpr_score", ">=", v)]))
                  for v in ("0.1", "7", "9")]
        decrescente = all(escada[i][1] > escada[i + 1][1] for i in range(len(escada) - 1))
        registrar("finding_vpr_score_escada", "findings", "finding_vpr_score `>=`",
                  "monotonico", "aplicado" if decrescente else "suspeito",
                  " > ".join(f"{v} -> {n}" for v, n in escada), usar=decrescente)

        cvss = n_findings([_f("finding_cvss3_base_score", ">=", "7")])
        registrar("finding_cvss3_base_score", "findings",
                  "finding_cvss3_base_score `>=`", "corpus_vs_filtrado",
                  veredito(corpus_f, cvss), f"corpus {corpus_f}, >= 7 -> {cvss}",
                  usar=True)
    except ErroApi as e:
        registrar("findings", "findings", "-", "-", "indeterminado",
                  f"falha de coleta: {e}", usar=None)

    # --- ativos ----------------------------------------------------------
    try:
        corpus_a = n_ativos()
        com_tag = n_ativos([_f("tag_count", ">=", "1")])
        sem_tag = n_ativos([_f("tag_count", "=", "0")])
        registrar("tag_count", "assets", "tag_count `>=` / `=`", "par_exclusivo",
                  veredito(corpus_a, com_tag),
                  f">= 1 -> {com_tag}; = 0 -> {sem_tag}; somam {com_tag + sem_tag} "
                  f"contra corpus {corpus_a}"
                  + ("" if com_tag + sem_tag == corpus_a else
                     ". NAO fecham: ha ativo sem a propriedade `tag_count`, e o "
                     "denominador correto continua sendo o corpus"),
                  usar=True)
        device = n_ativos([_f("asset_class", "=", "DEVICE")])
        registrar("asset_class", "assets", "asset_class `=`", "corpus_vs_filtrado",
                  veredito(corpus_a, device), f"corpus {corpus_a}, DEVICE -> {device}",
                  usar=True)
    except ErroApi as e:
        registrar("assets", "assets", "-", "-", "indeterminado",
                  f"falha de coleta: {e}", usar=None)

    # --- workbenches ------------------------------------------------------
    try:
        corpus_w = n_workbenches()
        for param in ("authenticated", "exploitable", "resolvable"):
            t = n_workbenches({param: "true"})
            fl = n_workbenches({param: "false"})
            registrar(param, "workbenches", f"{param} true/false", "booleano",
                      "ignorado" if t == fl else "aplicado",
                      f"true -> {t}; false -> {fl}; corpus {corpus_w}", usar=(t != fl))
        curto = n_workbenches({"date_range": "1"})
        longo = n_workbenches({"date_range": "90"})
        registrar("date_range", "workbenches", "date_range", "monotonico",
                  "aplicado" if curto < longo else "ignorado",
                  f"1 -> {curto}; 90 -> {longo}; corpus {corpus_w}. ATENCAO: e "
                  f"recencia da ultima observacao, NAO idade do finding.",
                  usar=(curto < longo))
        idade = n_workbenches({"age": "1"})
        registrar("age", "workbenches", "age", "corpus_vs_filtrado",
                  "ignorado" if idade == corpus_w else "aplicado",
                  f"age=1 -> {idade}; corpus {corpus_w}. `age` nao e parametro "
                  f"desta API; o nome real e `date_range`.", usar=False)
    except ErroApi as e:
        registrar("workbenches", "workbenches", "-", "-", "indeterminado",
                  f"falha de coleta: {e}", usar=None)

    # --- deny-list: rejeitado ANTES de sair, nunca executado --------------
    negados = []
    for descricao, tentativa in (
        ("`filters` como string", lambda: validar_filters("tag_count >= 1")),
        ("`exists` sem value", lambda: validar_filters(
            [_f("finding_vpr_score", "exists")])),
        ("`older than` em last_updated", lambda: validar_filters(
            [_f("last_updated", "older than", "3650d")])),
        ("`authenticated` em workbenches", lambda: validar_parametros_workbenches(
            {"authenticated": True})),
        ("`age` em workbenches", lambda: validar_parametros_workbenches({"age": 90})),
    ):
        try:
            tentativa()
            negados.append({"caso": descricao, "rejeitado": False,
                            "atencao": "DEVERIA ter sido rejeitado"})
        except ErroDenyList as e:
            negados.append({"caso": descricao, "rejeitado": True,
                            "regra": e.regra, "prova": e.prova})

    return {
        "verificacoes": linhas,
        "deny_list": negados,
        "resumo": {
            "aplicados": sum(1 for l in linhas if l["veredito"] == "aplicado"),
            "ignorados": sum(1 for l in linhas if l["veredito"] == "ignorado"),
            "indeterminados": sum(1 for l in linhas
                                  if l["veredito"] in ("indeterminado", "suspeito")),
        },
        "nota": ("Os vereditos da matriz de confianca foram medidos pelo MCP "
                 "OFICIAL. Esta tabela e medida contra a API REST direta, e "
                 "difere dela em quatro pontos - ver o cabecalho de preflight.py. "
                 "Filtro nao testado e filtro nao confiavel."),
    }
