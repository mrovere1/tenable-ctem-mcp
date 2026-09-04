"""Deny-list de filtros. Rejeicao acontece ANTES de a requisicao sair.

Os dois casos de 2026-09-03 sao o criterio de pronto do marco M3 e estao aqui
desde o M0, porque o modulo existe desde o M0.
"""

import pytest

from tenable_ctem_mcp.preflight import (
    ErroDenyList,
    validar_filters,
    validar_parametros_workbenches,
    veredito,
)


# --- Caso novo 1 de 2026-09-03: `filters` em texto livre -------------------

def test_filters_como_string_e_rejeitado():
    """A armadilha mais facil de cometer do conjunto.

    `filters="tag_count >= 1"` devolveu os 30 ativos do corpus, sem erro; o
    mesmo filtro como array JSON devolveu 9. A sintaxe em texto livre e
    exatamente a que list_inventory_properties sugere.
    """
    with pytest.raises(ErroDenyList) as exc:
        validar_filters("tag_count >= 1")
    assert exc.value.regra == "filters_precisa_ser_array_json"
    assert "30" in exc.value.prova  # a prova medida vai junto do erro


@pytest.mark.parametrize("entrada", [{"property": "tag_count"}, 42, ["texto solto"]])
def test_filters_que_nao_e_array_de_objetos_e_rejeitado(entrada):
    with pytest.raises(ErroDenyList):
        validar_filters(entrada)


# --- Caso novo 2 de 2026-09-03, CORRIGIDO contra a API direta -------------
#
# A matriz registrou "o operador `exists` responde 400 em finding_vpr_score" e
# concluiu que a propriedade nao suporta o operador. Reexecutando o par
# discriminante contra a API REST, a causa e outra: o 400 vem de `value` VAZIO,
# e a mensagem da API e literalmente "Missing value in filter".
# Com value=["true"], `exists` da 4.462 e `not exists` da 1.024 - que somam os
# 5.486 do corpus. O operador funciona.
#
# A regra certa e sobre o valor ausente, nao sobre a propriedade.

def test_operador_sem_valor_e_rejeitado():
    with pytest.raises(ErroDenyList) as exc:
        validar_filters([{"property": "finding_vpr_score", "operator": "exists"}])
    assert exc.value.regra == "operador_exige_valor"
    assert "Missing value in filter" in exc.value.prova


def test_exists_com_valor_e_aceito():
    """Corrige a matriz: pela API direta o operador funciona."""
    f = [{"property": "finding_vpr_score", "operator": "exists", "value": ["true"]}]
    assert validar_filters(f) == f


def test_vpr_maior_ou_igual_e_aceito():
    """O caminho valido: >= 0.1, aplicado e monotonico (4.462 / 1.254 / 586)."""
    f = [{"property": "finding_vpr_score", "operator": ">=", "value": ["0.1"]}]
    assert validar_filters(f) == f


# --- Filtros de data em findings ------------------------------------------

@pytest.mark.parametrize("prop", ["last_updated", "first_observed_at", "last_found"])
@pytest.mark.parametrize("op", ["older than", "within last", "newer than"])
def test_operador_relativo_de_data_e_rejeitado(prop, op):
    """Aceito e silenciosamente ignorado.

    Prova: state=FIXED da 50; com `older than 3650d` da 50 e com
    `within last 1d` tambem 50 - mutuamente exclusivos, os dois devolvendo o
    corpus inteiro.
    """
    with pytest.raises(ErroDenyList) as exc:
        validar_filters([{"property": prop, "operator": op, "value": ["3650d"]}])
    assert exc.value.regra == "operador_relativo_de_data_e_ignorado"


@pytest.mark.parametrize("prop", ["last_updated", "first_observed_at"])
@pytest.mark.parametrize("op", ["<", ">="])
def test_comparacao_contra_data_absoluta_e_aceita(prop, op):
    """CORRIGE a matriz, que negava filtro de data em bloco.

    `last_updated < 2020-01-01` da 0 e `>= 2020-01-01` da 50, e os dois somam
    os 50 findings FIXED do corpus. E a definicao de filtro aplicado.
    """
    f = [{"property": prop, "operator": op, "value": ["2020-01-01"]}]
    assert validar_filters(f) == f


# --- Booleanos de workbenches ---------------------------------------------

@pytest.mark.parametrize("param", ["authenticated", "exploitable", "resolvable"])
def test_booleano_de_workbenches_e_rejeitado(param):
    """true e false devolvem o mesmo conjunto: o parametro nao e aplicado.

    Com severity=critical (121 plugins), os tres devolvem 121 nos dois valores.
    `resolvable` era "presumido ignorado ate prova"; agora esta provado.
    """
    with pytest.raises(ErroDenyList):
        validar_parametros_workbenches({param: True})


def test_age_e_rejeitado_porque_nao_existe_na_api():
    """CORRIGE a matriz. `age` era o nome do MCP oficial; na API o parametro e
    `date_range`. Parametro inexistente e descartado em silencio - o pior caso,
    porque parece filtrado e devolve o corpus."""
    with pytest.raises(ErroDenyList) as exc:
        validar_parametros_workbenches({"severity": "critical", "age": 90})
    assert "date_range" in exc.value.prova


def test_date_range_e_severity_passam():
    """Os dois parametros comprovadamente aplicados: severity e date_range
    (1 -> 17, 30 -> 118, 90 -> 121)."""
    assert validar_parametros_workbenches({"severity": "critical", "date_range": 90})


# --- O teste discriminante -------------------------------------------------

def test_veredito_igual_ao_corpus_e_ignorado():
    """Se o total filtrado for identico ao corpus, o filtro esta ignorado.
    Numero nao se publica: vira lacuna."""
    assert veredito(30, 30) == "ignorado"


def test_veredito_menor_que_o_corpus_e_aplicado():
    assert veredito(30, 9) == "aplicado"


def test_veredito_sem_total_e_indeterminado():
    assert veredito(None, 9) == "indeterminado"


# ===========================================================================
# O pre-voo executavel (M3): roda os pares discriminantes contra a API.
# Nenhum veredito e herdado - e isso que fez aparecerem as quatro correcoes
# a matriz de confianca.
# ===========================================================================

def _linha(tabela, id_):
    return next(l for l in tabela["verificacoes"] if l["id"] == id_)


def test_preflight_produz_a_tabela_completa(sandbox):
    from tenable_ctem_mcp.preflight import executar_preflight
    t = executar_preflight()
    assert t["resumo"]["indeterminados"] == 0
    assert t["resumo"]["aplicados"] >= 8
    assert t["resumo"]["ignorados"] >= 5


def test_preflight_pega_o_operador_relativo_de_data(sandbox):
    """As duas consultas sao mutuamente exclusivas e as duas devolvem o corpus.
    Nao podem estar as duas certas - e a prova que expos o problema."""
    from tenable_ctem_mcp.preflight import executar_preflight
    l = _linha(executar_preflight(), "last_updated_relativo")
    assert l["veredito"] == "ignorado"
    assert l["usar"] is False


def test_preflight_aprova_comparacao_contra_data_absoluta(sandbox):
    """CORRECAO 1 a matriz: `< 2020-01-01` da 0 e `>= 2020-01-01` da 50, e os
    dois somam o corpus FIXED. Filtro de data nao e ignorado em bloco."""
    from tenable_ctem_mcp.preflight import executar_preflight
    l = _linha(executar_preflight(), "last_updated_comparacao")
    assert l["veredito"] == "aplicado"
    assert l["usar"] is True


def test_preflight_aprova_exists_em_vpr(sandbox):
    """CORRECAO 2: exists 4.462 + not exists 1.024 = 5.486, o corpus."""
    from tenable_ctem_mcp.preflight import executar_preflight
    l = _linha(executar_preflight(), "finding_vpr_score_exists")
    assert l["veredito"] == "aplicado"
    assert "5486" in l["detalhe"]


@pytest.mark.parametrize("param", ["authenticated", "exploitable", "resolvable"])
def test_preflight_confirma_os_booleanos_ignorados(sandbox, param):
    """CORRECAO 3: `resolvable` era presumido; agora esta provado."""
    from tenable_ctem_mcp.preflight import executar_preflight
    l = _linha(executar_preflight(), param)
    assert l["veredito"] == "ignorado"


def test_preflight_separa_age_de_date_range(sandbox):
    """CORRECAO 4: `age` nao existe na API e e descartado em silencio;
    `date_range` existe e e aplicado."""
    from tenable_ctem_mcp.preflight import executar_preflight
    t = executar_preflight()
    assert _linha(t, "age")["veredito"] == "ignorado"
    assert _linha(t, "date_range")["veredito"] == "aplicado"


def test_preflight_flagra_que_o_par_de_tag_count_nao_fecha(sandbox):
    """tag_count >= 1 (9) + = 0 (20) somam 29, nao os 30 do corpus: ha um ativo
    sem a propriedade. O detalhe tem de dizer isso, senao o leitor conclui que
    o denominador e 29."""
    from tenable_ctem_mcp.preflight import executar_preflight
    l = _linha(executar_preflight(), "tag_count")
    assert l["veredito"] == "aplicado"
    assert "NAO fecham" in l["detalhe"]


def test_preflight_prova_que_a_deny_list_rejeita_antes_de_sair(sandbox):
    from tenable_ctem_mcp.preflight import executar_preflight
    for d in executar_preflight()["deny_list"]:
        assert d["rejeitado"] is True, d
        assert d["prova"]
