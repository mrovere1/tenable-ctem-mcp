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


# --- Caso novo 2 de 2026-09-03: `exists` em finding_vpr_score -------------

def test_exists_em_finding_vpr_score_e_rejeitado():
    """O operador aparece na lista de operadores da propriedade e responde 400."""
    with pytest.raises(ErroDenyList) as exc:
        validar_filters([{"property": "finding_vpr_score", "operator": "exists"}])
    assert exc.value.regra == "exists_nao_funciona_em_finding_vpr_score"


def test_vpr_maior_ou_igual_e_aceito():
    """O caminho valido: >= 0.1, aplicado e monotonico (4.462 / 1.254 / 586)."""
    f = [{"property": "finding_vpr_score", "operator": ">=", "value": ["0.1"]}]
    assert validar_filters(f) == f


# --- Filtros de data em findings ------------------------------------------

@pytest.mark.parametrize("prop", ["last_updated", "first_observed_at", "last_found"])
@pytest.mark.parametrize("op", ["<", ">=", "older than", "within last", "newer than"])
def test_filtro_de_data_em_findings_e_rejeitado_em_todo_operador(prop, op):
    """Aceito pela API e silenciosamente ignorado, em TODO operador e formato."""
    with pytest.raises(ErroDenyList) as exc:
        validar_filters([{"property": prop, "operator": op, "value": ["2020-01-01"]}])
    assert exc.value.regra == "sem_filtro_de_data_em_findings"


# --- Booleanos de workbenches ---------------------------------------------

@pytest.mark.parametrize("param", ["authenticated", "exploitable", "resolvable"])
def test_booleano_de_workbenches_e_rejeitado(param):
    """true e false devolvem o mesmo conjunto: o parametro nao e aplicado.
    `resolvable` nao foi testado, e e presumido ignorado ate prova - esta na
    mesma familia dos dois comprovados."""
    with pytest.raises(ErroDenyList):
        validar_parametros_workbenches({param: True})


def test_severity_em_workbenches_passa():
    """severity e age sao os dois parametros comprovadamente aplicados."""
    assert validar_parametros_workbenches({"severity": "critical", "age": 90})


# --- O teste discriminante -------------------------------------------------

def test_veredito_igual_ao_corpus_e_ignorado():
    """Se o total filtrado for identico ao corpus, o filtro esta ignorado.
    Numero nao se publica: vira lacuna."""
    assert veredito(30, 30) == "ignorado"


def test_veredito_menor_que_o_corpus_e_aplicado():
    assert veredito(30, 9) == "aplicado"


def test_veredito_sem_total_e_indeterminado():
    assert veredito(None, 9) == "indeterminado"
