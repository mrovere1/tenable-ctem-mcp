"""Golden tests dos 17 indicadores, com os numeros medidos em 2026-09-02/03.

Fonte: _docs/execucao-maturidade-sandbox-2026-09-03.md e
       _docs/validacao-dados-coleta-mttr-2026-09-03.md

Divergencia e falha. Nao ajuste o teste para passar - investigue a causa.

Estado no marco M0: aqui esta o contrato do ENVELOPE, por onde todo indicador
passa. Os golden tests por estagio entram nos marcos M1 (scoping, discovery),
M2 (prioritization, validation) e M5 (mobilization).
"""

import json

from tenable_ctem_mcp import Indicador


def test_envelope_tem_exatamente_os_campos_do_contrato():
    d = Indicador.ok("M1", 21.0, n=12,
                     filtro_literal="scan_ids=['abc'], runs colapsados em 5 dias distintos"
                     ).para_dict()
    assert set(d) == {"indicador", "valor", "n", "filtro_literal",
                      "coletado_em_utc", "veredito_preflight"}
    assert d["valor"] == 21.0 and d["n"] == 12
    assert d["veredito_preflight"] == "ok"


def test_lacuna_zera_o_valor_e_nomeia_a_causa():
    """Numero parcial silencioso e proibido: e a regra central do projeto.
    Consulta que falhou vira lacuna declarada, com causa."""
    d = Indicador.lacuna_declarada("M4", causa="cadencia de scan domina as janelas").para_dict()
    assert d["valor"] is None
    assert d["lacuna"] is True
    assert d["causa"] == "cadencia de scan domina as janelas"


def test_carimbo_de_tempo_e_utc_com_z():
    d = Indicador.ok("S1", 30.0).para_dict()
    assert d["coletado_em_utc"].endswith("Z")
    assert len(d["coletado_em_utc"]) == 20


def test_envelope_serializa_em_json():
    """O envelope atravessa o transporte MCP: tem de ser JSON puro."""
    json.dumps(Indicador.ok("D2", 100.0, n=4, filtro_literal="exposure_classes").para_dict())


# --- Paginacao: truncamento silencioso e o defeito que este projeto proibe ---

def test_paginar_nao_para_no_limite_da_pagina(monkeypatch):
    """Regressao de um defeito real, encontrado no M0 contra o sandbox.

    A primeira versao lia o historico de scan com uma chamada de limit=200 e
    devolvia `runs: 200` para um scan que tem 243 runs. Contagem errada com
    aparencia de certa - sem nenhum sinal de que aconteceu. E o mesmo tipo de
    falha que motivou a deny-list.
    """
    from tenable_ctem_mcp import client

    total = 243
    paginas = []

    def falso_chamar(metodo, caminho, corpo=None, params=None, **kwargs):
        offset = (params or {}).get("offset", 0)
        limite = (params or {}).get("limit", 200)
        paginas.append((offset, limite))
        return {"history": [{"i": i} for i in range(offset, min(offset + limite, total))]}

    monkeypatch.setattr(client, "chamar", falso_chamar)
    runs = client.paginar("GET", "/scans/13/history", campo="history")

    assert len(runs) == total, f"truncou em {len(runs)} de {total}"
    assert len(paginas) > 1, "nao paginou: leu uma pagina so"


def test_paginar_para_quando_a_pagina_vem_incompleta(monkeypatch):
    """Nao pede pagina a mais depois da ultima."""
    from tenable_ctem_mcp import client

    chamadas = []

    def falso_chamar(metodo, caminho, corpo=None, params=None, **kwargs):
        chamadas.append(params)
        return {"data": [{"i": 1}, {"i": 2}]}

    monkeypatch.setattr(client, "chamar", falso_chamar)
    itens = client.paginar("GET", "/qualquer", limite_pagina=200)
    assert len(itens) == 2
    assert len(chamadas) == 1


# ===========================================================================
# GOLDEN TESTS - numeros medidos no sandbox em 2026-09-02/03.
# Fonte: _docs/execucao-maturidade-sandbox-2026-09-03.md
#
# Divergencia e falha. NAO ajuste o numero esperado para passar: investigue.
# ===========================================================================

from datetime import datetime, timezone

import pytest

MAPEAMENTO = {"categoria_criticidade": "Criticidade", "categoria_owner": "Owner"}


def _por_id(lista):
    return {i["indicador"]: i for i in lista}


# --- Retrato do tenant ------------------------------------------------------

def test_retrato_do_tenant_bate_com_o_medido(sandbox):
    from tenable_ctem_mcp.indicators.discovery import descobrir_tenant
    r = descobrir_tenant(usar_cache=False)

    assert r["tags"]["quantidade"] == 9
    assert r["ativos"]["total"] == 30
    assert r["ativos"]["por_asset_class"]["DEVICE"] == 8
    assert r["exposure_classes"]["VM"] == 8
    assert r["exposure_classes"]["WAS"] == 2
    assert r["exposure_classes"]["CLOUD"] == 0
    assert r["exposure_classes"]["IDENTITY"] == 0
    assert r["agentes"]["ativos"] == 7


def test_scan_33_tem_12_runs(sandbox):
    """O scan recorrente do sandbox: 12 runs em 9 dias distintos.

    E o caso que sustenta M1 no marco M5 - mediana 1,42 dia sem colapso,
    21 dias com colapso.
    """
    from tenable_ctem_mcp.indicators.discovery import descobrir_tenant
    r = descobrir_tenant(usar_cache=False)
    s33 = next(s for s in r["scans"]["scans"] if s["scan_id"] == 33)
    assert s33["runs"] == 12
    assert s33["runs_completed"] == 12


# --- Scoping: S1, S2, S3, S4 ------------------------------------------------

@pytest.mark.parametrize("indicador,esperado", [
    ("S1", 30.0),    # 9 de 30 ativos com ao menos uma tag
    ("S2", 26.7),    # 8 de 30 com tag de criticidade
    ("S3", 6.7),     # 2 de 30 com tag de owner
])
def test_scoping_bate_com_o_medido(sandbox, indicador, esperado):
    from tenable_ctem_mcp.indicators.scoping import calcular
    r = _por_id(calcular(MAPEAMENTO, indicadores=[indicador]))
    assert r[indicador]["valor"] == esperado
    assert r[indicador]["veredito_preflight"] == "aplicado"


def test_s4_e_informativo_e_nao_pontua(sandbox):
    from tenable_ctem_mcp.indicators.scoping import calcular
    s4 = _por_id(calcular(MAPEAMENTO, indicadores=["S4"]))["S4"]
    assert s4["valor"] is True
    assert s4["contexto"]["informativo"] is True
    assert "curadoria" in s4["contexto"]["lacuna_estrutural"]


def test_s2_sem_mapeamento_vira_lacuna_e_nao_numero(sandbox):
    """O servidor nao adivinha o nome da categoria. Sem mapeamento, lacuna."""
    from tenable_ctem_mcp.indicators.scoping import calcular
    s2 = _por_id(calcular({}, indicadores=["S2"]))["S2"]
    assert s2["valor"] is None and s2["lacuna"] is True
    assert "categoria_criticidade" in s2["causa"]


def test_s3_com_categoria_inexistente_lista_as_que_existem(sandbox):
    from tenable_ctem_mcp.indicators.scoping import calcular
    s3 = _por_id(calcular({"categoria_owner": "Nao Existe"}, indicadores=["S3"]))["S3"]
    assert s3["lacuna"] is True
    assert "Criticidade" in s3["causa"]      # ajuda o consultor a apontar a certa


def test_sugestao_de_categoria_nao_decide_sozinha(sandbox):
    """Sugere, nao escolhe: 'Owner' e 'Team' casam com as pistas de owner."""
    from tenable_ctem_mcp.indicators.discovery import descobrir_tenant
    from tenable_ctem_mcp.indicators.scoping import sugerir_categorias
    s = sugerir_categorias(descobrir_tenant(usar_cache=False)["tags"]["categorias"])
    assert s["criticidade"] == ["Criticidade"]
    assert set(s["owner"]) == {"Owner", "Team"}


# --- Discovery: D1, D2, D3, D4 ---------------------------------------------

# D1 e uma diferenca contra o instante da coleta. Sem relogio fixo nao existe
# teste de regressao: o valor cresce sozinho a cada dia. Este instante e o que
# reproduz os 0,5 dia registrados no documento, sobre o run mais recente da
# fixture (2026-09-03T00:28:58Z).
INSTANTE_DA_MEDICAO = datetime(2026, 9, 3, 12, 28, 58, tzinfo=timezone.utc)


def test_d1_dias_desde_a_ultima_avaliacao(sandbox):
    from tenable_ctem_mcp.indicators.discovery import calcular
    d1 = _por_id(calcular(indicadores=["D1"], agora=INSTANTE_DA_MEDICAO))["D1"]
    assert d1["valor"] == 0.5
    assert d1["contexto"]["run_mais_recente_utc"] == "2026-09-03T00:28:58Z"
    assert d1["contexto"]["invertido"] is True


def test_d2_cobertura_das_superficies_licenciadas(sandbox):
    """Razao percentual, nao contagem absoluta. Um cliente que licencia VM e
    WAS e cobre as duas nao pode ficar em Defined por ter 'apenas 2'."""
    from tenable_ctem_mcp.indicators.discovery import calcular
    d2 = _por_id(calcular(indicadores=["D2"]))["D2"]
    assert d2["valor"] == 100.0
    assert d2["contexto"]["presentes"] == ["VM", "WAS"]
    assert d2["contexto"]["presentes_nao_licenciadas"] == ["WAS"]


def test_d3_cobertura_de_agente_sobre_device(sandbox):
    """Denominador e DEVICE, nao o total de ativos: IDENTITY, ACCOUNT e GROUP
    nao tem software instalado."""
    from tenable_ctem_mcp.indicators.discovery import calcular
    d3 = _por_id(calcular(indicadores=["D3"]))["D3"]
    assert d3["valor"] == 87.5            # 7 agentes ativos sobre 8 DEVICE
    assert d3["n"] == 8


def test_d4_amostra_detectada_por_plugin_local(sandbox):
    from tenable_ctem_mcp.indicators.discovery import calcular
    d4 = _por_id(calcular(indicadores=["D4"]))["D4"]
    assert d4["valor"] == 100.0
    assert d4["contexto"]["plugins_sem_detalhe"] == []


def test_amostra_de_d4_e_alocada_proporcional_a_populacao(sandbox):
    """O erro que esta guarda existe para nao repetir: na primeira execucao real
    a amostra foi 60/40 enquanto a populacao era 65/35. Deu quase certo por
    coincidencia."""
    from tenable_ctem_mcp.indicators.discovery import calcular
    ctx = _por_id(calcular(indicadores=["D4"]))["D4"]["contexto"]
    a, b = ctx["estratos"]["A"], ctx["estratos"]["B"]
    assert a["populacao"] + b["populacao"] == 121     # plugins criticos do tenant
    # a fatia da amostra acompanha a fatia da populacao, dentro de 1 plugin
    assert abs(a["amostra"] / (a["amostra"] + b["amostra"])
               - a["share_por_plugin"]) < 1 / (a["amostra"] + b["amostra"])


def test_censo_tem_121_plugins_criticos(sandbox):
    from tenable_ctem_mcp.plugins import plugin_census
    assert plugin_census("critical")["plugins_distintos"] == 121


def test_detalhe_de_plugin_devolve_exatamente_cinco_campos(sandbox):
    """A economia de token do projeto depende disto. Campo extra aqui e
    regressao, nao melhoria."""
    from tenable_ctem_mcp.plugins import (amostrar_estratificado, plugin_census,
                                          plugin_details_batch)
    censo = plugin_census("critical")
    pid = amostrar_estratificado(censo["plugins"])["amostra"][0]["plugin_id"]
    lote = plugin_details_batch([pid])
    assert lote["lacunas"] == []       # senao o teste esconde buraco na fixture
    d = lote["plugins"][0]
    assert set(d) == {"plugin_id", "scan_type", "published", "exploit_available",
                      "exploitability", "cisa_known_exploited"}
    assert d["scan_type"] in ("local", "remote")


def test_plugin_sem_detalhe_vira_lacuna_declarada_e_nao_some(sandbox):
    """Resultado parcial DECLARADO e legitimo; parcial silencioso nao e."""
    from tenable_ctem_mcp.plugins import plugin_details_batch
    lote = plugin_details_batch([999999999])
    assert lote["plugins"] == []
    assert lote["lacunas"][0]["plugin_id"] == 999999999
    assert lote["n_pedidos"] == 1 and lote["n_resolvidos"] == 0


def test_wilson_reproduz_o_ic_publicado(sandbox):
    """9 de 20 no KEV deu IC 95% de 25,8% a 65,8% no documento."""
    from tenable_ctem_mcp.plugins import wilson
    lo, hi = wilson(9, 20)
    assert round(lo * 100, 1) == 25.8
    assert round(hi * 100, 1) == 65.8


# --- Prioritization: P1, P2, P3 --------------------------------------------

def test_corpus_de_findings_bate_com_o_medido(sandbox):
    """5.486 findings: 5.425 ACTIVE, 11 RESURFACED, 50 FIXED."""
    from tenable_ctem_mcp.indicators.prioritization import _contar, _estado
    assert _contar(None) == 5486
    assert _contar([_estado("ACTIVE")]) == 5425
    assert _contar([_estado("RESURFACED")]) == 11
    assert _contar([_estado("FIXED")]) == 50


def test_p1_todo_backlog_critico_esta_em_ativo_com_criticidade(sandbox):
    """O achado da execucao de aceitacao: 100% do backlog VPR >= 9 esta em ativo
    com criticidade, contra 26,7% de cobertura no inventario. O cliente tagueou
    os ativos certos - e isso e mais maduro que o inverso."""
    from tenable_ctem_mcp.indicators.prioritization import calcular
    p1 = _por_id(calcular(MAPEAMENTO, indicadores=["P1"]))["P1"]
    assert p1["valor"] == 100.0
    ctx = p1["contexto"]
    # a soma por valor de tag nao pode passar do total: um ativo pode ter duas
    assert ctx["em_ativo_com_criticidade"] == ctx["backlog_vpr_maior_igual_9"]


def test_p2_cobertura_de_vpr_no_backlog_ativo(sandbox):
    """81,6% - o denominador e ACTIVE, nao o corpus inteiro.
    Com o corpus (5.486) daria 81,3%, e com VPR sobre todos os estados, 82,2%."""
    from tenable_ctem_mcp.indicators.prioritization import calcular
    p2 = _por_id(calcular(MAPEAMENTO, indicadores=["P2"]))["P2"]
    assert p2["valor"] == 81.6
    assert p2["n"] == 5425


def test_p3_sem_criterio_declarado_e_lacuna_e_nao_numero(sandbox):
    """"O cliente nao sabe qual criterio usa" e o proprio estagio Ad Hoc.
    Cabe a skill classificar; o servidor nao inventa um corte."""
    from tenable_ctem_mcp.indicators.prioritization import calcular
    p3 = _por_id(calcular(MAPEAMENTO, indicadores=["P3"]))["P3"]
    assert p3["valor"] is None and p3["lacuna"] is True


def test_p3_oportunidade_e_filas_com_criterio_cvss(sandbox):
    """Trocar CVSS >= 7 por VPR >= 7 encolhe a fila em ~63%."""
    from tenable_ctem_mcp.indicators.prioritization import calcular
    p3 = _por_id(calcular(MAPEAMENTO, indicadores=["P3"],
                          corte_priorizacao_cliente={"metrica": "cvss3", "valor": 7.0}))["P3"]
    q = p3["contexto"]["filas"]
    assert q["cvss3_maior_igual_corte"] == 3377
    assert q["cobertura_de_vpr_na_fatia_alta_pct"] == 98.1   # 3.314 de 3.377
    assert 0.62 <= p3["valor"] <= 0.64


def test_filas_de_vpr_sao_monotonicas(sandbox):
    """0,1 -> 7,0 -> 9,0 tem de ser decrescente. E o que prova que o filtro de
    VPR e aplicado, e nao ignorado."""
    from tenable_ctem_mcp.indicators.prioritization import _contar, _vpr
    n01 = _contar([_vpr(">=", "0.1")])
    n7 = _contar([_vpr(">=", "7")])
    n9 = _contar([_vpr(">=", "9")])
    assert n01 == 4462
    assert n01 > n7 > n9 > 0


# --- Validation: V1, V2, V3, V4 --------------------------------------------

def test_v3_taxa_de_reincidencia(sandbox):
    """18,0% = 11 RESURFACED sobre 11 + 50 FIXED. Dado direto, nao calculo."""
    from tenable_ctem_mcp.indicators.validation import calcular
    v3 = _por_id(calcular(indicadores=["V3"]))["V3"]
    assert v3["valor"] == 18.0
    assert v3["n"] == 61
    assert v3["contexto"]["invertido"] is True


def test_v4_device_com_software_fora_de_suporte(sandbox):
    """87,5% = 7 de 8 DEVICE. Com o total de ativos daria 23% - dois estagios
    de distancia. O denominador e DEVICE."""
    from tenable_ctem_mcp.indicators.validation import calcular
    v4 = _por_id(calcular(indicadores=["V4"]))["V4"]
    assert v4["valor"] == 87.5
    assert v4["n"] == 8
    assert v4["contexto"]["devices_com_eol"] == 7


def test_v1_e_informativo_e_declara_a_base_dos_pesos(sandbox):
    """Taxa ponderada sem base declarada nao e verificavel: a mesma amostra da
    59,3% por deteccao e 54,6% por plugin com n=20."""
    from tenable_ctem_mcp.indicators.validation import calcular
    for base, esperado in (("por_deteccao", 59.3), ("por_plugin", 54.6)):
        v1 = _por_id(calcular(indicadores=["V1"], n_amostra=20, ponderar=base))["V1"]
        assert v1["contexto"]["informativo"] is True
        assert v1["contexto"]["base_dos_pesos"] == base
        assert v1["valor"] == esperado


def test_v2_mediana_de_dias_no_kev_com_relogio_congelado(sandbox):
    """V2 e uma diferenca contra o instante da coleta e cresce sozinha a cada
    dia. Sem relogio fixo nao existe regressao."""
    from tenable_ctem_mcp.indicators.validation import calcular
    v2 = _por_id(calcular(indicadores=["V2"], agora=INSTANTE_DA_MEDICAO))["V2"]
    assert v2["valor"] == 1357.0
    assert v2["contexto"]["invertido"] is True
    assert v2["contexto"]["plugins_com_kev"] == 12
    assert "BOD 26-04" in v2["contexto"]["origem_do_limiar"]


def test_v1_e_v2_saem_da_mesma_amostra_que_d4(sandbox):
    """Senao o relatorio descreve tres amostras diferentes com um unico tamanho
    declarado, e o IC publicado nao vale para nenhuma delas."""
    from tenable_ctem_mcp.indicators.discovery import calcular as disc
    from tenable_ctem_mcp.indicators.validation import calcular as val
    d4 = _por_id(disc(indicadores=["D4"]))["D4"]
    v1 = _por_id(val(indicadores=["V1"]))["V1"]
    assert d4["n"] == v1["n"]
    assert d4["contexto"]["estratos"]["A"]["amostra"] == \
        v1["contexto"]["por_estrato"]["A"]["n"]


def test_divergencia_de_v1_tem_causa_identificada(sandbox):
    """O documento publica V1 = 59,6% com a amostra dele (A 11/12, B 1/8).

    Esse numero NAO se reconstroi com os 65/35 de populacao que o proprio
    documento afirma - da 64,0%. Reconstroi exatamente com share_A = 0,595
    (a fatia por plugin medida hoje) e ponderacao POR PLUGIN, nao por deteccao.

    Duas conclusoes, e as duas importam:
      1. a base de pesos usada la foi `por_plugin`, nao o `por_deteccao` que a
         config da skill traz como default;
      2. a fatia de populacao narrada no documento nao e a que sustenta o
         numero publicado nele.

    Por isso V1 e V2 NAO tem golden test contra o valor do documento: eles
    dependem de quais plugins foram sorteados, e a amostra de la nao e
    recuperavel. O que se testa e o metodo, sobre a fixture, com semente fixa.
    """
    def reconstruir(share_a):
        return round(100 * ((11 / 12) * share_a + (1 / 8) * (1 - share_a)), 1)

    assert reconstruir(0.65) == 64.0            # o que o documento narra
    assert reconstruir(0.5950413223140496) == 59.6   # o que o documento publica


def test_amostra_e_reproduzivel_entre_execucoes(sandbox):
    """Semente fixa. Sem reprodutibilidade o mesmo tenant pontua diferente a
    cada rodada, e golden test nao existe."""
    from tenable_ctem_mcp.client import CACHE
    from tenable_ctem_mcp.plugins import amostra_com_detalhes
    a = [p["plugin_id"] for p in amostra_com_detalhes()["amostra"]["amostra"]]
    CACHE.limpar()
    b = [p["plugin_id"] for p in amostra_com_detalhes()["amostra"]["amostra"]]
    assert a == b and len(a) == 30
