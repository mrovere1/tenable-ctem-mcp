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


def test_d4_detectada_por_plugin_local(sandbox):
    """Censo por default: 121 de 121, sem intervalo de confianca."""
    from tenable_ctem_mcp.indicators.discovery import calcular
    d4 = _por_id(calcular(indicadores=["D4"]))["D4"]
    assert d4["valor"] == 100.0
    assert d4["contexto"]["plugins_sem_detalhe"] == []
    assert d4["contexto"]["modo"] == "censo"
    assert d4["n"] == 121
    assert "CENSO" in d4["filtro_literal"]


def test_amostra_de_d4_e_alocada_proporcional_a_populacao(sandbox):
    """Vale quando a populacao passa do limite de censo e a amostra volta.

    O erro que esta guarda existe para nao repetir: na primeira execucao real a
    amostra foi 60/40 enquanto a populacao era 65/35. Deu quase certo por
    coincidencia."""
    from tenable_ctem_mcp.indicators.discovery import calcular
    ctx = _por_id(calcular(indicadores=["D4"],
                           modo_plugins="amostra"))["D4"]["contexto"]
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
        v1 = _por_id(calcular(indicadores=["V1"], n_amostra=20, ponderar=base,
                              modo_plugins="amostra"))["V1"]
        assert v1["contexto"]["informativo"] is True
        assert v1["contexto"]["base_dos_pesos"] == base
        assert v1["valor"] == esperado


def test_v2_mediana_de_dias_no_kev_com_relogio_congelado(sandbox):
    """V2 e uma diferenca contra o instante da coleta e cresce sozinha a cada
    dia. Sem relogio fixo nao existe regressao."""
    from tenable_ctem_mcp.indicators.validation import calcular
    v2 = _por_id(calcular(indicadores=["V2"], agora=INSTANTE_DA_MEDICAO,
                          modo_plugins="amostra"))["V2"]
    assert v2["valor"] == 1357.0
    assert v2["contexto"]["invertido"] is True
    assert v2["contexto"]["plugins_com_kev"] == 12
    assert "BOD 26-04" in v2["contexto"]["origem_do_limiar"]


def test_v2_no_censo_nao_tem_intervalo_de_confianca(sandbox):
    """Censo nao infere: nao ha o que estimar, entao nao ha IC."""
    from tenable_ctem_mcp.indicators.validation import calcular
    v2 = _por_id(calcular(indicadores=["V2"], agora=INSTANTE_DA_MEDICAO))["V2"]
    assert v2["contexto"]["modo"] == "censo"
    assert v2["contexto"]["ic95_proporcao_com_kev"] is None
    assert v2["contexto"]["plugins_na_amostra"] == 121


def test_v1_e_v2_saem_do_mesmo_conjunto_que_d4(sandbox):
    """Senao o relatorio descreve tres conjuntos diferentes com um unico tamanho
    declarado, e o IC publicado nao vale para nenhum deles."""
    from tenable_ctem_mcp.indicators.discovery import calcular as disc
    from tenable_ctem_mcp.indicators.validation import calcular as val
    for modo in ("censo", "amostra"):
        d4 = _por_id(disc(indicadores=["D4"], modo_plugins=modo))["D4"]
        v1 = _por_id(val(indicadores=["V1"], modo_plugins=modo))["V1"]
        assert d4["n"] == v1["n"]
        assert d4["contexto"]["modo"] == v1["contexto"]["modo"] == modo


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
    a = [p["plugin_id"] for p in
         amostra_com_detalhes(modo="amostra")["amostra"]["amostra"]]
    CACHE.limpar()
    b = [p["plugin_id"] for p in
         amostra_com_detalhes(modo="amostra")["amostra"]["amostra"]]
    assert a == b and len(a) == 30


# --- Censo: o modo default desde que plugin_details_batch existe ------------

def test_censo_e_o_default_quando_cabe_no_limite(sandbox):
    """A amostragem existia porque plugins_search_plugins nao aceita lista de
    IDs. plugin_details_batch aceita, entao a restricao caiu."""
    from tenable_ctem_mcp.plugins import amostra_com_detalhes
    c = amostra_com_detalhes()["amostra"]
    assert c["modo"] == "censo"
    assert c["n"] == c["populacao"] == 121
    assert c["semente"] is None          # nao ha sorteio


def test_censo_volta_a_amostra_acima_do_limite(sandbox):
    """Um tenant grande pode ter milhares de plugins criticos; a 528 ms cada,
    mil plugins sao nove minutos."""
    from tenable_ctem_mcp.plugins import amostra_com_detalhes
    c = amostra_com_detalhes(limite_censo=50)["amostra"]
    assert c["modo"] == "amostra"
    assert c["n"] == 30 and c["populacao"] == 121


def test_censo_nao_pondera_nem_estima(sandbox):
    """No censo a taxa e a contagem. `base_dos_pesos` vem `nao_se_aplica` em vez
    de um rotulo que sugira escolha de metodo onde nao houve."""
    from tenable_ctem_mcp.plugins import amostra_com_detalhes, taxa
    pac = amostra_com_detalhes()
    r = taxa(pac["amostra"], pac["detalhes"],
             lambda d: bool(d.get("exploit_available")))
    assert r["modo"] == "censo"
    assert r["base_dos_pesos"] == "nao_se_aplica"
    assert r["ic95_amostra_inteira"] is None
    assert r["n"] == 121


def test_censo_elimina_a_ambiguidade_da_base_de_pesos(sandbox):
    """Na amostra, por_deteccao e por_plugin dao 59,3% e 54,6% - cinco pontos de
    diferenca so pela escolha de metodo. No censo os dois dao o mesmo numero,
    porque nao ha ponderacao nenhuma."""
    from tenable_ctem_mcp.indicators.validation import calcular
    valores = {b: _por_id(calcular(indicadores=["V1"], ponderar=b))["V1"]["valor"]
               for b in ("por_deteccao", "por_plugin")}
    assert valores["por_deteccao"] == valores["por_plugin"] == 61.2


# --- Mobilization: M1, M2, M3, M4 ------------------------------------------

SCANS_RECORRENTES = {"scans_recorrentes": [33]}


def test_m1_usa_dias_distintos_e_nao_runs_crus(sandbox):
    """O CRITERIO DE PRONTO DO M5.

    A formula anterior era "mediana do intervalo entre runs completed
    consecutivos", e estava errada: um scan relancado minutos depois e a MESMA
    avaliacao. Os 12 runs do scan recorrente caem em 9 dias distintos; a mediana
    crua da 1,42 dia - numero sem sentido para um tenant que avaliou em 9 dias
    ao longo de 12 meses. Colapsada, 21 dias: Standardized em vez de Optimized.
    """
    from tenable_ctem_mcp.indicators.mobilization import calcular
    m1 = _por_id(calcular(SCANS_RECORRENTES, indicadores=["M1"]))["M1"]
    assert m1["valor"] == 21.0
    assert m1["valor"] != 1.42
    assert m1["contexto"]["intervalos_dias"] == [140, 40, 2, 89, 1, 1, 85, 1]
    assert m1["contexto"]["dias_distintos"] == 9
    # o contraste vai junto, sempre, para o leitor ver o que o colapso muda
    assert m1["contexto"]["mediana_sem_colapso_dias"]["33"] == 1.42


def test_m2_maior_lacuna_nao_muda_com_o_colapso(sandbox):
    from tenable_ctem_mcp.cadence import scan_cadence
    from tenable_ctem_mcp.indicators.mobilization import calcular
    m2 = _por_id(calcular(SCANS_RECORRENTES, indicadores=["M2"]))["M2"]
    assert m2["valor"] == 140.0
    assert scan_cadence([33], colapsar_runs_do_mesmo_dia=False)["maximo_dias"] == 140


def test_scan_cadence_sem_colapso_agrega_intervalos_crus(sandbox):
    """Achado da auditoria de 2026-09-04: com `colapsar_runs_do_mesmo_dia=False`
    os intervalos crus eram calculados por scan mas a mediana GERAL continuava
    somando os colapsados - os dois modos devolviam 21,0. O modo diagnostico
    existe justamente para MOSTRAR o contraste 1,42 vs 21; devolvendo o mesmo
    numero, ele escondia o que deveria expor."""
    from tenable_ctem_mcp.cadence import scan_cadence
    com = scan_cadence([33], colapsar_runs_do_mesmo_dia=True)
    sem = scan_cadence([33], colapsar_runs_do_mesmo_dia=False)
    assert com["mediana_dias"] == 21.0
    assert sem["mediana_dias"] == 1.42
    assert sem["mediana_dias"] != com["mediana_dias"]
    # a lista crua vai junto, para o numero ser auditavel e nao so afirmado
    assert len(sem["scans"]["33"]["intervalos_crus_dias"]) == 11
    assert sem["aviso"] and "COLAPSO DESLIGADO" in sem["aviso"]


def test_m1_sem_scans_declarados_e_lacuna(sandbox):
    """O servidor nao escolhe quais scans representam a cadencia, e a razao esta
    medida: com todos os scans com historico a mediana cai de 21 para 1,0 e o
    maximo de 140 para 89, porque um deles roda quase todo dia."""
    from tenable_ctem_mcp.indicators.mobilization import calcular
    m1 = _por_id(calcular({}, indicadores=["M1"]))["M1"]
    assert m1["lacuna"] is True and m1["valor"] is None
    assert "scans_recorrentes" in m1["causa"]
    assert "33" in m1["causa"]          # lista os scans com historico


def test_m3_rotula_published_como_proxy_declarado(sandbox):
    """`Published` e a data do PLUGIN DE DETECCAO, nao a do patch."""
    from tenable_ctem_mcp.indicators.mobilization import calcular
    m3 = _por_id(calcular(SCANS_RECORRENTES, indicadores=["M3"],
                          agora=INSTANTE_DA_MEDICAO, modo_plugins="amostra"))["M3"]
    assert m3["valor"] == 1047.0
    assert m3["contexto"]["invertido"] is True
    assert "proxy" in m3["contexto"]["proxy_declarado"]
    assert "patch_publication_date" in m3["contexto"]["proxy_declarado"]


def test_m4_vira_lacuna_quando_a_guarda_de_cadencia_dispara(sandbox, monkeypatch):
    """No sandbox M4 e lacuna POR MERITO: as 7 datas que formam as janelas sao
    7 de 7 datas de execucao de scan. Com cadencia dominante, M4 mediria a mesma
    coisa que M1 e M2 - contaria cadencia duas vezes."""
    import json
    from pathlib import Path

    from tenable_ctem_mcp import mttr
    from tenable_ctem_mcp.indicators import mobilization

    d = json.loads((Path(__file__).parent / "fixtures"
                    / "mttr_export_2026-09-03.json").read_text(encoding="utf-8"))
    linhas = [dict(zip(d["campos"], l)) for l in d["linhas"]]
    resumo = mttr.resumir(linhas, d["filtros_pedidos"], "uuid-fixture", d["status"], 2)
    resumo["status"] = "concluido"
    monkeypatch.setattr(mobilization, "mttr_collect", lambda **k: resumo)

    m4 = _por_id(mobilization.calcular(SCANS_RECORRENTES, indicadores=["M4"]))["M4"]
    assert m4["lacuna"] is True and m4["valor"] is None
    assert "cadencia de avaliacao" in m4["causa"]
    g = m4["contexto"]["guarda_de_cadencia"]
    assert g["pct_em_lote"] == 93.5
    assert g["todas_as_datas_sao_de_scan"] is True
    # os p50 continuam visiveis mesmo na lacuna: a skill precisa deles no texto
    assert m4["contexto"]["p50_critical"] == 42.94
    assert m4["contexto"]["p50_high"] == 85.51


def test_m4_pendente_e_lacuna_recuperavel_com_uuid(sandbox, monkeypatch):
    """Export em andamento nao e falha: e lacuna recuperavel, e a causa carrega
    o export_uuid para a proxima chamada retomar."""
    from tenable_ctem_mcp.indicators import mobilization

    monkeypatch.setattr(mobilization, "mttr_collect",
                        lambda **k: {"status": "pendente", "export_uuid": "u-123",
                                     "status_do_job": "PROCESSING"})
    m4 = _por_id(mobilization.calcular(SCANS_RECORRENTES, indicadores=["M4"]))["M4"]
    assert m4["lacuna"] is True
    assert "u-123" in m4["causa"] and "409" in m4["causa"]


def test_m4_declara_que_e_o_menor_dos_dois_estagios(sandbox, monkeypatch):
    """Mobilizacao madura fecha as duas severidades, nao compensa uma com a
    outra. O estagio e da skill; o servidor entrega os dois p50 e os cortes."""
    from tenable_ctem_mcp.indicators import mobilization

    resumo = {
        "status": "concluido", "export_uuid": "u",
        "cadencia_de_scan": {"janelas": [{"ativo": "a", "first_found": "2026-01-05",
                                          "last_fixed": "2026-01-09", "findings": 1}],
                             "findings_com_mttr": 1},
        "mttr_por_severidade": {"critical": {"mttr_dias_p50": 12.0},
                                "high": {"mttr_dias_p50": 40.0}},
        "metodo_percentil": "interpolado", "estados_incluidos_no_mttr": ["FIXED"],
        "severidade_modificada_diferente_de_none": 0,
    }
    monkeypatch.setattr(mobilization, "mttr_collect", lambda **k: resumo)
    m4 = _por_id(mobilization.calcular({"scans_recorrentes": [33]},
                                       indicadores=["M4"]))["M4"]
    assert m4.get("lacuna", False) is False
    assert m4["valor"] == {"p50_critical": 12.0, "p50_high": 40.0}
    assert m4["contexto"]["cortes"]["critical"] == [90, 30, 15, 7]
    assert "MENOR dos dois" in m4["contexto"]["como_pontuar"]
