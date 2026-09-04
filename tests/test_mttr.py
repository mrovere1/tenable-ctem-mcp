"""M4 - MTTR, cadencia e as tres travas obrigatorias.

Numeros de _docs/validacao-dados-coleta-mttr-2026-09-03.md.
Divergencia e falha. Nao ajuste o teste: investigue.
"""

import json
from pathlib import Path

import pytest

from tenable_ctem_mcp.mttr import (
    ErroFiltroDivergente,
    comparar_filtros,
    detectar_lotes,
    mttr_cadence_guard,
    mttr_collect,
    percentil,
    percentil_posicao_mais_proxima,
    resumir,
)

FIXTURE = Path(__file__).parent / "fixtures" / "mttr_export_2026-09-03.json"


@pytest.fixture(scope="module")
def coleta():
    d = json.loads(FIXTURE.read_text(encoding="utf-8"))
    campos = d["campos"]
    linhas = [dict(zip(campos, l)) for l in d["linhas"]]
    return d, linhas


@pytest.fixture(scope="module")
def resumo(coleta):
    d, linhas = coleta
    return resumir(linhas, d["filtros_pedidos"], "00000000-0000-0000-0000-000000000001",
                   d["status"], corte_lote=2)


# --- Os numeros de referencia ---------------------------------------------

def test_recorte_tem_as_4278_linhas(coleta):
    _, linhas = coleta
    assert len(linhas) == 4278


def test_severidade_modificada_e_none_em_todas(resumo):
    """A unica medicao direta de recast e aceitacao que o assessment alcanca.
    `severity_modification_type` nao existe na API de Exposure Management -
    nenhum tool tenable_one_* chega nele. Vale para S3, P1 e P2, nao so M4."""
    assert resumo["severidade_modificada_diferente_de_none"] == 0
    assert resumo["registros_analisados"] == 4278


def test_mttr_critical_bate_com_o_csv_de_referencia(resumo):
    c = resumo["mttr_por_severidade"]["critical"]
    assert c["corrigidos_com_data"] == 10
    assert c["mttr_dias_media"] == 52.93
    assert c["mttr_dias_p50"] == 42.94
    assert c["mttr_dias_p90"] == 101.43
    assert c["mttr_dias_max"] == 178.07


def test_percentil_interpolado_difere_do_por_posicao(resumo):
    """Com n=10 a escolha muda o numero em 9%: 101,43 contra 92,91. Por isso o
    metodo vai declarado, e os dois valores vao no resumo."""
    c = resumo["mttr_por_severidade"]["critical"]
    assert c["mttr_dias_p90"] == 101.43
    assert c["mttr_dias_p90_posicao_mais_proxima"] == 92.91
    assert "interpolado" in resumo["metodo_percentil"]


def test_origem_do_mttr_e_nativa_em_todas(resumo):
    """100% de `time_taken_to_fix` nativo, 0 derivados."""
    for sev in ("critical", "high", "medium"):
        b = resumo["mttr_por_severidade"][sev]
        assert b["origem_derivado_last_fixed_menos_first_found"] == 0
        assert b["origem_nativo_time_taken_to_fix"] == b["corrigidos_com_data"]


def test_exclusao_de_reabertos_e_declarada_com_o_efeito(resumo):
    """A exclusao e defensavel - um finding reaberto nao foi corrigido - mas
    tem de estar escrita, com o numero que ela muda."""
    h = resumo["mttr_por_severidade"]["high"]
    assert h["mttr_dias_media"] == 60.39            # so FIXED
    assert h["mttr_dias_media_se_incluir_reabertos"] == 49.66
    assert h["reabertos_no_recorte"] == 5
    m = resumo["mttr_por_severidade"]["medium"]
    assert m["mttr_dias_media"] == 95.95
    assert m["mttr_dias_media_se_incluir_reabertos"] == 64.08
    assert resumo["estados_incluidos_no_mttr"] == ["FIXED"]


# --- Cadencia: o achado que importa mais que o percentual ------------------

def test_pct_em_lote_e_a_sensibilidade_ao_corte(coleta):
    """O corte 5 daria 38,7% e passaria pela guarda de 40% da skill. Por isso o
    corte usado e a sensibilidade vao no resumo: quem le o numero precisa saber
    com que corte ele foi feito."""
    _, linhas = coleta
    c = detectar_lotes(linhas, corte=2)
    assert c["pct_em_lote"] == 93.5
    assert c["lote_minimo_por_janela"] == 2
    assert c["sensibilidade_ao_corte"] == {"2": 93.5, "3": 74.2, "4": 64.5, "5": 38.7}
    assert c["findings_com_mttr"] == 31
    assert c["findings_em_lote"] == 29


def test_nove_janelas_sobre_sete_datas(coleta):
    """As 9 janelas (first_found, last_fixed) sao todas pares tirados de 7 datas.
    E o achado estrutural: essas 7 datas sao as datas de scan do tenant."""
    _, linhas = coleta
    c = detectar_lotes(linhas, corte=2)
    assert c["janelas_distintas"] == 9
    assert c["datas_que_formam_as_janelas"] == [
        "2026-01-27", "2026-03-08", "2026-06-07", "2026-06-08",
        "2026-06-09", "2026-09-02", "2026-09-03"]


def test_maior_lote_tem_12_findings_do_mesmo_ativo(coleta):
    """Todos com o mesmo dias_para_corrigir por construcao - o valor e o
    intervalo entre dois scans, nao o tempo de acao da equipe."""
    _, linhas = coleta
    maior = detectar_lotes(linhas, corte=2)["lotes"][0]
    assert maior["findings"] == 12
    assert maior["dias_para_corrigir"] == 85.51


def test_janelas_inclui_as_unitarias_e_lotes_nao(coleta):
    """Defeito encontrado ao ligar a guarda: alimentar mttr_cadence_guard com
    `lotes` exclui as janelas de um finding so do denominador e inflaciona o
    percentual - deu 100% contra os 93,5% reais, e sumiu uma das 7 datas."""
    _, linhas = coleta
    c = detectar_lotes(linhas, corte=2)
    assert len(c["janelas"]) == 9
    assert len(c["lotes"]) < len(c["janelas"])
    assert sum(j["findings"] for j in c["janelas"]) == c["findings_com_mttr"]


DATAS_DE_SCAN = ["2025-09-09", "2026-01-27", "2026-03-08", "2026-03-10",
                 "2026-06-07", "2026-06-08", "2026-06-09", "2026-09-02", "2026-09-03"]


def test_guarda_de_cadencia_declara_lacuna_pelos_dois_portoes(coleta):
    """As 7 datas das janelas sao 7 de 7 datas de execucao de scan. O MTTR aqui
    e o intervalo entre scans - mede cadencia de avaliacao, nao correcao."""
    _, linhas = coleta
    g = mttr_cadence_guard(detectar_lotes(linhas, corte=2)["janelas"],
                           datas_de_scan=DATAS_DE_SCAN)
    assert g["veredito"] == "lacuna"
    assert g["pct_em_lote"] == 93.5
    assert g["todas_as_datas_sao_de_scan"] is True
    assert len(g["datas_que_coincidem_com_scan"]) == 7
    assert len(g["motivos"]) == 2      # os dois portoes disparam


def test_segundo_portao_dispara_mesmo_com_percentual_baixo():
    """O portao das datas nao depende do corte escolhido, e e por isso que ele
    existe: com corte 5 o percentual cairia para 38,7% e passaria pela guarda."""
    janelas = [{"ativo": "a", "first_found": "2026-06-09",
                "last_fixed": "2026-09-02", "findings": 1}]
    g = mttr_cadence_guard(janelas, datas_de_scan=["2026-06-09", "2026-09-02"])
    assert g["pct_em_lote"] == 0.0            # nenhum lote
    assert g["veredito"] == "lacuna"          # ainda assim
    assert g["todas_as_datas_sao_de_scan"] is True


def test_guarda_libera_quando_as_datas_nao_sao_de_scan():
    janelas = [{"ativo": "a", "first_found": "2026-01-05",
                "last_fixed": "2026-01-09", "findings": 1}]
    g = mttr_cadence_guard(janelas, datas_de_scan=["2026-06-09"])
    assert g["veredito"] == "pode_pontuar"
    assert g["motivos"] == []


# ===========================================================================
# As TRES travas obrigatorias de mttr_collect.
# Nenhuma pode se perder na porta do coletor - decisao 2 do plano: nao ha
# caminho paralelo, entao a falha tem de ser explicita e recuperavel.
# ===========================================================================

def test_trava_1_estouro_de_tempo_devolve_pendente_com_uuid(monkeypatch):
    """Nao levanta excecao e nao devolve numero parcial: devolve o bilhete para
    a proxima chamada retomar. Abrir outro export responderia 409."""
    from tenable_ctem_mcp import mttr

    monkeypatch.setattr(mttr, "abrir_export",
                        lambda *a, **k: ("uuid-do-job", {"state": ["FIXED"]}, False))
    monkeypatch.setattr(mttr, "aguardar",
                        lambda uuid, s: ([], {"status": "PROCESSING",
                                              "finished_chunks": 1,
                                              "total_chunks": 4}, True))
    r = mttr_collect(max_wait_s=1)
    assert r["status"] == "pendente"
    assert r["export_uuid"] == "uuid-do-job"
    assert "409" in r["como_retomar"]
    assert "mttr_dias_media" not in json.dumps(r)   # nenhum numero parcial


def test_trava_2_filtros_divergentes_viram_erro_e_nao_numero(monkeypatch):
    """O recorte nao e o pedido, entao o numero nao responde a pergunta."""
    from tenable_ctem_mcp import mttr

    monkeypatch.setattr(mttr, "abrir_export",
                        lambda *a, **k: ("u", {"severity": ["critical"]}, False))
    monkeypatch.setattr(mttr, "aguardar",
                        lambda uuid, s: ([], {"status": "FINISHED",
                                              "filters": {"severity": ["low"]}}, False))
    with pytest.raises(ErroFiltroDivergente) as exc:
        mttr_collect()
    assert exc.value.causa == "filtros_divergiram"


def test_trava_3_falha_de_tls_sobe_com_causa_diagnosticada(monkeypatch):
    """Nunca excecao crua: o parceiro precisa saber que e o proxy dele, nao o
    MCP. E o servidor NUNCA oferece desligar a verificacao."""
    from tenable_ctem_mcp import mttr
    from tenable_ctem_mcp.client import ErroTLS

    def explode(*a, **k):
        raise ErroTLS("proxy corporativo interceptando TLS",
                      causa="tls_proxy_corporativo")

    monkeypatch.setattr(mttr, "abrir_export", explode)
    with pytest.raises(ErroTLS) as exc:
        mttr_collect()
    assert exc.value.causa == "tls_proxy_corporativo"


def test_retomada_por_uuid_nao_abre_export_novo(monkeypatch):
    """E assim que se evita o 409."""
    from tenable_ctem_mcp import mttr

    def nao_deveria(*a, **k):
        raise AssertionError("abriu export novo tendo export_uuid; isso daria 409")

    monkeypatch.setattr(mttr, "abrir_export", nao_deveria)
    monkeypatch.setattr(mttr, "aguardar",
                        lambda uuid, s: ([], {"status": "FINISHED", "filters": {}}, False))
    r = mttr_collect(export_uuid="uuid-existente")
    assert r["status"] == "concluido"
    assert r["export_retomado"] is True


def test_severidade_invalida_e_recusada_antes_de_sair():
    with pytest.raises(ValueError):
        mttr_collect(severities=["catastrofica"])


# --- Comparacao semantica de filtros ---------------------------------------

def test_comparacao_de_filtros_ignora_normalizacao_da_api():
    """A API normaliza a severidade e acrescenta TODOS os filtros de data com
    valor 0. Comparar os dicionarios literalmente acusaria divergencia em toda
    execucao - e por isso o consumidor le `filtros_divergiram`, nunca os dois."""
    pedidos = {"state": ["FIXED"], "severity": ["critical", "high"]}
    aplicados = {"state": ["FIXED"], "severity": ["HIGH", "CRITICAL"],
                 "since": 0, "first_found": 0, "last_fixed": 0}
    divergiu, div = comparar_filtros(pedidos, aplicados)
    assert divergiu is False and div == {}


def test_comparacao_de_filtros_pega_divergencia_real():
    divergiu, div = comparar_filtros({"severity": ["critical"]},
                                     {"severity": ["low"]})
    assert divergiu is True and "severity" in div


def test_percentil_com_lista_vazia_e_none():
    assert percentil([], 90) is None
    assert percentil_posicao_mais_proxima([], 90) is None
