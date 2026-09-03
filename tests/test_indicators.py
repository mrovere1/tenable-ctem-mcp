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
