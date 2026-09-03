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
