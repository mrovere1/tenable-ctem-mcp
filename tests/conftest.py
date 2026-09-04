"""Toca as respostas gravadas do sandbox no lugar da API.

Permite `pytest` sem tenant nenhum: nenhuma chamada de rede sai daqui, e
nenhuma chave e lida. A fixture e `tests/fixtures/sandbox_2026-09-03.json`,
higienizada estruturalmente.
"""

import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_2026-09-03.json"


def _assinatura(metodo, caminho, corpo, params):
    return json.dumps([metodo, caminho, corpo, params], sort_keys=True,
                      ensure_ascii=False)


@pytest.fixture
def sandbox(monkeypatch):
    """Substitui client.chamar e client.paginar pelas respostas gravadas.

    Falha alto quando a assinatura nao existe: um teste que pede uma consulta
    nao gravada tem de quebrar, nunca receber vazio e virar numero errado.
    """
    gravado = json.loads(FIXTURE.read_text(encoding="utf-8"))

    from tenable_ctem_mcp import client
    from tenable_ctem_mcp.indicators import discovery, scoping
    from tenable_ctem_mcp import plugins

    def chamar(metodo, caminho, corpo=None, params=None, **kw):
        a = _assinatura(metodo, caminho, corpo, params)
        if a not in gravado:
            raise AssertionError(f"consulta nao gravada na fixture: {a[:180]}")
        return gravado[a]

    def paginar(metodo, caminho, corpo=None, params=None, campo="data",
                limite_pagina=200, teto=100_000):
        itens, offset = [], 0
        while len(itens) < teto:
            p = dict(params or {}, limit=limite_pagina, offset=offset)
            lote = client._extrair_lista(chamar(metodo, caminho, params=p), campo)
            if not lote:
                break
            itens.extend(lote)
            if len(lote) < limite_pagina:
                break
            offset += limite_pagina
        return itens

    for modulo in (client, discovery, scoping, plugins):
        if hasattr(modulo, "chamar"):
            monkeypatch.setattr(modulo, "chamar", chamar)
        if hasattr(modulo, "paginar"):
            monkeypatch.setattr(modulo, "paginar", paginar)

    client.CACHE.limpar()
    yield
    client.CACHE.limpar()
