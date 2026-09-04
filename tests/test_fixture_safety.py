"""Falha se qualquer fixture parecer conter chave, IP privado ou hostname.

Barato de escrever, evita o acidente classico. Roda mesmo com o diretorio
vazio - e nasce junto com a primeira fixture, nao depois dela.
"""

import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

PADRAO_CHAVE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")

# SEM \b a esquerda, e a partir de 16: a primeira versao deste teste deixou
# passar `"schedule_uuid": "template-01df1e4e-be08-...-fc947e0b74a80cbae7b9..."`,
# porque o identificador tem prefixo e o \b nunca casava. Identificador opaco de
# tenant nao precisa ter forma de UUID para ser dado de tenant.
PADRAO_HEX_LONGO = re.compile(r"[0-9a-f]{16,}", re.I)

# Qualquer IPv4 que nao seja das faixas de documentacao da RFC 5737. A versao
# anterior so olhava faixas privadas e deixou passar 31.0.0.148 e 32.0.0.101,
# que sao endereços reais de ativos do sandbox.
PADRAO_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IP_DE_DOCUMENTACAO = re.compile(r"^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$")
PADRAO_IP_PRIVADO = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
PADRAO_HOSTNAME = re.compile(
    r"\b[\w-]+\.(?:local|corp|internal|lan|tenablesecurity\.com)\b", re.I
)
PADRAO_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
)

# UUIDs higienizados de proposito: tudo zero, ou o prefixo declarado.
UUID_PERMITIDO = re.compile(r"^(0{8}-0{4}-0{4}-0{4}-[0-9a-f]{12}|fixture-.*)$", re.I)


def _arquivos():
    if not FIXTURES.is_dir():
        return []
    return sorted(p for p in FIXTURES.rglob("*") if p.is_file())


@pytest.mark.parametrize("caminho", _arquivos(), ids=lambda p: p.name)
def test_fixture_nao_contem_segredo_nem_dado_de_tenant(caminho):
    texto = caminho.read_text(encoding="utf-8", errors="replace")
    rel = caminho.relative_to(FIXTURES)

    achado = PADRAO_CHAVE.search(texto)
    assert achado is None, (
        f"{rel}: parece haver uma chave de API ({achado.group()[:8]}...). "
        "Fixture nunca leva credencial."
    )

    for ip in PADRAO_IP.findall(texto):
        if all(0 <= int(o) <= 255 for o in ip.split(".")):
            assert IP_DE_DOCUMENTACAO.match(ip), (
                f"{rel}: endereco IP real ({ip}). Só faixas de documentacao da "
                "RFC 5737 sao aceitas."
            )

    for h in PADRAO_HEX_LONGO.findall(texto):
        assert set(h) == {"0"}, (
            f"{rel}: identificador opaco de tenant ({h[:12]}...). Zere antes de commitar."
        )

    achado = PADRAO_HOSTNAME.search(texto)
    assert achado is None, f"{rel}: hostname de tenant ({achado.group()})."

    for uuid in PADRAO_UUID.findall(texto):
        assert UUID_PERMITIDO.match(uuid), (
            f"{rel}: UUID que parece real ({uuid}). Higienize antes de commitar."
        )


def test_os_padroes_realmente_pegam():
    """Guarda do proprio guarda: um regex quebrado passaria tudo em silencio,
    e o teste ficaria verde sem proteger nada."""
    assert PADRAO_CHAVE.search("key=0123456789abcdef0123456789abcdef")
    assert PADRAO_IP_PRIVADO.search("host 192.168.1.10 up")
    assert not IP_DE_DOCUMENTACAO.match("31.0.0.148")     # o que passou antes
    assert IP_DE_DOCUMENTACAO.match("203.0.113.1")
    # o caso exato que escapou: forma de UUID com prefixo e cauda
    assert PADRAO_HEX_LONGO.search("template-01df1e4e-be08-f5f8-8a71-fc947e0b74a80cbae7b9b9a52612")
    assert PADRAO_HOSTNAME.search("srv-01.corp responded")
    assert PADRAO_UUID.search("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    assert not UUID_PERMITIDO.match("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    assert UUID_PERMITIDO.match("00000000-0000-0000-0000-000000000001")
