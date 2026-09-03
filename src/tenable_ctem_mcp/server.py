"""Registro das tools MCP. Nada mais.

Transporte: stdio. Nenhum HTTP, nenhuma hospedagem, nenhuma autenticacao de
rede - decisao fechada.

Estado do marco M0: uma tool registrada, `ctem_discover_tenant`. As outras dez
entram nos marcos M1 a M5, nesta ordem:
  M1  ctem_scoping, ctem_discovery, plugin_details_batch
  M2  ctem_prioritization, ctem_validation, plugin_census
  M3  ctem_preflight
  M4  mttr_collect, mttr_cadence_guard, scan_cadence
  M5  ctem_mobilization

NOTA sobre o SDK: o CLAUDE.md pede "FastMCP se disponivel no SDK". No SDK
oficial 2.x FastMCP foi renomeado para MCPServer; a ergonomia e a mesma
(decorator @mcp.tool e run("stdio")). Nao e desvio de decisao, e o nome novo
da mesma coisa.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from . import __version__, agora_utc
from .client import ErroApi, origem_tls
from .indicators.discovery import descobrir_tenant
from .preflight import ErroDenyList

mcp = MCPServer(
    name="tenable-ctem-mcp",
    version=__version__,
    instructions=(
        "Indicadores do assessment de CTEM da Tenable, ja agregados. Cada "
        "indicador vem com valor, n, filtro_literal, coletado_em_utc e "
        "veredito_preflight. Consulta que falha vira lacuna declarada com causa "
        "- nunca numero parcial. Community/partner tooling, nao suportado pela "
        "Tenable."
    ),
)


def _erro(e: Exception) -> dict[str, Any]:
    """Erro estruturado, sempre. Nunca stack trace, nunca numero parcial.

    A chave de API nunca aparece aqui: `client.chamar` nao a coloca em nenhuma
    mensagem, e o unico lugar que a le e o header da requisicao.
    """
    if isinstance(e, ErroDenyList):
        return dict(e.para_dict(), lacuna=True, coletado_em_utc=agora_utc())
    if isinstance(e, ErroApi):
        return {"erro": "falha_de_coleta", "causa": e.causa, "detalhe": str(e),
                "lacuna": True, "coletado_em_utc": agora_utc()}
    return {"erro": "falha_inesperada", "causa": type(e).__name__,
            "detalhe": str(e), "lacuna": True, "coletado_em_utc": agora_utc()}


@mcp.tool()
def ctem_discover_tenant(usar_cache: bool = True) -> dict[str, Any]:
    """Retrato do tenant numa chamada, para o Passo 0 do assessment.

    Devolve: categorias e valores de tag, contagem de ativos por asset_class,
    exposure_classes presentes (com o total de cada), scans com historico de
    execucao, e agentes por status.

    Substitui cerca de dez chamadas da Fase A do Passo 0. Resultado fica em
    cache por TTL curto; `usar_cache=False` forca coleta nova.

    ATENCAO: asset_class nao e exposure_classes. Um tenant pode ter ativos com
    asset_class = IDENTITY e exposure_classes = IDENTITY em zero. D2 usa
    exposure_classes.
    """
    try:
        return descobrir_tenant(usar_cache=usar_cache)
    except Exception as e:  # noqa: BLE001 - erro estruturado e o contrato
        return _erro(e)


@mcp.tool()
def ctem_diagnostico() -> dict[str, Any]:
    """Diz se o servidor consegue falar com o tenant, sem coletar indicador.

    Nao imprime a chave, nem parte dela. Serve para separar tres causas que se
    parecem no cliente: credencial ausente, credencial invalida, e TLS
    interceptado por proxy corporativo.
    """
    import os

    tem_ak = bool(os.environ.get("TIO_ACCESS_KEY", "").strip())
    tem_sk = bool(os.environ.get("TIO_SECRET_KEY", "").strip())
    d: dict[str, Any] = {
        "versao": __version__,
        "tio_url": os.environ.get("TIO_URL", "https://cloud.tenable.com"),
        "credenciais_no_ambiente": tem_ak and tem_sk,
        "coletado_em_utc": agora_utc(),
    }
    try:
        d["origem_das_cas_tls"] = origem_tls()
    except Exception as e:  # noqa: BLE001
        d["origem_das_cas_tls"] = f"indeterminada: {e}"

    if not (tem_ak and tem_sk):
        d["veredito"] = "credencial_ausente"
        d["detalhe"] = ("Defina TIO_ACCESS_KEY e TIO_SECRET_KEY no ambiente do "
                        "processo do servidor. A chave sai de Settings > My "
                        "Account > API Keys no tenant.")
        return d

    from .client import chamar
    try:
        chamar("GET", "/tags/categories")
        d["veredito"] = "ok"
    except Exception as e:  # noqa: BLE001
        d["veredito"] = "falha"
        d.update(_erro(e))
    return d


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
