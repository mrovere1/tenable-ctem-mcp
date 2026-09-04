"""Registro das tools MCP. Nada mais.

Transporte: stdio. Nenhum HTTP, nenhuma hospedagem, nenhuma autenticacao de
rede - decisao fechada.

Estado do marco M1: ctem_discover_tenant, ctem_scoping, ctem_discovery,
plugin_details_batch, plugin_census. Faltam:
  M2  ctem_prioritization, ctem_validation
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
from .indicators import discovery, scoping
from .indicators.discovery import descobrir_tenant
from .plugins import plugin_census as _plugin_census
from .plugins import plugin_details_batch as _plugin_details_batch
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
def ctem_scoping(mapeamento: dict[str, Any],
                 indicadores: list[str] | None = None) -> dict[str, Any]:
    """Estagio 1 - Scoping: S1, S2, S3, S4.

    `mapeamento` e obrigatorio e explicito - o servidor nao adivinha o nome da
    categoria de tag:
        {"categoria_criticidade": "Criticidade", "categoria_owner": "Owner"}
    Sem ele, S2 e S3 viram lacuna e a resposta lista as categorias que existem.
    Use `ctem_discover_tenant` antes para ver as categorias do tenant.

    S1 % de ativos com ao menos uma tag - S2 % com tag de criticidade
    S3 % com tag de owner - S4 Crown Jewels declarados (INFORMATIVO, nao pontua)

    `indicadores=["S2","S3"]` calcula so o subconjunto pedido.
    """
    try:
        return {"indicadores": scoping.calcular(mapeamento, indicadores)}
    except Exception as e:  # noqa: BLE001
        return _erro(e)


@mcp.tool()
def ctem_discovery(indicadores: list[str] | None = None,
                   superficies_licenciadas: list[str] | None = None,
                   corte_vpr_amostra: float = 7.0,
                   n_amostra: int = 30) -> dict[str, Any]:
    """Estagio 2 - Discovery: D1, D2, D3, D4.

    D1 dias desde a ultima avaliacao (invertido; fonte: scan_history, nunca
       filtro de data em findings nem o parametro `age`)
    D2 % das superficies licenciadas cobertas - passe `superficies_licenciadas`
       (default ["VM"]). E razao percentual, nao contagem
    D3 % de ativos DEVICE com agente - denominador e DEVICE, nao o total
    D4 % da amostra detectada por plugin local, com amostra estratificada de
       alocacao proporcional e intervalo de Wilson no contexto

    `indicadores=["D1","D3"]` evita as chamadas de plugin que D4 exigiria.
    """
    try:
        return {"indicadores": discovery.calcular(
            indicadores, superficies_licenciadas, corte_vpr_amostra, n_amostra)}
    except Exception as e:  # noqa: BLE001
        return _erro(e)


@mcp.tool()
def plugin_details_batch(plugin_ids: list[int]) -> dict[str, Any]:
    """Detalhe de varios plugins numa chamada, com CINCO campos por plugin.

    Devolve so: scan_type (local/remote), published, exploit_available,
    exploitability e as datas de CISA-KNOWN-EXPLOITED.

    O detalhe completo de um plugin tem ~8.200 caracteres e 97 atributos. Vinte
    plugins pelo caminho completo sao ~15.000 tokens; por aqui, ~1.500. Plugin
    que falhar entra em `lacunas` com a causa, e os outros continuam.
    """
    try:
        return _plugin_details_batch(plugin_ids)
    except Exception as e:  # noqa: BLE001
        return _erro(e)


@mcp.tool()
def plugin_census(severity: str = "critical") -> dict[str, Any]:
    """Quadro de amostragem: plugin, contagem de deteccoes, VPR e familia.

    Uma chamada, em cache por TTL curto. E o denominador de D4, M3, V1 e V2.
    Nao existe censo por busca: plugins_search_plugins aceita palavra-chave e
    CVE, nao lista de IDs de plugin.
    """
    try:
        return _plugin_census(severity)
    except Exception as e:  # noqa: BLE001
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
