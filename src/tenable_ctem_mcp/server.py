"""Registro das tools MCP. Nada mais.

Transporte: stdio. Nenhum HTTP, nenhuma hospedagem, nenhuma autenticacao de
rede - decisao fechada.

Estado do marco M5: as 11 tools registradas, mais ctem_diagnostico.

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
from .indicators import (discovery, mobilization, prioritization, scoping,
                         validation)
from .indicators.discovery import descobrir_tenant
from .cadence import scan_cadence as _scan_cadence
from .mttr import ErroFiltroDivergente
from .mttr import mttr_cadence_guard as _mttr_cadence_guard
from .mttr import mttr_collect as _mttr_collect
from .plugins import plugin_census as _plugin_census
from .plugins import plugin_details_batch as _plugin_details_batch
from .preflight import ErroDenyList
from .preflight import executar_preflight as _executar_preflight

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
    if isinstance(e, ErroFiltroDivergente):
        return {"erro": "filtros_divergiram", "causa": e.causa, "detalhe": str(e),
                "lacuna": True, "coletado_em_utc": agora_utc(),
                "nota": ("O recorte que o job aplicou nao e o pedido, entao o "
                         "numero nao responde a pergunta. Isto e erro, nao "
                         "numero com ressalva.")}
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
def ctem_preflight(severity_workbenches: str = "critical") -> dict[str, Any]:
    """A tabela PREFLIGHT pronta: cada filtro que a skill usa, testado ao vivo.

    Nenhum veredito e herdado de documento. Tres formas de prova:
      par_exclusivo     duas consultas mutuamente exclusivas cujos totais tem de
                        somar o corpus - "reduziu" nao basta, um filtro pode
                        reduzir por acaso
      booleano          true e false; totais iguais significam parametro ignorado
      monotonico        escada de cortes que tem de ser estritamente decrescente

    Devolve tambem `deny_list`: os filtros que o servidor rejeita ANTES de a
    requisicao sair, com a regra e a prova medida de cada um.

    Rode isto antes de publicar qualquer numero derivado de filtro. Custa
    consultas com limit=1, porque so o campo `total` importa.
    """
    try:
        return _executar_preflight(severity_workbenches)
    except Exception as e:  # noqa: BLE001
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
def ctem_prioritization(mapeamento: dict[str, Any],
                        indicadores: list[str] | None = None,
                        corte_priorizacao_cliente: dict[str, Any] | None = None,
                        p2_valor: float | None = None) -> dict[str, Any]:
    """Estagio 3 - Prioritization: P1, P2, P3. Devolve tambem as filas comparadas.

    P1 % do backlog VPR >= 9 em ativo com criticidade declarada. NAO e a
       concordancia entre modelos de score - essa nao tem direcao de maturidade
    P2 % do backlog ACTIVE com VPR disponivel (>= 0.1; `exists` responde 400)
    P3 composto: criterio declarado + oportunidade medida. Depende de P2

    `corte_priorizacao_cliente` = {"metrica": "vpr"|"cvss3", "valor": 7.0,
    "confirmado": bool}. Sem metrica declarada P3 e LACUNA, nao numero: "o
    cliente nao sabe qual criterio usa" e o proprio estagio Ad Hoc.

    O contexto de P3 traz as tres filas (CVSS >= corte, VPR >= corte,
    intersecao) e a cobertura de VPR na fatia alta - que e a cobertura que
    sustenta uma recomendacao de troca de criterio, nao a do backlog inteiro.
    """
    try:
        return {"indicadores": prioritization.calcular(
            mapeamento, indicadores, corte_priorizacao_cliente, p2_valor)}
    except Exception as e:  # noqa: BLE001
        return _erro(e)


@mcp.tool()
def ctem_validation(mapeamento: dict[str, Any] | None = None,
                    indicadores: list[str] | None = None,
                    corte_vpr_amostra: float = 7.0,
                    n_amostra: int = 30,
                    ponderar: str = "por_deteccao") -> dict[str, Any]:
    """Estagio 4 - Validation: V1, V2, V3, V4.

    V1 % da amostra com exploit disponivel - INFORMATIVO, nao pontua estagio
    V2 mediana de dias no CISA KEV (invertido; cortes ancorados na CISA BOD 26-04)
    V3 taxa de reincidencia: RESURFACED / (RESURFACED + FIXED). Dado direto
    V4 % de DEVICE com software fora de suporte - denominador e DEVICE

    V1 e V2 saem da MESMA amostra de D4, para o relatorio nao descrever tres
    amostras diferentes com um unico tamanho declarado.

    `ponderar` e "por_deteccao" (default) ou "por_plugin" - a escolha muda o
    numero e vai declarada no contexto.
    """
    try:
        return {"indicadores": validation.calcular(
            mapeamento, indicadores, corte_vpr_amostra, n_amostra, ponderar)}
    except Exception as e:  # noqa: BLE001
        return _erro(e)


@mcp.tool()
def ctem_mobilization(mapeamento: dict[str, Any] | None = None,
                      indicadores: list[str] | None = None,
                      corte_vpr_amostra: float = 7.0, n_amostra: int = 30,
                      mttr_days: int = 180,
                      mttr_severities: list[str] | None = None,
                      mttr_max_wait_s: int = 240,
                      mttr_export_uuid: str | None = None,
                      corte_lote: int = 2,
                      pct_em_lote_max: float = 40.0) -> dict[str, Any]:
    """Estagio 5 - Mobilization: M1, M2, M3, M4.

    M1 cadencia mediana de avaliacao (invertido) - runs COLAPSADOS em dias
       distintos, no servidor. Sem colapso a mediana do sandbox e 1,42 dia;
       com colapso, 21 - dois estagios de diferenca
    M2 maior lacuna de avaliacao (invertido) - nao muda com o colapso
    M3 mediana da idade da correcao disponivel (invertido) - `Published` e
       proxy declarado da data do patch
    M4 MTTR, via mttr_collect, COM a guarda de cadencia aplicada

    `mapeamento["scans_recorrentes"]` e OBRIGATORIO para M1 e M2: o servidor nao
    escolhe quais scans representam a cadencia. No sandbox, so o scan recorrente
    da mediana 21 e maximo 140; somando todos os scans com historico da mediana
    1,0 e maximo 89, porque um deles roda quase todo dia.

    M4 vira LACUNA quando a guarda dispara - e resultado correto, nao defeito.
    Se o export estourar `mttr_max_wait_s`, M4 vira lacuna recuperavel com o
    `export_uuid` na causa; chame de novo passando `mttr_export_uuid`.
    """
    try:
        return {"indicadores": mobilization.calcular(
            mapeamento, indicadores, corte_vpr_amostra, n_amostra, mttr_days,
            mttr_severities, mttr_max_wait_s, mttr_export_uuid, corte_lote,
            pct_em_lote_max)}
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
def scan_cadence(scan_ids: list[str], colapsar_runs_do_mesmo_dia: bool = True,
                 apenas_completed: bool = True) -> dict[str, Any]:
    """Colapsa runs do mesmo dia em DIAS DISTINTOS de avaliacao.

    Devolve intervalos, mediana e maximo - e tambem `mediana_sem_colapso_dias`,
    sempre, para o contraste ficar visivel.

    Por que isso existe: um scan relancado minutos depois e a MESMA avaliacao,
    nao um novo ciclo. No sandbox os 12 runs do scan recorrente caem em 9 dias
    distintos; a mediana crua da 1,42 dia e a colapsada da 21 - Standardized em
    vez de Optimized, dois estagios de diferenca.

    `colapsar_runs_do_mesmo_dia=False` existe para o relatorio mostrar a
    diferenca, nunca para ser o default. M2 (maior lacuna) nao muda com o colapso.
    """
    try:
        return _scan_cadence(scan_ids, colapsar_runs_do_mesmo_dia, apenas_completed)
    except Exception as e:  # noqa: BLE001
        return _erro(e)


@mcp.tool()
def mttr_collect(days: int = 180, severities: list[str] | None = None,
                 tags: dict[str, Any] | None = None, max_wait_s: int = 240,
                 export_uuid: str | None = None,
                 estados: list[str] | None = None,
                 num_assets: int = 100, corte_lote: int = 2) -> dict[str, Any]:
    """MTTR por POST /vulns/export, com polling e download em chunks.

    E o UNICO caminho para MTTR: `last_fixed`, `time_taken_to_fix` e
    `severity_modification_type` nao estao entre as 44 propriedades de findings
    da API de Exposure Management. Nao e wrapper faltando.

    NAO bloqueia. Ao estourar `max_wait_s` devolve
    {status: "pendente", export_uuid} - chame de novo passando esse
    `export_uuid` para retomar. Abrir um export novo responderia 409.

    Se o job aplicar um recorte diferente do pedido, devolve ERRO estruturado e
    nao numero: o recorte nao e a pergunta.

    Leia sempre `cadencia_de_scan` junto do MTTR, e passe as janelas de la para
    `mttr_cadence_guard`.
    """
    try:
        return _mttr_collect(days, severities, tags, max_wait_s, export_uuid,
                             estados, num_assets, corte_lote)
    except Exception as e:  # noqa: BLE001
        return _erro(e)


@mcp.tool()
def mttr_cadence_guard(janelas: list[dict[str, Any]],
                       datas_de_scan: list[str] | None = None,
                       corte_alerta_pct: float = 40.0) -> dict[str, Any]:
    """Diz se o MTTR esta medindo cadencia de scan em vez de tempo de correcao.

    Passe `janelas` = `cadencia_de_scan.JANELAS` de mttr_collect (nao `lotes`:
    esse ja vem filtrado pelo corte, e sem as janelas unitarias o denominador
    encolhe e o percentual infla), e `datas_de_scan` = as datas de scan_cadence.

    Dois portoes, e o segundo importa mais:
      1. pct_em_lote acima do corte de alerta -> M4 e lacuna;
      2. janelas formadas SO por datas de scan -> M4 e lacuna, mesmo com
         pct_em_lote abaixo do corte.

    O portao 2 existe porque o percentual depende do corte de lote escolhido:
    no CSV de referencia o mesmo dado deu 93,5% com corte 2 e 38,7% com corte 5,
    e o corte 5 passaria pela guarda de 40%. A composicao das datas nao depende
    de escolha nenhuma.
    """
    try:
        return _mttr_cadence_guard(janelas, datas_de_scan, corte_alerta_pct)
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
