# tenable-ctem-mcp

Servidor MCP **local (stdio)** que entrega os 17 indicadores do assessment de CTEM da Tenable já
agregados, mais MTTR — o que a API de Exposure Management não alcança diretamente.

Documentação de referência do projeto: `_docs/plano-mcp-ctem.md`. Leia antes de começar.

---

## O que este servidor é e o que não é

**É:** servidor local, stdio, que move a agregação para o servidor e entrega números prontos com
`valor`, `n`, `filtro_literal`, `coletado_em_utc`, `veredito_preflight`.

**Não é:** clone do MCP oficial da Tenable, MCP genérico, servidor hospedado, produto Tenable.

O ganho de performance vem de reduzir as chamadas de ~40 para ~7 e de ~15.000 para ~1.500 tokens
para os 17 indicadores + 20 plugins. Qualquer mudança que desfaça esse ganho é errada.

---

## Arquitetura — decisões fechadas. Não as reabra.

| Decisão | Valor |
|---|---|
| Linguagem | Python 3.12 |
| Framework MCP | SDK oficial MCP Python (FastMCP se disponível no SDK) |
| Transporte | **stdio**. Nenhum HTTP, nenhuma hospedagem, nenhuma autenticação de rede |
| Granularidade | Um tool por estágio CTEM + 5 primitivas. Total: 11 tools |
| Parâmetro de subconjunto | Cada tool de estágio aceita `indicadores: list[str] \| None`. Se `None`, calcula todos do estágio |
| Credenciais | Somente via variáveis de ambiente `TIO_ACCESS_KEY`, `TIO_SECRET_KEY`, `TIO_URL`. Nunca como parâmetro de tool, nunca em log |
| Export assíncrono | `mttr_collect` com `max_wait_s`. Devolve `status: pendente` + `export_uuid` ao estourar — nunca bloqueia indefinidamente |
| Cache | Em memória, por processo, TTL curto, chaveado por filtro literal. Obrigatório em `ctem_discover_tenant` e `plugin_census` |
| Paginação | Interna, invisível para o chamador. Nenhum tool expõe `offset` |
| Erro | Estruturado, nunca número parcial silencioso. Consulta que falhou → lacuna declarada com causa |
| Rate limit | Backoff exponencial com jitter. **Confirme os limites em developer.tenable.com antes de fixar número** |
| Caminho único de execução | Não há coletor paralelo. Se o MCP falha, todos os indicadores falham. `mttr_collect` é o único caminho para MTTR |
| Escopo v1 | Apenas CTEM. Nenhuma tool genérica para outras skills |
| Suporte | Comunidade. O README e o Exchange declaram: "community/partner tooling, não suportado pela Tenable" |

---

## Estrutura do repositório

Crie exatamente esta estrutura. Não adicione módulos fora dela sem justificativa.

```
tenable-ctem-mcp/
  CLAUDE.md                   # este arquivo
  README.md                   # instalação, chaves, aviso de laboratório, escopo, suporte
  LICENSE
  pyproject.toml
  .gitignore                  # ver seção Segurança
  src/tenable_ctem_mcp/
    __init__.py
    server.py                 # registro das 11 tools, nada mais
    client.py                 # HTTP para a API Tenable: auth, TLS, backoff, paginação, chunks
    preflight.py              # pares discriminantes e deny-list de filtros
    indicators/
      __init__.py
      scoping.py              # S1, S2, S3, S4
      discovery.py            # D1, D2, D3, D4
      prioritization.py       # P1, P2, P3
      validation.py           # V1, V2, V3, V4
      mobilization.py         # M1, M2, M3, M4
    mttr.py                   # porta de tenable_mttr_export.py 1.1.0 — não reescreva do zero
    plugins.py                # plugin_details_batch e plugin_census
    cadence.py                # colapso de runs em dias distintos de avaliação
  tests/
    fixtures/                 # respostas gravadas do sandbox, higienizadas (sem UUID real, IP, hostname)
    test_indicators.py        # golden tests com os números medidos em 2026-09-02/03
    test_preflight.py
    test_mttr.py
    test_fixture_safety.py    # falha se qualquer fixture parecer conter chave, IP ou hostname
  docs/
    tools.md                  # contrato de cada tool: parâmetros, retorno, erros
    limitacoes.md             # o que a API não entrega, com prova
    troubleshooting.md        # casos reais: 401, 409, TLS, coleta vazia, filters ignorado, ACR vazio
```

---

## Surface de tools

### Descoberta e pré-voo

```
ctem_discover_tenant()
  → categorias e valores de tag, contagem por asset_class, exposure_classes presentes,
    scans com histórico, agentes
  → substitui ~10 chamadas do Passo 0 Fase A
  → resultado em cache por TTL curto

ctem_preflight()
  → tabela PREFLIGHT pronta: cada filtro que a skill usa, testado com par discriminante
  → implementa mcp-preflight.md internamente
```

### Indicadores por estágio

```
ctem_scoping(mapeamento: dict, indicadores: list[str] | None = None)
  → S1, S2, S3, S4
  → requer mapeamento de categoria como parâmetro explícito

ctem_discovery(indicadores: list[str] | None = None)
  → D1, D2, D3, D4
  → D4 usa plugin_details_batch internamente

ctem_prioritization(indicadores: list[str] | None = None)
  → P1, P2, P3
  → devolve também as filas: CVSS ≥ corte, VPR ≥ corte, interseção

ctem_validation(mapeamento: dict, indicadores: list[str] | None = None)
  → V1, V2, V3, V4
  → V1 e V2 usam plugin_details_batch internamente

ctem_mobilization(indicadores: list[str] | None = None)
  → M1, M2, M3, M4
  → M1 usa scan_cadence (colapso de runs em dias distintos — crítico para MTTR correto)
  → M4 usa mttr_collect
```

### Primitivas

```
plugin_details_batch(plugin_ids: list[int])
  → aceita lista de IDs, devolve só: Scan Type, Published, Exploit Available,
    Exploitability, datas CISA-KNOWN-EXPLOITED
  → maior ganho de token do projeto. Não exponha campos extras.

plugin_census(severity: str)
  → quadro de amostragem: plugin, contagem de detecções, VPR, família
  → resultado em cache por TTL curto

scan_cadence(scan_ids: list[str])
  → colapsa runs do mesmo dia em dias distintos de avaliação
  → devolve intervalos, mediana e máximo
  → ATENÇÃO: sem colapso, mediana de M1 = 1,42 dia; com colapso = 21 dias. Dois estágios de
    diferença. Este colapso DEVE acontecer no servidor, nunca no cliente.

mttr_collect(days: int, severities: list[str], tags: dict | None = None,
             max_wait_s: int = 240, export_uuid: str | None = None)
  → wrapper de POST /vulns/export com polling e download em chunks
  → se export_uuid for passado, retoma export existente (evita 409)
  → ao estourar max_wait_s: devolve {status: "pendente", export_uuid: "<uuid>"}
  → agrega por severidade, devolve resumo com as três escolhas de método declaradas

mttr_cadence_guard(janelas: list[dict])
  → recebe janelas do MTTR, devolve pct_em_lote com corte usado,
    sensibilidade a cortes de 2 a 5, e as datas que formam as janelas
  → permite detectar "MTTR = intervalo entre scans"
```

---

## Contrato de retorno de cada indicador

Todo indicador, em todo tool, devolve este envelope. Nunca desvie.

```json
{
  "indicador": "M1",
  "valor": 21.0,
  "n": 12,
  "filtro_literal": "scan_ids=['abc','def'], runs colapsados em 5 dias distintos",
  "coletado_em_utc": "2026-09-03T14:22:00Z",
  "veredito_preflight": "ok"
}
```

Se a consulta falhar, o campo `valor` é `null` e `lacuna` é `true` com `causa` preenchida.
Número parcial silencioso é proibido. É a regra central do projeto.

---

## Regras de `mttr_collect` — não podem se perder na porta do coletor

O coletor `tenable_mttr_export.py` 1.1.0 já resolve estes três comportamentos. Mantenha-os:

1. Estouro de `max_wait_s` → `{status: "pendente", export_uuid: "<uuid>"}`. Não levanta exceção.
2. `filtros_divergiram = true` → erro estruturado, não número. O recorte não é o pedido.
3. Falha de TLS → causa diagnosticada ("proxy corporativo interceptando TLS"), não exceção crua.
   O servidor NUNCA oferece opção de desabilitar verificação de certificado.

A variável de ambiente `TIO_CA_BUNDLE` é o mecanismo para redes com inspeção de TLS. Documente
isso em `docs/troubleshooting.md`.

---

## Deny-list de filtros (`preflight.py`)

A deny-list deve rejeitar antes de chegar à API. Casos confirmados em 2026-09-03:

- `filters` em texto livre → ignorado em silêncio pela API. O servidor rejeita com erro.
- `exists` em `finding_vpr_score` → responde 400. O servidor rejeita com erro antes de enviar.

Consulte `_docs/matriz-confianca-filtros-mcp.md` para a lista atualizada. Não a replique aqui —
importe e mantenha em um lugar só.

---

## Testes

**Golden tests** com os números medidos em 2026-09-02/03 (fonte: `_docs/execucao-maturidade-sandbox-2026-09-03.md`
e `_docs/validacao-dados-coleta-mttr-2026-09-03.md`). Qualquer divergência é falha — não ajuste o
teste para passar, investigue a causa.

**Fixtures:** respostas gravadas do sandbox, higienizadas. Devem:
- Não conter hostname, IP, UUID real nem nome de cliente
- Permitir `pytest` sem tenant nenhum
- Ser validadas por `test_fixture_safety.py` (falha se encontrar padrão de chave, IP ou hostname)

`pytest` deve passar inteiro antes de cada commit. CI no GitHub verifica isso.

---

## Segurança — antes do primeiro `git push`

1. `.gitignore` inclui: `*.csv`, `*_resumo_*.json`, `.env`, `__pycache__`, `*.key`, `*.pem`
2. Secret scanning e push protection ligados no repositório GitHub
3. Chave somente em variável de ambiente. Nunca em parâmetro, arquivo de config ou log
4. `test_fixture_safety.py` falha se qualquer fixture contiver padrão de chave (`[A-Fa-f0-9]{32}`),
   endereço IP privado ou hostname do sandbox

---

## Ordem de desenvolvimento — marcos com critério de pronto

Não avance para o próximo marco sem satisfazer o critério do atual.

### M0 — Spike de risco (meio dia)
Uma tool: `ctem_discover_tenant`.
**Pronto quando:** MCP Inspector lista a tool e devolve as 9 categorias de tag do sandbox.
Isso derisca autenticação, transporte e formato antes de qualquer indicador.

### M1 — Scoping + Discovery
`ctem_scoping` e `ctem_discovery` com golden tests passando.
**Pronto quando:** `pytest tests/test_indicators.py -k "scoping or discovery"` passa com os
valores medidos de S1–S4 e D1–D4.

### M2 — Prioritization + Validation
`ctem_prioritization` e `ctem_validation` com golden tests.
**Pronto quando:** `pytest tests/test_indicators.py -k "prioritization or validation"` passa.

### M3 — Preflight
`ctem_preflight` com deny-list completa.
**Pronto quando:** `pytest tests/test_preflight.py` passa, incluindo os dois casos de 2026-09-03.

### M4 — MTTR
`mttr_collect`, `mttr_cadence_guard`, `scan_cadence`.
**Pronto quando:** os três comportamentos obrigatórios de `mttr_collect` têm teste próprio e
`pytest tests/test_mttr.py` passa com os números de `_docs/validacao-dados-coleta-mttr-2026-09-03.md`.

### M5 — Mobilization completo
`ctem_mobilization` com M1 usando `scan_cadence` (colapso de runs).
**Pronto quando:** mediana de M1 = 21 dias no fixture do sandbox (não 1,42).

### M6 — Integração com a skill
Registrar o servidor no cliente Claude Desktop ou Claude Code e rodar a skill de assessment
de ponta a ponta no tenant de sandbox.
**Pronto quando:** os 17 indicadores aparecem no relatório final sem lacunas inesperadas.

---

## Workflow de validação por marco

1. **MCP Inspector primeiro:** `npx @modelcontextprotocol/inspector`. Mostra JSON cru de request e
   response. Use para cada nova tool antes de passar para o cliente Claude.
2. **`pytest` antes de todo commit.** Sem exceção.
3. **Cliente Claude ou Claude Code** só na validação de ponta a ponta (M6). Cada mudança no
   servidor exige reiniciar o cliente — não use para iterar.

---

## O que não fazer

- **Não reescreva `mttr.py` do zero.** Porte `tenable_mttr_export.py` 1.1.0 — ele já tem TLS
  corporativo, retomada por 409, download em chunks, percentil interpolado e autoteste resolvidos.
- **Não adicione tools genéricas** para outras skills. Escopo v1 = CTEM.
- **Não exponha campos extras em `plugin_details_batch`.** A economia de tokens depende disso.
- **Não use polling síncrono em `mttr_collect`.** Devolva `status: pendente` ao estourar.
- **Não redistribua arquivos de OpenAPI** da pasta `API Specs` no repositório público. Referencie
  a URL de developer.tenable.com.
- **Não invente limites de rate.** Leia developer.tenable.com e fixe o número que lá está.
- **Não ajuste golden tests para passar.** Investigue a divergência.
- **Não faça dois agentes editarem ao mesmo tempo.** Um repositório, commits pequenos, um agente
  por vez. Termine e faça commit antes de passar a bola.

---

## Referências

| Arquivo | Propósito |
|---|---|
| `_docs/plano-mcp-ctem.md` | Briefing completo: escopo, contrato das tools, marcos |
| `tenable-ctem-maturity-assessment.skill` | Consumidor do MCP; contém fórmulas, cortes e limiar |
| `_ferramentas/mttr-export/tenable_mttr_export.py` | Base de `mttr.py`. Versão 1.1.0 |
| `_docs/validacao-dados-coleta-mttr-2026-09-03.md` | Números do MTTR para golden tests |
| `_docs/execucao-maturidade-sandbox-2026-09-03.md` | Números dos 17 indicadores para golden tests |
| `_docs/matriz-confianca-filtros-mcp.md` | Deny-list atualizada em 2026-09-03 |
