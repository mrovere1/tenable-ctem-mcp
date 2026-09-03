# Plano de desenvolvimento — MCP local para o assessment de CTEM

Documento de partida para abrir uma conversa nova dedicada ao desenvolvimento. Tudo aqui é
derivado de medição feita contra o tenant de laboratório em 2026-09-02 e 2026-09-03, não de
estimativa.

---

## 1. Decisão de escopo, antes de escrever código

**O que este MCP é:** um servidor local, em stdio, que devolve os **indicadores do assessment de
CTEM já agregados**, mais o MTTR que a API de Exposure Management não alcança.

**O que ele não é:** não é um MCP genérico da Tenable, não substitui o MCP oficial, e não roda
hospedado. Ele complementa: onde o oficial devolve linhas, este devolve o número do indicador com
N, filtro literal e carimbo de tempo.

**Por que isso importa para o desempenho.** O ganho não vem de ter menos tools. Vem de mover a
agregação para o servidor. Medido nesta execução:

| | Hoje, via MCP oficial | Com o MCP dedicado |
|---|---|---|
| Chamadas para coletar os 17 indicadores | ~40 | ~7 |
| Detalhe de 20 plugins | 20 chamadas, ~15.000 tokens | 1 chamada, ~1.500 tokens |
| MTTR | impossível pelo MCP; exige script Python fora | 1 tool |
| Cadência (M1) | 12 runs crus, colapsados na skill | já colapsado em dias distintos |

A conta dos ~15.000 tokens é real: cada `plugins_get_plugin_details` devolve descrição, lista
completa de CVEs, sinopse e solução — e a skill usa **cinco campos**.

---

## 2. Superfície de tools proposta

Onze tools, **um tool por estágio**, cada um com um parâmetro `indicadores[]` opcional para pedir
um subconjunto (decisão fechada). Cada tool devolve, sempre, os mesmos metadados por indicador:
`valor`, `n`, `filtro_literal`, `coletado_em_utc`, `veredito_preflight`.

```
ctem_validation(mapeamento, indicadores=["V2","V3"])
→ devolve só V2 e V3, sem gastar as chamadas de plugin que V1 e V4 exigiriam
```

O parâmetro não é conveniência: é o que permite reexecutar um indicador que ficou em lacuna sem
recoletar os 17, e é o que faz o custo de uma reavaliação parcial ser proporcional ao pedido.

### Descoberta e pré-voo

| Tool | O que devolve | Substitui |
|---|---|---|
| `ctem_discover_tenant` | categorias e valores de tag, contagem por `asset_class`, `exposure_classes` presentes, scans com histórico, agentes | ~10 chamadas do Passo 0 Fase A |
| `ctem_preflight` | a tabela PREFLIGHT pronta: cada filtro que a skill usa, testado com par discriminante | o procedimento manual de `mcp-preflight.md` |

### Indicadores, um tool por estágio

| Tool | Indicadores | Observação de implementação |
|---|---|---|
| `ctem_scoping` | S1, S2, S3, S4 | precisa do mapeamento de categoria como parâmetro |
| `ctem_discovery` | D1, D2, D3, D4 | D4 usa `plugin_details_batch` |
| `ctem_prioritization` | P1, P2, P3 | devolve também as filas comparadas: CVSS ≥ corte, VPR ≥ corte, interseção |
| `ctem_validation` | V1, V2, V3, V4 | V1 e V2 usam `plugin_details_batch` |
| `ctem_mobilization` | M1, M2, M3, M4 | M4 depende do export; ver abaixo |

### Primitivas que resolvem os gargalos

| Tool | Por que existe |
|---|---|
| `plugin_details_batch(plugin_ids[])` | aceita **lista de IDs** e devolve só `Scan Type`, `Published`, `Exploit Available`, `Exploitability` e as datas de `CISA-KNOWN-EXPLOITED`. É o maior ganho de token do projeto. O `plugins_search_plugins` oficial aceita só palavra-chave e CVE — foi por isso que o censo de D4 e M3 ficou inalcançável |
| `plugin_census(severity)` | quadro de amostragem: plugin, contagem de detecções, VPR e família, numa chamada. Hoje sai de `workbenches_list_vulnerabilities` |
| `scan_cadence(scan_ids[])` | colapsa runs do mesmo dia em **dias distintos de avaliação** e devolve os intervalos, a mediana e o máximo. Corrige M1 no servidor: com runs crus a mediana deu 1,42 dia; colapsada, 21 dias — dois estágios de diferença |
| `mttr_collect(days, severities, tags)` | o wrapper de `POST /vulns/export`. Faz request, polling e download em chunks, agrega por severidade e devolve o resumo já com as três escolhas de método declaradas |
| `mttr_cadence_guard()` | recebe as janelas do MTTR e devolve `pct_em_lote` com o corte usado, a sensibilidade a cortes de 2 a 5, e as datas que formam as janelas — o que permite detectar "MTTR = intervalo entre scans" |

**Regra de ouro da API dos tools:** nenhuma tool aceita chave de API como parâmetro. Chave vem de
`TIO_ACCESS_KEY`, `TIO_SECRET_KEY` e `TIO_URL` no ambiente do processo.

---

## 3. Decisões de arquitetura a fechar no início

| Decisão | Recomendação | Razão |
|---|---|---|
| Linguagem | **Python**, com o SDK oficial de MCP | você já tem `tenable_mttr_export.py` 1.1.0 funcionando: 51 KB com tratamento de TLS corporativo, retomada de export por 409, download em chunks, percentil interpolado e autoteste. Porta-se quase inteiro para dentro do servidor. Em TypeScript isso é reescrita |
| Transporte | **stdio** | é MCP local. Sem HTTP, sem hospedagem, sem camada de autenticação para manter |
| Export assíncrono | tool única `mttr_collect` com `max_wait_s`, que devolve `status: pendente` com o `export_uuid` se estourar o tempo | um tool que bloqueia por 10 minutos estoura timeout do cliente. Devolver o UUID permite retomar, que é o que o script já faz com `--retomar` |
| Cache | cache em memória por processo, com TTL curto, chaveado por filtro literal | `ctem_discover_tenant` e `plugin_census` são chamados por vários indicadores. Sem cache, a mesma consulta sai 4 vezes |
| Rate limit | backoff exponencial com jitter, **e confirmar os limites documentados em developer.tenable.com antes de fixar número** | não invente o limite; leia |
| Paginação | interna, invisível para o tool | o cliente nunca deve receber `offset` |
| Erro | erro estruturado, nunca número parcial silencioso | é a regra central do projeto: consulta que falhou vira lacuna declarada |

---

## 4. Estrutura do repositório

```
tenable-ctem-mcp/
  README.md                 # instalação, chaves, aviso de laboratório, escopo
  LICENSE
  pyproject.toml
  src/tenable_ctem_mcp/
    server.py               # registro das tools
    client.py               # HTTP: auth, TLS, backoff, paginação, chunks
    preflight.py            # os pares discriminantes e a deny-list de filtros
    indicators/
      scoping.py  discovery.py  prioritization.py  validation.py  mobilization.py
    mttr.py                 # porta do tenable_mttr_export.py
    plugins.py              # batch e censo
    cadence.py              # colapso de runs em dias distintos
  tests/
    fixtures/               # respostas gravadas do sandbox, higienizadas
    test_indicators.py      # golden tests com os números medidos
    test_preflight.py
    test_mttr.py
  docs/
    tools.md                # contrato de cada tool
    limitacoes.md           # o que a API não entrega, com prova
```

---

## 5. Ordem de desenvolvimento

Cada marco tem um critério de pronto verificável. Não avance sem ele.

**M0 — Spike de risco (meio dia).** Um servidor com **uma** tool (`ctem_discover_tenant`),
respondendo do tenant real, testado no **MCP Inspector** (`npx @modelcontextprotocol/inspector`).
*Pronto quando:* o Inspector lista a tool e devolve as 9 categorias de tag do sandbox.
Isso derrisca autenticação, transporte e formato de resposta antes de qualquer indicador.

**M1 — Cliente HTTP e pré-voo.** `client.py` com auth, TLS, backoff e paginação; `ctem_preflight`
devolvendo a tabela completa. *Pronto quando:* o pré-voo reproduz os vereditos já conhecidos,
incluindo os três filtros que são aceitos e ignorados em silêncio e o `exists` que devolve 400.

**M2 — Primitivas de plugin.** `plugin_census` e `plugin_details_batch`. *Pronto quando:* os 20
plugins da amostra desta execução voltam em uma chamada, com os cinco campos, e a resposta cabe
em menos de 2.000 tokens.

**M3 — Indicadores sem MTTR.** Os quatro tools de estágio, S1 a M3. *Pronto quando:* os golden
tests batem com os números medidos em 2026-09-03 (seção 6).

**M4 — MTTR.** Porta do coletor para `mttr_collect`, mais `mttr_cadence_guard`. *Pronto quando:*
reprocessando o mesmo recorte, o resumo bate com o CSV de referência: `pct_em_lote` 93,5% com
corte 2, sensibilidade 93,5 / 74,2 / 64,5 / 38,7, e as 7 datas das janelas.

**M5 — Integração com a skill.** A skill passa a chamar as tools novas; o passo de coleta encurta;
o Passo 0 e o relatório não mudam. *Pronto quando:* a execução de aceitação reproduz o mesmo
relatório com ~7 chamadas em vez de ~40, e o coletor Python sai do pacote da skill.

**M6 — Empacotamento e publicação.** Plugin com MCP + skill, README, versionamento, publicação no
Exchange apontando para o GitHub. *Pronto quando:* instalação limpa numa máquina que nunca viu o
projeto, seguindo só o README, chega a um assessment completo.

---

## 6. Golden tests — os números que o servidor tem de reproduzir

Gravados do sandbox em 2026-09-03. Servem de regressão e são a razão pela qual este plano não é
especulativo.

| Medida | Valor |
|---|---|
| total de findings / ACTIVE / RESURFACED / FIXED | 5.486 / 5.425 / 11 / 50 |
| ativos / DEVICE | 30 / 8 |
| `tag_count >= 1` | 9 |
| VPR ≥ 9 | 586 · Crown Jewel 88 + Média 498 = 586 |
| VPR ≥ 0,1 | 4.462 |
| VPR ≥ 7 / CVSS3 ≥ 7 / interseção | 1.254 / 3.377 / 1.209 |
| CVSS3 ≥ 7 **e** VPR ≥ 0,1 | 3.314 (98,1% da fatia alta tem VPR) |
| `exposure_classes` | VM 8 · WAS 2 · CLOUD 0 · IDENTITY 0 |
| agentes ativos | 7 |
| plugins Critical distintos | 121 |
| dias distintos de avaliação do scan 33 | 9 · intervalos 140, 40, 2, 89, 1, 1, 85, 1 |
| MTTR Critical média / p50 / p90 | 52,93 / 42,94 / 101,43 |
| `pct_em_lote` com corte 2 | 93,5% (29 de 31) |
| `severidade_modificada` | NONE em 4.278 de 4.278 |

**Dois testes que não são sobre número, e são os mais importantes:**

1. **Deny-list de filtro ignorado.** O servidor **nunca** pode devolver uma contagem do corpus
   inteiro como se fosse filtrada. Filtros de data em findings, `authenticated`, `exploitable` e
   `filters` em texto livre entram numa deny-list: se alguém pedir, o tool devolve erro
   explicando, não um número. O teste prova que devolve erro.
2. **`filters` só aceita array JSON.** Passar `"tag_count >= 1"` como string devolveu os 30 ativos
   do corpus, sem erro — a armadilha mais fácil de cometer, porque é a sintaxe que
   `list_inventory_properties` sugere. O teste prova que o servidor rejeita string.

---

## 7. Acessos: o que é público e o que não é

**Tudo o que o MCP precisa é público.** Não há dependência de acesso interno Tenable:

| Item | Situação |
|---|---|
| APIs de Vulnerability Management e Exposure Management | públicas, documentadas em developer.tenable.com |
| `POST /vulns/export`, `last_fixed`, `time_taken_to_fix`, `severity_modification_type` | públicos, na API de VM |
| Chave de API | gerada pelo próprio usuário no tenant dele: **Settings › My Account › API Keys** |
| SDK de MCP, MCP Inspector | open source |

**Três cuidados, nenhum bloqueante:**

1. **Não redistribua os arquivos de OpenAPI** que estão na sua pasta `API Specs` dentro do repo
   público. Referencie a URL da documentação. Endpoint público não implica licença de
   redistribuição do arquivo de spec — e essa checagem é rápida de fazer antes de publicar.
2. **Tenant de desenvolvimento.** O sandbox é interno; use para desenvolver, mas os testes do repo
   rodam sobre **fixtures gravadas e higienizadas**, para que qualquer pessoa consiga rodar
   `pytest` sem tenant nenhum. Fixture não leva hostname, IP, UUID real nem nome de cliente.
3. **Nome e marca.** Nome que não se confunda com produto oficial — `tenable-ctem-mcp` com o aviso
   de "community / partner tooling, não suportado pela Tenable" no README e na descrição do
   Exchange, junto do aviso de laboratório que você já planejou.

---

## 8. Segurança do repositório — quatro itens, antes do primeiro push

1. `.gitignore` com `*.csv`, `*_resumo_*.json`, `.env`, `__pycache__`. Dado de tenant nunca entra
   no git, nem em fixture.
2. **Secret scanning e push protection** ligados no repositório do GitHub.
3. Chave só de variável de ambiente. Nada de parâmetro de tool, nada de arquivo de config com
   chave, nada de chave em log — o coletor já faz isso e o padrão se mantém.
4. Um teste que falha se qualquer fixture contiver o que parece uma chave, um IP ou um hostname
   do sandbox. Barato de escrever, evita o acidente clássico.

---

## 9. O que levar para a conversa nova

Cinco arquivos. Nada além disso é necessário para começar.

| Arquivo | Para que serve na conversa nova |
|---|---|
| `_docs/plano-mcp-ctem.md` | este documento. É o briefing: escopo, contrato das tools, marcos e critérios de pronto |
| `tenable-ctem-maturity-assessment.skill` | o consumidor do MCP. Contém os 19 indicadores com fórmula, cortes e origem do limiar, o pré-voo e o roteiro. É o contrato que as tools têm de satisfazer |
| `_ferramentas/mttr-export/tenable_mttr_export.py` (1.1.0) | a base do marco M4. TLS corporativo, retomada de export por 409, download em chunks, percentil declarado e autoteste já resolvidos. **Não comece do zero** |
| `_docs/validacao-dados-coleta-mttr-2026-09-03.md` | os números do MTTR para os golden tests, com o método de cada um declarado |
| `_docs/execucao-maturidade-sandbox-2026-09-03.md` | os números dos 17 indicadores para os golden tests, mais os três defeitos que a execução de aceitação encontrou |
| `_docs/matriz-confianca-filtros-mcp.md` | a deny-list. **Atualizado em 2026-09-03** com os dois casos novos: `filters` em texto livre ignorado em silêncio, e `exists` respondendo 400 em `finding_vpr_score` |

São seis linhas porque o plano entra na conta — sua lista de cinco estava certa, faltava só ele.

O `.skill` já carrega `references/mcp-preflight.md` e `references/indicadores-maturidade.md` dentro
do pacote, então não precisa levá-los soltos.

**Primeiro pedido da conversa nova:** o marco M0. Uma tool, `ctem_discover_tenant`, respondendo do
tenant real, validada no MCP Inspector. Antes disso, discussão de arquitetura é teoria.

---

## 10. Ambiente de desenvolvimento: Claude Code, Codex, ou os dois

**O chat do Claude Desktop está fora**: isto é projeto de código com arquivos, testes e git, e
você vai precisar rodar o servidor, rodar os testes e ler o erro no mesmo ciclo. Desktop serve para
conversar sobre o desenho, não para iterar num repositório.

**Entre Claude Code e Codex, os dois funcionam, e funcionam bem juntos** — porque ambos são
clientes de MCP, o que significa que qualquer um dos dois consegue registrar e exercitar o servidor
que você está construindo.
No Codex a configuração fica em `~/.codex/config.toml`, com `codex mcp add <nome> <comando>`,
compartilhada entre CLI, IDE e nuvem; no Claude Code, `claude mcp add`.

Onde cada um rende mais, na prática:

| Tarefa | Ferramenta | Por quê |
|---|---|---|
| Andaimes do projeto, contrato das tools, decisões de arquitetura | **Claude Code** | o contexto do assessment está aqui: as fórmulas dos 17 indicadores, os cortes, as armadilhas de filtro, o histórico das correções |
| Porta do coletor para dentro do servidor | **qualquer um** | é refatoração de código que já funciona e tem autoteste |
| Varredura de erro repetitivo, teste unitário em volume, tipagem | **Codex** | tarefa mecânica e paralelizável, onde segunda opinião de outro modelo pega o que o primeiro deixou passar |
| Revisão cruzada antes de publicar | **os dois, um sobre o trabalho do outro** | dois modelos diferentes erram em lugares diferentes. Vale especialmente na `preflight.py` e na deny-list |
| Validação de ponta a ponta com a skill | **Claude Code** | a skill roda no cliente Claude; é o ambiente real do parceiro |

**A regra que evita a dor de cabeça de trabalhar com dois agentes:** um repositório git, commits
pequenos, e **nunca os dois editando ao mesmo tempo**. Termine e faça commit antes de passar a bola.
Dois agentes no mesmo working tree sem commit no meio produz conflito silencioso — e num projeto
onde o valor está na exatidão do número, conflito silencioso é o pior tipo.

**E o Inspector continua sendo o teste principal, independentemente do agente.**
`npx @modelcontextprotocol/inspector` recarrega na hora e mostra o JSON cru de request e response.
Cliente Claude ou Codex só na validação de ponta a ponta — nos dois, cada mudança no servidor
exigiria reiniciar o cliente.

---

## 11. Decisões fechadas

| # | Decisão | Consequência no plano |
|---|---|---|
| 1 | **Granularidade: um tool por estágio**, com parâmetro `indicadores[]` para subconjunto | seção 2. Cinco tools de indicador em vez de dezessete, sem perder a reexecução parcial |
| 2 | **O coletor Python não fica em paralelo.** Se o MCP falhar, todos os indicadores falham — manter contingência só para M4 não muda o resultado da skill | o coletor sai do pacote da skill no marco M5, e passa a existir apenas como **origem do código** de `mttr.py` e como gerador das fixtures dos golden tests. Um caminho de execução, não dois |
| 3 | **Escopo da v1: só CTEM**, com a skill geral integrada | nenhuma tool genérica para as outras skills na v1. Uma coisa integrada e funcionando vale mais no Exchange que cinco meio prontas |
| 4 | **Suporte: comunidade, sem vínculo de produto** | o repositório entrega `docs/troubleshooting.md` e o README declara, junto do aviso de laboratório: MCP base, validado em laboratório, sem suporte oficial da Tenable, teste no seu ambiente antes de produção. Issues no GitHub são o canal, sem SLA prometido |

### O que a decisão 2 muda no marco M4

Como não há caminho paralelo, o M4 precisa de uma trava a mais: **`mttr_collect` tem de falhar de
forma explícita e recuperável.** Três comportamentos obrigatórios, todos já resolvidos no coletor e
que não podem se perder na porta para o servidor:

1. estouro de `max_wait_s` devolve `status: pendente` **com o `export_uuid`**, para a chamada
   seguinte retomar em vez de pedir um export novo — que responderia 409;
2. `filtros_divergiram = true` devolve erro, não número: o recorte não é o pedido;
3. falha de TLS devolve a causa diagnosticada, não uma exceção crua — é o erro mais comum em rede
   corporativa de cliente, e o parceiro precisa saber que é o proxy dele, não o MCP.

### O que a decisão 4 muda no repositório

`docs/troubleshooting.md` já nasce com os casos que este projeto encontrou de verdade — não é
documento especulativo:

- `401` — chave de outro container, ou espaço no fim da variável de ambiente;
- `409` no export — já existe export aberto para aquela chave; retomar pelo `export_uuid`;
- falha de certificado — rede que inspeciona TLS; usar o bundle da empresa via `TIO_CA_BUNDLE`, ou
  os keychains no macOS. **Nunca** desabilitar verificação, e o servidor não deve oferecer a opção;
- coleta vazia — resultado, não erro: vira lacuna declarada, e a janela usada vai no relatório;
- número que parece filtrado e é o corpus inteiro — o caso do `filters` em texto livre; a
  deny-list do servidor tem de rejeitar antes de chegar à API;
- ACR e AES vazios — ativo novo, calculados ~24 h após o primeiro scan;
- `pct_em_lote` alto — não é defeito: é o MTTR medindo intervalo entre scans, e a skill declara
  lacuna de propósito.
