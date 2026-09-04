# Os 19 indicadores de maturidade CTEM

Arquivo de referência da skill `tenable-ctem-maturity-assessment`. Uma cópia vive dentro do pacote.

Cada indicador traz a fórmula, a origem do limiar e os cortes default.

> **Atualizado em 2026-09-04.** A coluna **Fonte MCP** de cada tabela descreve o caminho ANTIGO,
> pelo MCP oficial da Tenable. A coleta agora é feita pelo servidor **`tenable-ctem-mcp`**, que
> devolve cada indicador já agregado:
>
> | Estágio | Tool | Indicadores |
> |---|---|---|
> | Scoping | `ctem_scoping(mapeamento)` | S1–S4 |
> | Discovery | `ctem_discovery()` | D1–D4 |
> | Prioritization | `ctem_prioritization(mapeamento, corte_priorizacao_cliente)` | P1–P3 |
> | Validation | `ctem_validation(mapeamento)` | V1–V4 |
> | Mobilization | `ctem_mobilization(mapeamento)` | M1–M4 |
>
> **As fórmulas, os cortes e a origem dos limiares não mudaram** — só quem executa a consulta. A
> coluna antiga fica porque documenta de onde cada número vem na API, e porque é ela que explica as
> armadilhas de filtro que a deny-list do servidor hoje bloqueia.
>
> Três mudanças de fato, e não só de caminho:
> - **D4, V1, V2 e M3 saem de CENSO por default**, não de amostra — ver `mcp-preflight.md`;
> - **M4 não usa mais CSV**: `ctem_mobilization` chama `mttr_collect` e já aplica a guarda de cadência;
> - **M1 recebe os runs já colapsados** em dias distintos, feito no servidor.

**Todo indicador passa pelo pré-voo, que agora é uma chamada: `ctem_preflight()`.**

## Como ler os cortes

Quatro pontos de corte produzem os cinco estágios:

```
Ad Hoc < c1 ≤ Defined < c2 ≤ Standardized < c3 ≤ Advanced < c4 ≤ Optimized
```

`invertido` significa que menor é melhor — dias, latência, taxa de reincidência. Nesses casos a
ordem dos cortes é decrescente e a comparação se inverte.

`informativo` significa que o indicador **não** entra no cálculo do estágio. Entra como contexto,
porque converter aquele número em maturidade exigiria premissa que o dado não sustenta.

---

## Estágio 1 — Scoping

Critérios oficiais correspondentes: **Asset Visibility** e **People | Process**.

| ID | Indicador | Fórmula | Fonte MCP | Cortes default |
|---|---|---|---|---|
| S1 | % de ativos com ao menos uma tag | `assets(tag_count ≥ 1) / assets(total)` | `tenable_one_search_assets` com filtro `tag_count >= 1` | 20 / 50 / 80 / 95 |
| S2 | % de ativos com tag de criticidade | `assets na categoria de criticidade / total` | `tagging_list_tag_categories_and_values` para achar a categoria, depois `search_assets(tag="Categoria:Valor")` por valor | 10 / 40 / 70 / 90 |
| S3 | % de ativos com tag de owner | idem, na categoria de owner | idem | 10 / 40 / 70 / 90 |
| S4 | Crown Jewels declarados | existe categoria de criticidade **e** ≥1 ativo com `acr ≥ 9` | `acr` + tags | `informativo` (gate) |

**Como identificar a categoria de criticidade e de owner.** Não assumir nome. Procurar, sem
distinção de acentuação ou caixa, por: criticidade, criticality, criticality tier, business
criticality, crown jewel, tier, importancia. Para owner: owner, dono, responsavel, responsible,
custodian, team, squad, departamento, department, business unit, bu. Se nada casar, S2 e S3 viram
**lacuna** e o relatório lista as categorias que existem, para o consultor apontar a correta.

**Lacuna estrutural de S4, sempre declarada:** o MCP não expõe se o ACR foi ajustado por humano ou
se é o valor automático da Tenable. Portanto S4 mede *declaração* de contexto, não *curadoria*.
Por isso é informativo e não pontua estágio.

---

## Estágio 2 — Discovery

Critérios oficiais: **Asset Visibility**, **Risk Detection** e **Data Consolidation**.

| ID | Indicador | Fórmula | Fonte MCP | Cortes default (dias) |
|---|---|---|---|---|
| D1 | Dias desde a última avaliação | `hoje − Start time do run mais recente` | `scan_list_scans` + `scan_history` de cada scan com histórico | 90 / 45 / 14 / 7 · `invertido` |
| D2 | Cobertura das superfícies licenciadas | `distinct(exposure_classes) presentes / superfícies licenciadas` | `tenable_one_search_assets`, uma consulta por classe com `limit=1` lendo só o total | 25 / 50 / 75 / 90 (percentual) |
| D3 | % de ativos com agente | `agentes ativos / assets(asset_class = DEVICE)` | `agent_list_agents` + `search_assets(asset_class="DEVICE")` | 20 / 50 / 75 / 90 |
| D4 | % da amostra detectada por plugin local | `plugins(Scan Type = local) / plugins da amostra` | `plugins_get_plugin_details` sobre a amostra estratificada | 25 / 50 / 75 / 90 |

**Sobre D1.** Não usar filtro de data em findings — eles são silenciosamente ignorados, ver
`mcp-preflight.md` seção 1. Não usar o parâmetro `age` como idade: ele é recência da última
observação. `scan_history` devolve `Start time` real por run e é a fonte correta.

**Sobre D2, corrigido em 2026-09-02.** Os cortes eram contagem absoluta, o que contradizia a
própria instrução de comparar contra o licenciado: um cliente que licencia só VM e WAS e cobre as
duas ficaria em Defined por ter "apenas 2". Agora é razão percentual.

Valores possíveis de `exposure_classes`: `VM`, `WAS`, `CLOUD`, `IDENTITY`, `OT`, `AI`, `CODE`.
**Atenção:** `asset_class` não é `exposure_classes`. No sandbox existem ativos com
`asset_class = IDENTITY`, mas `exposure_classes = IDENTITY` retorna zero — os ativos de identidade
estão no inventário sem carregar achados de Identity Exposure. Usar sempre `exposure_classes`.

**Sobre D4.** Proxy legítimo e declarado: plugin de tipo `local` só retorna resultado com
credencial válida ou agente. Não é leitura de status de credencial. Não usar o parâmetro
`authenticated` de workbenches — comprovadamente ignorado.

---

## Estágio 3 — Prioritization

Critérios oficiais: **Prioritization** e **Scoring Methodology**.

| ID | Indicador | Fórmula | Fonte MCP | Cortes default |
|---|---|---|---|---|
| P1 | % do backlog crítico em ativo com contexto de negócio | `findings(VPR ≥ 9 E ativo com tag de criticidade) / findings(VPR ≥ 9)` | `search_findings` com `vpr_min=9.0` combinado com `tag="Categoria:Valor"` — o AND funciona, validado | 10 / 40 / 70 / 90 |
| P2 | % do backlog com VPR disponível | `findings(finding_vpr_score existe) / findings(ACTIVE)` | `search_findings` | 40 / 70 / 90 / 98 |
| P3 | Adequação do critério de priorização | composto, ver abaixo | `finding_cvss3_base_score`, `vpr_min` e a resposta do Passo 0 | tabela de estágio própria |

**P1 foi redefinido em 2026-09-02, durante a primeira execução real.** A versão anterior era
`findings(VPR ≥ 9) / findings(CRITICAL)`, marcada como invertido. Isso estava errado: aquele número
é a **concordância entre dois modelos de score**, e não tem direção de maturidade defensável — pela
mesma razão que o delta VPR × CVSS não tem. Pior, a direção que eu havia atribuído contradizia a
própria nota de leitura do indicador. O erro apareceu ao ver o valor real de 94,4% no sandbox e
perceber que ele classificaria como Ad Hoc um tenant onde os dois modelos simplesmente concordam.

A definição nova mede o que é de fato maturidade de priorização: **o contexto de negócio chega até
a camada de decisão?** De todo o backlog que a fila trata como crítico por VPR, quanto está em ativo
que tem criticidade declarada.

É diferente de S2, e a diferença é informativa. S2 mede cobertura de tag sobre o inventário todo;
P1 mede cobertura ponderada por onde o risco crítico realmente está. Um cliente com 27% dos ativos
tagueados e 100% do backlog crítico em ativo tagueado **tagueou os ativos certos** — isso é mais
maduro que o inverso. Foi exatamente o caso medido no sandbox.

A concordância entre os dois modelos de score continua no relatório, agora como número de contexto
dentro de P3, onde tem sentido porque está cruzada com o critério que o cliente declara usar.

### P3 em detalhe — por que o delta puro não pode pontuar sozinho

**O delta VPR × CVSS mede oportunidade, não maturidade.** Um cliente com delta enorme tem muito a
ganhar trocando de critério, mas o tamanho do delta é propriedade da mistura de vulnerabilidades do
ambiente dele, não do processo dele. Promover o número cru a indicador de maturidade puniria um
cliente por ter um parque Windows antigo, o que não é uma escolha de processo.

O delta vira sinal de maturidade quando **combinado com o critério que o cliente declara usar**,
coletado na Pergunta 4 do Passo 0. Aí a pergunta deixa de ser "qual o tamanho do delta" e passa a
ser "o cliente está operando no critério que concentra risco, e o dado dele sustenta esse critério".

**Parte medida — a oportunidade:**

```
fila_cliente  = findings acima do corte declarado (CONFIG.cutMetric ≥ CONFIG.cutValue)
fila_vpr      = findings(VPR ≥ CONFIG.cutValue)
oportunidade  = max(0, 1 − fila_vpr / fila_cliente)
```

**Parte declarada:** `CONFIG.cutMetric`, que é `vpr` ou `cvss3`.

**Tabela de estágio de P3:**

| Estágio | Condição |
|---|---|
| 1 — Ad Hoc | o cliente **não sabe** qual critério usa (resposta "Não sei" no Passo 0) |
| 2 — Defined | usa CVSS e `oportunidade ≥ 0,50` — metade da fila imediata sairia trocando de critério |
| 3 — Standardized | usa CVSS e `0,20 ≤ oportunidade < 0,50` |
| 4 — Advanced | usa CVSS com `oportunidade < 0,20` (os dois modelos concordam neste ambiente), **ou** usa VPR com cobertura de VPR abaixo de 98% |
| 5 — Optimized | usa VPR **e** cobertura de VPR ≥ 98% (o valor de P2) |

**A distinção entre Advanced e Optimized é a que dá sentido ao indicador.** Um cliente pode dizer
que prioriza por VPR enquanto 40% do backlog não tem VPR calculado — nesse caso o critério não é
aplicável à maior parte da fila, e o processo está declarado mas não sustentado pelo dado. Por isso
P3 depende de P2.

**Dependência a registrar:** P3 exige P2 calculado. Se P2 estiver em lacuna, P3 também vira lacuna.

### Qual critério recomendar ao cliente — medido no sandbox em 2026-09-03

A recomendação **não** entra em `corte_priorizacao_cliente`, que é descritivo. Ela entra no
roadmap. E é sustentada por medição, não por preferência:

| Fila | Findings | O que significa |
|---|---|---|
| `CVSSv3 >= 7` | 3.377 | fila imediata se o critério for CVSS |
| `VPR >= 7` | 1.254 | fila imediata se o critério for VPR |
| interseção | 1.209 | os dois critérios concordam aqui |
| só CVSS ≥ 7 | 2.168 | o que sai da fila ao trocar para VPR |
| só VPR ≥ 7 | 45 | o que **entra** na fila ao trocar para VPR |

Trocar CVSS ≥ 7 por VPR ≥ 7 nesse tenant tira 2.168 itens e acrescenta 45 — fila 63% menor, com
45 itens novos que o VPR considera relevantes por atividade de ameaça e o CVSS não flagava.

**A objeção esperada, e a resposta medida.** "VPR não cobre todo o backlog" é verdade: P2 deu
81,6%. Mas a cobertura que importa é a da fatia que o critério de CVSS selecionaria, e ali ela é
de **98,1%** — 3.314 dos 3.377 findings com CVSS ≥ 7 têm VPR. O VPR que falta está concentrado no
backlog de baixa severidade, que nenhum dos dois critérios coloca na fila imediata. Medir isso
antes de recomendar é obrigatório: em tenant onde a cobertura da fatia alta for baixa, a
recomendação passa a ser composta — VPR como primário e CVSS ou severidade como regra de fallback
para os findings sem VPR, mais uma regra de exceção que puxa para o topo o que estiver no CISA KEV
ou com exploit disponível, independentemente do score.

**Detalhe de coleta:** `finding_vpr_score` com operador `>=` **funciona** no array `filters`
(3.314 com CVSS ≥ 7 e VPR ≥ 0,1). O que responde HTTP 400 é o operador `exists` nessa propriedade.

**Declarar no relatório**, junto ao número: que o delta em si mede oportunidade no ambiente e não
comportamento do cliente, e que o estágio de P3 vem da combinação entre o critério declarado e a
oportunidade medida. Sem essa frase, o leitor pode concluir que a Tenable está avaliando o processo
dele a partir do backlog, o que não é o caso.

**Sobreposição com a skill 1.3, deliberadamente aceita.** A `tenable-vpr-vs-cvss-delta` continua
sendo a entrega em profundidade — comparativo visual dos dois modelos, volume que sai da fila
imediata, ganho de esforço em itens. Aqui P3 é **um número composto**, não a análise. A duplicação
é de dado, não de entrega.

---

## Estágio 4 — Validation

Critério oficial: **Risk Detection**.

| ID | Indicador | Fórmula | Fonte MCP | Cortes default |
|---|---|---|---|---|
| V1 | % da amostra com exploit disponível | `plugins(Exploit Available = True) / plugins da amostra` | `plugins_get_plugin_details` | `informativo` |
| V2 | Mediana de dias no CISA KEV | `mediana(hoje − min(datas CISA-KNOWN-EXPLOITED))` | `plugins_get_plugin_details`, Cross References | 180 / 90 / 30 / 14 · `invertido` |
| V3 | Taxa de reincidência | `findings(RESURFACED) / findings(RESURFACED + FIXED)` | `search_findings`, propriedade `state` | 25% / 15% / 8% / 3% · `invertido` |
| V4 | % de DEVICE com software fora de suporte | `assets DEVICE com finding de EOL / assets(asset_class = DEVICE)` | `search_findings(query_text="Unsupported Version Detection")` e `query_text="SEoL"` | 30 / 15 / 7 / 2 · `invertido` |

**V1 é informativo.** Um percentual alto de exploit disponível pode indicar backlog ruim ou apenas
ambiente montado sobre stack popular, que concentra pesquisa de exploit. Sem premissa do cliente,
virar estágio seria interpretação.

**V2 é o indicador mais forte do conjunto** e o único com âncora externa citável: os cortes de 14 e
de 30 dias derivam dos tiers de remediação da CISA BOD 26-04. Declarar no relatório que a diretiva
se aplica a agências federais dos Estados Unidos e aqui é referência de prazo reconhecida, não
obrigação regulatória do cliente.

**V3 usa dado direto.** `state = RESURFACED` é estado do registro, não cálculo. Reincidência alta
indica correção que não se sustenta — patch revertido, imagem base não corrigida, reprovisionamento
a partir de template vulnerável.

**Denominador de V4 corrigido em 2026-09-02:** são os ativos `DEVICE`, não o total de ativos. O
inventário Tenable One inclui IDENTITY, ACCOUNT e GROUP, que não têm software instalado; usá-los no
denominador dilui o indicador. No sandbox a diferença foi grande: 7 de 30 ativos dá 23%, e 7 de 8
DEVICE dá 87,5% — dois estágios de distância.

**Sobre V4.** `unsupported_by_vendor` existe na API mas não é alcançável pelo MCP. O caminho válido
é busca textual, que funciona: `query_text` é filtro comprovadamente aplicado. Confirmar cada
achado no detalhe do plugin antes de contar.

---

## Estágio 5 — Mobilization

Critérios oficiais: **Mobilization** e **Metrics | Reporting**.

| ID | Indicador | Fórmula | Fonte MCP | Cortes default (dias) |
|---|---|---|---|---|
| M1 | Cadência mediana de avaliação | `mediana do intervalo entre DIAS distintos de avaliação` | `scan_history` | 90 / 45 / 14 / 7 · `invertido` |
| M2 | Maior lacuna de avaliação | `maior intervalo entre dois runs consecutivos` | `scan_history` | 180 / 90 / 30 / 14 · `invertido` |
| M3 | Mediana da idade da correção disponível | `mediana(hoje − Published do plugin)` na amostra | `plugins_get_plugin_details` | 180 / 90 / 30 / 14 · `invertido` |
| M4 | MTTR mediano de fechamento | `min(estágio(p50 Critical), estágio(p50 High))` — ver abaixo | **CSV do coletor**, não MCP | Critical 90 / 30 / 15 / 7 · High 180 / 60 / 30 / 14 · `invertido` |

### M4 — o único indicador fora do MCP

**Fonte.** `tenable_mttr_findings_*.csv`, produzido por `tenable_mttr_export.py` (distribuído com
esta skill em `scripts/`, e também com `tenable-mttr-dashboard`; cópias idênticas por checksum). O coletor chama `POST /vulns/export` na API de
Vulnerability Management e traz `first_found`, `last_found`, `last_fixed` e o `time_taken_to_fix`
que a própria Tenable calcula em segundos.

**Por que não sai do MCP.** `last_fixed` e `time_taken_to_fix` não existem na API de Exposure
Management, que é a que os tools `tenable_one_*` consomem — não é wrapper faltando. E os filtros
de data em `search_findings` são aceitos e silenciosamente ignorados (revalidado em 2026-09-03:
`state=FIXED` devolveu 50 findings, e `within last 1d`, `older than 3650d` e `< 2020-01-01`
devolveram os mesmos 50).

**Fórmula.** Por severidade, `p50` de `dias_para_corrigir` nas linhas `estado=FIXED` com valor.
Cada p50 vira um estágio pelos seus cortes; **M4 é o menor dos dois** — mobilização madura fecha
as duas severidades, não compensa uma com a outra.

**Origem dos cortes**, rotulada indicador por indicador como exige a camada 3:

| Corte | Critical | High | Origem |
|---|---|---|---|
| Optimized | ≤ 7 d | ≤ 14 d | CIS Controls v8 |
| Advanced | ≤ 15 d | ≤ 30 d | NIST SP 800-40 |
| Standardized | ≤ 30 d | ≤ 60 d | PCI DSS v4.0 |
| Defined | ≤ 90 d | ≤ 180 d | **piso sem padrão de referência** — declarar como escolha da skill |
| Ad Hoc | acima disso | acima disso | — |

Nenhum desses limiares é oficial da Tenable, e nenhum é o SLA do cliente. Quando o operador
informar o SLA interno na Pergunta correspondente do Passo 0, usar o SLA dele e trocar a origem
para `sla_do_cliente` no relatório.

**Condicional.** Sem CSV, M4 vira lacuna com causa nomeada e o total de pontuáveis cai de 17 para
16. Os portões de `n` mínimo, composição derivada, divergência de filtro e cadência de scan estão
no Passo 2.M4 do SKILL.md e são obrigatórios.

**O portão que mais importa: cadência de scan.** `time_taken_to_fix` mede detecção a detecção. Se
`cadencia_de_scan.pct_em_lote` do resumo for 40% ou mais, M4 vira **lacuna** — não rótulo. Com
cadência dominante, M4 mediria a mesma coisa que M1 e M2, contando cadência duas vezes e chamando
de maturidade de remediação o que é maturidade de avaliação. Mesmo princípio que impediu P3 de
pontuar pelo delta puro.

Na primeira coleta real do sandbox, em 2026-09-03 (4 278 findings, 31 `FIXED` com data), o resumo
do coletor publicou `pct_em_lote = 74,2%`; recontado do CSV com corte de lote em 2 findings, o
valor é **93,5%** — o coletor só conta grupos de 3 ou mais e descarta três grupos de 2. Por isso o
portão **reconta do CSV** com `CONFIG.mttr.lote_minimo_por_janela` em vez de aceitar o número do
resumo. E o achado estrutural: as 9 janelas `(first_found, last_fixed)` são todas pares tiradas de
7 datas, que são as datas de scan do tenant, com 29 dos 31 findings em janela compartilhada — o
MTTR ali **é** o intervalo entre scans. M4 é lacuna nesse tenant pelos dois valores.

**Escolhas de método que o resumo não declara, e que a skill precisa declarar.** Estados: o
coletor calcula só sobre `FIXED`; incluindo `REOPENED` a média de High cai de 60,39 para 49,66
dias. Manter só `FIXED` — um finding reaberto não foi corrigido — e declarar a exclusão com a
contagem. Percentil: `p90` de Critical é 101,43 interpolado e 92,91 por posição mais próxima;
usar interpolado e nomear o método.

**`severidade_modificada`** vem de `severity_modification_type`, ausente na API de Exposure
Management: é a única medição direta de recast e aceitação que o assessment alcança. Na coleta do
sandbox as 4 278 linhas vieram `NONE` — nenhuma severidade distorcida por exceção. Havendo linhas
diferentes de `NONE`, contar por severidade e declarar em S3, P1, P2 e M4.

**Divergência de filtro: ler `filtros_divergiram`**, nunca comparar `filtros_pedidos` com
`filtros_aplicados_pelo_job`. A API normaliza a severidade e devolve todos os filtros de data com
valor 0, então a comparação literal acusa divergência em toda execução.

**M4 e M1/M2 medem coisas diferentes, e as duas entram.** MTTR pergunta quanto tempo se leva para
fechar; cadência pergunta se se está olhando. Um cliente pode ter MTTR excelente sobre uma amostra
minúscula porque quase não avalia — é o cruzamento de M4 com M1 que revela isso, e o relatório
deve fazer esse cruzamento em texto quando M4 pontuar Advanced ou acima com M1 em Ad Hoc.

**Sobre M1, corrigido em 2026-09-03 durante a execução de aceitação.** A fórmula anterior era
"mediana do intervalo entre runs `completed` consecutivos", e está errada: um scan relançado
minutos depois é a **mesma** avaliação, não um novo ciclo de cadência. No sandbox, os 12 runs do
scan recorrente incluem quatro pares no mesmo dia, e a mediana dos 11 intervalos crus deu
**1,42 dia** — número sem sentido para um tenant que avaliou em 9 dias ao longo de 12 meses.
Colapsando os runs em **dias distintos de avaliação** (9 dias), os intervalos são
140, 40, 2, 89, 1, 1, 85 e 1 dias, e a mediana é **21 dias** — Standardized em vez de Optimized,
dois estágios de diferença. `CONFIG.cortes.colapsar_runs_do_mesmo_dia` controla isso e vem `true`;
desligar exige declarar no relatório.

M2 não muda: o maior intervalo é o mesmo com ou sem colapso.

**Sobre o censo de D4 e M3, corrigido em 2026-09-03.** O plano original era censo via
`plugins_search_plugins` em vez de amostra. **Não é alcançável:** o tool aceita `query` (palavra-
chave) e `cve`, não uma lista de IDs de plugin, então não há como pedir o `Scan Type` e o
`Published` dos plugins que aparecem nos findings do tenant. D4 e M3 saem da amostra
estratificada, e o relatório declara o tamanho, a alocação e o intervalo de confiança.
`CONFIG.amostra_plugins.censo_d4_m3` agora vem `false`.

**Sobre M3.** `Published` é a data de publicação do plugin de detecção, não a do patch do
fabricante — diferença de dias. Rotular no relatório como proxy declarado. O campo
`patch_publication_date` da API não é alcançável pelo MCP.

---

## Mapeamento para os oito critérios oficiais

A skill reporta cada indicador vinculado a um dos oito critérios da avaliação oficial da Tenable,
para que o resultado seja comparável a uma avaliação que o cliente já tenha respondido.

| # | Critério oficial Tenable | Indicadores da skill |
|---|---|---|
| 1 | Asset Visibility | S1, D1, D2, D3 |
| 2 | Prioritization | P1, P3 |
| 3 | Risk Detection | D4, V1, V2, V4 |
| 4 | People \| Process | S2, S3, S4 |
| 5 | Data Consolidation | D2 |
| 6 | Mobilization | M1, M2, M3, M4 |
| 7 | Scoring Methodology | P2 |
| 8 | Metrics \| Reporting | V3, M2 |

Fonte dos oito critérios: Tenable Exposure Management Maturity Assessment,
https://assess.tenable.com/exposure-management-maturity-assessment

---

## Faixas oficiais, fixas, não configuráveis

Vão citadas no relatório e não entram no bloco de limiares.

| Métrica | Escala | Faixas oficiais |
|---|---|---|
| CES | 0–1000 | High 650–1000 · Medium 350–649 · Low 0–349 |
| AES | 0–1000 | High 650–1000 · Medium 350–649 · Low 0–349 |
| ACR | 1–10 | Critical 9–10 · High 7–8 · Medium 4–6 · Low 1–3 |
| VPR | 0,1–10,0 | Critical 9,0–10,0 · High 7,0–8,9 · Medium 4,0–6,9 · Low 0,1–3,9 |

Observações oficiais a reproduzir: ativos com mais de 90 dias sem observação são excluídos do
cálculo do CES, e o AES não é calculado para ativo não licenciado.
Fonte: https://docs.tenable.com/exposure-management/Content/getting-started/metrics.htm

---

## O que NÃO é oficial

**Nenhum material oficial da Tenable publica limiar numérico por estágio de maturidade.** O
Exposure Management Maturity Model é qualitativo: descreve capacidades por estágio. A avaliação
oficial classifica por respostas declaratórias em oito critérios, sem faixas de score divulgadas.

Portanto todos os cortes deste arquivo, exceto os de V2 e os derivados da CISA BOD 26-04, são
**critério da skill**. O relatório é obrigado a rotulá-los assim, indicador por indicador. Cravar
um percentual como se fosse critério Tenable seria imprecisão.
