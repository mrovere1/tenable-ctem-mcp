# Procedimento comum — Pré-voo de filtro e amostragem de plugins no MCP Tenable

Arquivo de referência compartilhado. Uma cópia vive dentro de cada pacote `.skill` que precisa dele,
para que cada skill funcione sozinha depois de baixada do Exchange.

Validado no MCP Tenable em 2026-09-01.

> **Atualizado em 2026-09-04, e em dois pontos o veredito MUDOU.**
>
> **1. O pré-voo virou uma chamada: `ctem_preflight()`.** O servidor executa os pares
> discriminantes ao vivo e devolve a tabela pronta, mais a `deny_list` dos filtros que ele rejeita
> antes de a requisição sair. O procedimento manual da seção 2 continua sendo a *definição* do que
> ele faz — leia para entender, não para executar à mão.
>
> **2. Quatro vereditos deste arquivo valem para o MCP oficial, e não para a API REST direta**, que
> é por onde o servidor fala:
>
> | Aqui | Pela API direta |
> |---|---|
> | filtro de data em findings é ignorado, em todo operador | só os **relativos** (`within last`, `older than`, `newer than`); `<` e `>=` contra data absoluta **funcionam** |
> | `exists` não funciona em `finding_vpr_score` | **funciona** — o HTTP 400 vinha de `value` vazio |
> | `resolvable` — presumir ignorado até prova | **provado** ignorado |
> | `age` é aplicado em workbenches | `age` **não é parâmetro** da API; o nome real é `date_range`, e esse funciona |
>
> **3. A seção 4 (amostragem) só se aplica quando `contexto.modo` for `amostra`.** O censo passou a
> ser alcançável — a conclusão de 4.1 vale para a BUSCA (`plugins_search_plugins` não aceita lista
> de IDs), mas `plugin_details_batch` aceita. Com `modo_plugins: auto`, o servidor faz censo de
> todos os plugins da severidade quando a população cabe em `limite_censo`. **No censo não há
> intervalo de confiança, nem ponderação, nem alocação entre estratos: a taxa é a contagem.**
> As três regras de 4.2 e 4.3 continuam valendo para tenants grandes, onde a amostra volta.

---

## 1. Por que este pré-voo existe

**O MCP aceita filtros que não aplica, e não retorna erro.** A consulta parece filtrada, devolve o
total do corpus inteiro, e a skill apresenta esse número como se fosse o resultado do filtro.

Isso não é dado faltando. É número errado com aparência de certo, sem nenhum sinal de que ocorreu.

Casos comprovados de filtro silenciosamente ignorado:

| Ferramenta | Filtro ignorado | Prova |
|---|---|---|
| `tenable_one_search_findings` | `last_updated`, `first_observed_at` — qualquer operador e formato | `older than 3650d` devolveu os 1840 findings do corpus, igual a `within last 1d` |
| `workbenches_list_vulnerabilities` | `authenticated` | `true` → 20 e `false` → 20, resultados idênticos |
| `workbenches_list_vulnerabilities` | `exploitable` | `true` devolveu todos os 20, incluindo SEoL e checagem de Spectre |
| `tenable_one_search_assets` e `_findings` | **o parâmetro `filters` inteiro, quando não é JSON válido** | `filters="tag_count >= 1"` como texto livre devolveu os 30 ativos do corpus, sem erro. O mesmo filtro como `[{"property":"tag_count","operator":">=","value":["1"]}]` devolveu 9. Confirmado em 2026-09-03 |

**A armadilha do `filters` em texto livre é a mais fácil de cometer**, porque a sintaxe
`tag_count >= 1` é exatamente a que `list_inventory_properties` sugere ao listar operadores. O
parâmetro exige **um array JSON**; qualquer outra coisa é descartada em silêncio e a consulta
volta sem filtro nenhum. O pré-voo pega isso: um filtro que devolve o total do corpus está
ignorado, não é um filtro que "casa com tudo".

Também comprovado em 2026-09-03: o operador **`exists`** existe na lista de operadores de
findings mas responde **HTTP 400** em `finding_vpr_score`. Para contar findings com VPR, usar
`vpr_min="0.1"`, que é aplicado e é monotônico (0,1 → 4.462 · 7,0 → 1.254 · 9,0 → 586).

Filtros comprovadamente aplicados: `state`, `finding_severity`, `vpr_min`,
`finding_cvss3_base_score`, `asset_class`, `tag_count`, `tag` no formato `Categoria:Valor`,
`query_text`, e em workbenches apenas `severity` e `age`.

---

## 2. O pré-voo — executar antes de publicar qualquer número derivado de filtro

Custo: uma consulta extra com `limit=1`, porque só o campo `total` importa.

**2a. Filtro de valor (numérico, enum, texto):**

1. Rodar a consulta **sem** o filtro. Guardar `total_corpus`.
2. Rodar **com** o filtro. Guardar `total_filtrado`.
3. Se `total_filtrado == total_corpus`, tratar o filtro como **ignorado** e o indicador como
   **lacuna**. Não publicar o número.

**2b. Filtro booleano:**

1. Rodar com o valor `true`. Guardar `total_true`.
2. Rodar com o valor `false`. Guardar `total_false`.
3. Se `total_true == total_false`, o filtro é **ignorado**. Indicador vira lacuna.

**2c. Registro obrigatório no relatório**, por indicador:

| O que registrar | Exemplo |
|---|---|
| Filtro literal aplicado | `[{"property":"state","operator":"=","value":["FIXED"]}]` |
| Total do corpus | 1840 |
| Total filtrado | 20 |
| Veredito do pré-voo | aplicado |
| Data e hora da coleta | 2026-09-01 22:13 UTC |

Isso torna o problema visível para quem lê o relatório, e não só para quem escreveu a skill.

---

## 3. Armadilha de propagação de índice

Após escrita de tag, o índice do inventário Tenable One **demora a refletir**. Segundos depois de
aplicar uma tag, `search_assets(tag=...)` retornou vazio enquanto a API de tagging já havia
confirmado sucesso. Cerca de quinze minutos depois passou a funcionar.

Regra: **nunca validar escrita por leitura imediata do índice**, e nunca concluir que o filtro está
quebrado com base em uma leitura feita logo após uma escrita.

---

## 4. Amostragem de plugins — três regras, e a ordem importa

Vários atributos só existem em `plugins_get_plugin_details`, que é **uma chamada por plugin**.
Um tenant pequeno já tem centenas de plugins distintos. Cobrir tudo com essa ferramenta é inviável.

Mas **aumentar o N não é a primeira coisa a fazer.** Uma amostra estratificada maior é uma amostra
enviesada com mais precisão. A ordem correta é: censo onde é barato, ponderação sempre, e só então
N maior — com portão de confiança.

### 4.1 Censo onde é barato: `plugins_search_plugins`

> **Limite comprovado em 2026-09-03.** `plugins_search_plugins` aceita `query` (palavra-chave) e
> `cve`, **não** uma lista de IDs de plugin. Não há como pedir `Scan Type` e `Published` para o
> conjunto de plugins que aparece nos findings do tenant, então **não existe censo** por esse
> caminho para D4 e M3 — eles saem da amostra estratificada, com tamanho, alocação e intervalo de
> confiança declarados. O que serve de censo barato é
> `workbenches_list_vulnerabilities(severity=...)`, que devolve plugin, contagem de detecções, VPR
> e família de todos os plugins daquela severidade numa chamada, e é o quadro de amostragem certo
> para estratificar.

`plugins_search_plugins` devolve, por plugin e em formato compacto — cerca de oito linhas contra
quarenta do detalhe completo:

`Severity`, `Family`, `Sensor`, `Supported Sensors`, **`Scan Type`**, **`Published`**, `Modified`,
`Synopsis`.

Isso cobre **D4** (`Scan Type = local`) e **M3** (`Published`) **sem amostragem nenhuma**. Esses dois
indicadores devem ser censo, não amostra.

Como fazer o censo em poucas chamadas: a busca aceita texto livre e devolve 50 resultados por
página, então consultar por **família de produto** e cruzar os IDs retornados contra a lista de
plugins do tenant obtida em `workbenches_list_vulnerabilities`. Um punhado de consultas cobre a
maior parte de um tenant típico, porque o backlog se concentra em poucas famílias — boletins
Windows, navegador, Java, Office, e o resto é cauda. Para os plugins que sobrarem sem cobertura,
consultar por número de KB ou por nome exato, uma chamada cada.

**Declarar a cobertura do censo:** quantos dos N plugins do tenant tiveram `Scan Type` e `Published`
resolvidos. Se ficar abaixo de 80%, tratar D4 e M3 como amostra e aplicar 4.2 e 4.3.

**O que `plugins_search_plugins` NÃO devolve:** `Exploit Available`, `Exploitability` e as
`Cross References` com a data do CISA KEV. Esses só existem no detalhe completo. Portanto **V1 e V2
continuam por amostra** — e é para eles que valem as duas regras seguintes.

### 4.2 Alocação proporcional e ponderação — obrigatórias, e de graça

**Erro a não repetir:** na primeira execução real a amostra foi alocada 60% no estrato A e 40% no B
por decisão de desenho, enquanto na população A era 65% e B era 35%. Deu quase certo por
coincidência — o estrato B ficou sobre-representado por fator 1,14 e o viés no resultado foi de
cerca de 5 pontos percentuais. Num tenant onde o estrato B seja 10% da população, uma alocação de
40% enviesaria gravemente.

**Alocação:** dimensionar cada estrato pela sua fatia real da população, medida antes de amostrar:

```
share_A = plugins acima do corte do cliente / total de plugins
n_A     = round(N × share_A)   ·   n_B = N − n_A
```

**Piso do estrato B:** mínimo de 4 plugins, mesmo que a proporção dê menos. O estrato B não existe
para estimar taxa, existe para **encontrar casos** de subpriorizado; com menos de 4 ele perde a
função. Quando o piso for acionado, o estrato fica sobre-representado de propósito — e aí a
ponderação de 4.2 é o que impede que isso contamine as taxas.

**Ponderação de toda taxa e toda mediana:** nunca calcular sobre a amostra inteira misturada.
Estimar dentro de cada estrato e combinar pelos pesos da população:

```
taxa_estimada = (taxa_no_estrato_A × share_A) + (taxa_no_estrato_B × share_B)
```

Usar `share` por **detecção** (soma de `Count`) e não por contagem de plugins, quando o indicador
fala de volume de backlog. Reportar qual base foi usada.

### 4.3 Portão de confiança da amostra — o que responde "10% é suficiente?"

Não decidir por regra fixa. **Deixar o dado dizer.**

Para cada indicador estimado por amostra, calcular o intervalo de confiança de 95% da proporção
pelo método de Wilson e confrontá-lo com os cortes do indicador:

| Situação | Comportamento |
|---|---|
| O intervalo inteiro cai dentro de **um** estágio | Classificar. A amostra é suficiente para este indicador neste tenant |
| O intervalo atravessa um corte | **Ampliar a amostra em blocos de 10** e recalcular |
| Atingiu o teto de orçamento e o intervalo ainda atravessa um corte | **Não classificar.** Reportar a faixa e declarar que a amostra não distingue os dois estágios |

Larguras medidas na prática, para a taxa de presença no KEV:

| N | Largura do IC 95% |
|---|---|
| 10 | 50 pontos percentuais |
| 20 | 37 pontos |
| 30 | 31 pontos |
| 50 | 25 pontos |

Com N=10 o intervalo tem 50 pontos de largura — inútil para separar estágios de uma taxa. **Por isso
o default de `sampleN` sobe para 30, e o teto para 60.**

**Nuance que o portão captura e uma regra fixa não:** um valor muito distante do corte mais próximo
classifica com segurança mesmo com amostra pequena. Na primeira execução real a mediana de dias no
KEV deu 1.100 dias contra um corte mais permissivo de 180 — o menor valor observado na amostra foi
629 dias, então nenhum N maior mudaria o estágio, só a precisão do número reportado. O portão deixa
esse indicador passar e concentra o esforço onde a decisão está apertada.

---

## 4.4 Identidade de ativo — não inferir duplicidade por nome

**Erro cometido na primeira execução real:** seis ativos `DEVICE` com o mesmo NetBIOS name foram
reportados como duplicidade de inventário, inflando supostamente os denominadores de S1, S2 e S3.
**Estava errado.**

Cada um dos seis tinha **Tenable asset ID distinto, agente Nessus próprio com UUID distinto e IP
distinto**. São seis máquinas reais com nome mal padronizado, não seis registros do mesmo ativo. O
denominador estava correto e nenhum indicador mudou.

Regras:

1. **Nome igual não é duplicidade.** Nunca inferir duplicidade de ativo a partir de hostname,
   NetBIOS name ou FQDN.
2. **Agente instalado é identidade.** Um ativo com agente Nessus é unicamente identificado pelo
   agente. Conferir em `agent_list_agents`, campo `Asset UUID`: se cada ativo suspeito aparece com
   agente próprio, são ativos distintos. Ponto final.
3. **Se realmente suspeitar de duplicidade**, o teste é conjunto: mesmo `Asset UUID` em fontes
   diferentes, ou ausência de agente somada a IP e MAC coincidentes. Nome nunca entra sozinho.
4. Nome repetido continua digno de nota, mas como **achado de padronização de nomenclatura**, não
   como erro de inventário — e sem qualquer efeito sobre denominadores.

---

## 5. O que `plugins_get_plugin_details` entrega

Campos úteis, confirmados no retorno real:

| Campo | Uso |
|---|---|
| `Scan Type` | `local` ou `remote`. Plugin `local` só retorna com credencial válida ou agente — é o proxy correto para scan autenticado |
| `Published` | data de publicação do plugin. Para plugin de checagem de patch, proxy da disponibilidade da correção |
| `Modified` | última revisão do plugin |
| `Exploit Available` | `True` ou `False` |
| `Exploitability` | `Exploits are available`, `No exploit is required`, `No known exploits are available` |
| `Cross References` | inclui **`CISA-KNOWN-EXPLOITED: AAAA/MM/DD`**, com a data de entrada no KEV. Também `IAVA`, `MSFT`, `MSKB` |
| `VPR Score` | com a faixa em texto |
| `CVSS v2 Base`, `CVSS v3 Base` e vetores | scoring |
| `CVEs` | lista, com contagem total |
| `Family`, `Filename`, `Solution`, `Synopsis` | contexto e ação |

`plugin_type` da chamada deve casar com o produto que publica o plugin, senão retorna 404. Para
plugins Nessus, o default `nessus` funciona.
