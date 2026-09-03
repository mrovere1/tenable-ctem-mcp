# Matriz de confiança dos filtros do MCP Tenable

Testado no tenant sandbox em 2026-09-01. Corpus de referência: **1840 findings**, 20 em `FIXED`,
98 críticos em workbenches, 20 low em workbenches.

## Por que este documento é o mais importante do projeto

O MCP **aceita filtros que não aplica, e não retorna erro.** A consulta parece filtrada, devolve o
total do corpus inteiro, e a skill apresenta esse número como se fosse o resultado do filtro.

Isso não é dado faltando — é **número errado com aparência de certo**. É a falha mais grave possível
diante da regra de 98% do projeto, porque não há sinal de que aconteceu.

Regra que passa a valer para toda skill: **filtro não testado é filtro não confiável.** Antes de usar
um filtro que não está na tabela verde abaixo, provar com um teste discriminante.

---

## 1. O teste discriminante

Não basta ver se a consulta retorna resultado. É preciso montar duas consultas **mutuamente
exclusivas** e conferir se os totais somam o corpus. Se as duas devolverem o total inteiro, o filtro
está sendo ignorado.

Exemplo real que expôs o problema:

| Consulta | Total esperado | Total retornado |
|---|---|---|
| `state=FIXED` + `last_updated within last 1d` | ≤ 20 | **20** |
| `state=FIXED` + `last_updated older than 3650d` | 0 | **20** |

As duas não podem estar certas ao mesmo tempo. O filtro de data foi descartado.

---

## 2. Verde — filtros comprovadamente aplicados

| Ferramenta | Filtro | Prova |
|---|---|---|
| `tenable_one_search_findings` | `state` | `state=FIXED` → 20 de 1840 |
| `tenable_one_search_findings` | `finding_severity` | `state=FIXED` + `CRITICAL` → 1 |
| `tenable_one_search_findings` | `vpr_min` | `vpr_min=9.0` → 171 de 1840 |
| `tenable_one_search_findings` | `finding_cvss3_base_score` | `>= 9.0` → 176 de 1840 |
| `tenable_one_search_findings` | **AND de múltiplos filtros** | `state` + `severity` reduziu corretamente |
| `tenable_one_search_assets` | `asset_class` | `DEVICE` → 3 de 24 |
| `tenable_one_search_assets` | `tag_count` | `>= 1` → 2 de 3 devices |
| `tenable_one_search_assets` | `sort` | `acr:desc` e `aes:desc` ordenaram corretamente |
| `workbenches_list_vulnerabilities` | `severity` | `low` → 20, `critical` → 98 |
| `workbenches_list_vulnerabilities` | `age` | `age=80` → 0, `age=90` → 20 |
| `tagging_create_tag` / `tagging_add_tags_assets` | escrita | retorno de sucesso e categorias criadas |

---

## 3. Vermelho — filtros aceitos e silenciosamente ignorados

| Ferramenta | Filtro | Prova de que é ignorado |
|---|---|---|
| `tenable_one_search_findings` | `last_updated` (todos os operadores e formatos) | `older than 3650d` → 1840, ou seja o corpus inteiro. Testado com `within last`, `older than`, `<` com ISO 8601 e `<` com epoch em milissegundos. Todos devolveram 1840 |
| `tenable_one_search_findings` | `first_observed_at` | `newer than 2026-08-25` → 20 de 20 FIXED, sem redução |
| `workbenches_list_vulnerabilities` | `authenticated` | `true` → 20 e `false` → 20. Resultados idênticos, logo o parâmetro não é aplicado |
| `workbenches_list_vulnerabilities` | `exploitable` | `true` → 20, incluindo `Mozilla Firefox SEoL` e checagem de configuração de Spectre, que não têm exploit público |
| `tenable_one_search_findings` | `exists` com `value: []` | erro 400. Precisa de valor mesmo sendo operador de existência |

**Não testado, presumir ignorado até prova:** `workbenches_list_vulnerabilities.resolvable`.
Está na mesma família dos dois booleanos comprovadamente ignorados.

---

## 4. Semântica do parâmetro `age` — não é o que o nome sugere

`age` filtra por **recência da última observação**, não pela idade do finding.

Prova: o último scan do sandbox foi em `2026-06-09`, 84 dias antes da coleta. O corte ficou entre
`age=80` (zero resultados) e `age=90` (20 resultados) — exatamente na data do último scan, não na
data de descoberta das vulnerabilidades, que vão de 2018 a 2026.

Consequência: `age` serve para medir **frescor de dado e cobertura de scan**. Não serve para aging
de backlog. Uma skill que usar `age` como "dias em aberto" produz número errado.

---

## 5. O que isso elimina do backlog

Correções sobre o que eu havia registrado antes:

| Indicador / skill | Status anterior | Status real |
|---|---|---|
| MTTR em qualquer forma | aproximável por `last_updated` | **inviável.** O campo existe mas os filtros de data são ignorados e os valores não são impressos |
| Aging do backlog por idade | viável via `age` | **inviável.** `age` é recência, não idade |
| Idade do patch (`patch_publication_date`) | KPI de primeira linha proposto | **inviável.** `workbenches_list_vulnerabilities` só expõe 5 parâmetros e este não está entre eles |
| `tenable-exploitability-reality-check` | Direto via workbenches | **inviável hoje.** `exploitable` é ignorado |
| Indicador D4, scan autenticado | proxy via `authenticated` | **inviável.** `authenticated` é ignorado |
| `tenable-eol-software-inventory` | Direto via `unsupported_by_vendor` | **inviável por esse caminho.** Alternativa a testar: plugins SEoL por nome, via `plugins_search_plugins` |

## 6. O que continua de pé, e é bastante

| Indicador | Fonte verificada |
|---|---|
| Delta VPR × CVSS | 171 findings com VPR ≥ 9 contra 176 com CVSS3 ≥ 9. **A skill 1.3 é viável e o dado é bom** |
| Taxa de reincidência | `state = RESURFACED` sobre `RESURFACED + FIXED`. Dado direto |
| Distribuição de backlog por severidade e por VPR | filtros numéricos funcionam |
| Cobertura de contexto de negócio | `tag_count`, categorias e valores de tag |
| Contagem de attack paths por ativo | propriedades `apa_*` |
| Cobertura por superfície | `exposure_classes` |
| Criticidade e exposição por ativo | `acr`, `aes` |
| Frescor de dado e cobertura de scan | `age` em workbenches, com a semântica correta |
| Saúde de agentes e scanners | família `agent_*` e `scan_*` |

---

## 7. Pré-voo obrigatório em toda skill nova

Antes de apresentar qualquer número derivado de filtro:

1. Rodar a consulta sem o filtro e guardar o total do corpus.
2. Rodar com o filtro. Se o total for **idêntico** ao corpus, tratar o filtro como ignorado e o
   indicador como **lacuna** — nunca publicar o número.
3. Para filtro booleano, rodar `true` e `false`. Se os totais forem iguais, o filtro é ignorado.
4. Registrar no relatório, por indicador, o total do corpus, o total filtrado e o filtro literal.
   Isso torna o problema visível para quem lê, e não só para quem escreveu a skill.

Este pré-voo é barato: uma consulta extra com `limit=1`, porque só o campo `total` importa.

---

## Adendo de 2026-09-03 — dois casos novos, e o corpus mudou

**Corpus de referência atualizado:** o tenant passou a ter **5.486 findings** (5.425 `ACTIVE`, 11
`RESURFACED`, 50 `FIXED`) e **30 ativos**, dos quais 8 `DEVICE`. Os totais das tabelas acima são de
2026-09-01, com 1.840 findings — os **vereditos** continuam válidos, os números absolutos não.

### Caso novo 1 — `filters` em texto livre é ignorado em silêncio

| Consulta | Total retornado | Veredito |
|---|---|---|
| `filters="tag_count >= 1"` (string) | **30** — o corpus inteiro de ativos | **ignorado em silêncio** |
| `filters=[{"property":"tag_count","operator":">=","value":["1"]}]` | 9 | aplicado |

**É a armadilha mais fácil de cometer do conjunto**, porque `tag_count >= 1` é exatamente a sintaxe
que `tenable_one_list_inventory_properties` sugere ao listar os operadores de cada propriedade. O
parâmetro exige **array JSON**; qualquer outra coisa é descartada sem erro e a consulta volta sem
filtro nenhum.

Consequência para quem for construir um MCP em cima disso: **rejeitar string no parâmetro
`filters`** é a validação mais barata e mais valiosa do servidor.

### Caso novo 2 — operador `exists` em `finding_vpr_score` responde 400

| Consulta | Resultado |
|---|---|
| `[{"property":"finding_vpr_score","operator":"exists"}]` | **HTTP 400** |
| `[{"property":"finding_vpr_score","operator":">=","value":["0.1"]}]` | **4.462** — aplicado |

O operador `exists` aparece na lista de operadores da propriedade, mas não funciona nela. Para
contar findings com VPR, usar `>= 0.1`, que é aplicado e é monotônico:
0,1 → 4.462 · 7,0 → 1.254 · 9,0 → 586.

Também confirmado como aplicado no array `filters`, com par discriminante:

| Consulta | Total | Veredito |
|---|---|---|
| `finding_cvss3_base_score >= 7.0` | 3.377 | aplicado |
| `finding_cvss3_base_score >= 7.0` **e** `finding_vpr_score >= 0.1` | 3.314 | AND funciona |
| `finding_cvss3_base_score >= 7.0` **e** `finding_vpr_score >= 7.0` | 1.209 | AND funciona |
| `asset_class = DEVICE` | 8 de 30 | aplicado |
| `acr >= 9` | 0 de 30 | aplicado |

### Deny-list para o MCP dedicado

Filtros que **nunca** podem virar número, e que um servidor próprio deve rejeitar com erro
explícito em vez de devolver contagem:

- qualquer filtro de data em `tenable_one_search_findings` (`last_updated`, `first_observed_at`,
  qualquer operador e formato);
- `authenticated` em `workbenches_list_vulnerabilities`;
- `exploitable` em `workbenches_list_vulnerabilities`;
- `filters` recebido como string em vez de array JSON;
- `exists` em `finding_vpr_score`.
