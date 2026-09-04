# Limitações — o que a API não entrega, com prova

Cada linha aqui foi medida contra o tenant de laboratório, não presumida.
Fonte: `_docs/matriz-confianca-filtros-mcp.md`.

> **Dois caminhos, dois conjuntos de vereditos.** A matriz de origem foi medida **através do MCP
> oficial da Tenable**; este servidor fala **direto com a API REST**, e em quatro pontos o
> comportamento é outro. As seções abaixo trazem a medição do caminho antigo, marcada como tal, e
> a seção **"Quatro vereditos da matriz que mudam na API direta"**, no fim deste arquivo, é a que
> vale para este servidor. Em caso de conflito entre as duas, **a de baixo manda** — e
> `ctem_preflight()` reexecuta tudo contra o tenant do momento, que é a autoridade final.

## Filtros aceitos e silenciosamente ignorados

O pior tipo de falha: a consulta parece filtrada, devolve o total do corpus inteiro, e o número sobe
para o relatório como se fosse resultado do filtro. **Não há sinal de que aconteceu.**

| Filtro | Prova |
|---|---|
| datas em findings — **apenas os operadores relativos**, `within last` / `older than` / `newer than` (ver correção nº 1 no fim) | `older than 3650d` devolveu 1840, o corpus inteiro, igual a `within last 1d`. Revalidado em 2026-09-03 com 50 `FIXED` |
| `authenticated` em workbenches | `true` → 20 e `false` → 20, resultados idênticos |
| `exploitable` em workbenches | `true` → 20, incluindo Mozilla Firefox SEoL e checagem de Spectre, que não têm exploit público |
| `filters` recebido como string | `"tag_count >= 1"` → 30 ativos do corpus; como array JSON → 9 |

O servidor rejeita todos eles antes de a requisição sair.

## Operador que a propriedade lista e não suporta

**Medido via MCP oficial — corrigido na API direta (ver correção nº 2 no fim).** Ali, `exists` em
`finding_vpr_score` responde **HTTP 400**. Na API direta o 400 vem de `value` vazio, não do
operador, e `exists` funciona.

O caminho `>= 0.1` vale nos dois: é aplicado e monotônico — 0,1 → 4.462 · 7,0 → 1.254 · 9,0 → 586.

## `age` não é idade

**Medido via MCP oficial — na API direta `age` nem sequer é parâmetro (ver correção nº 4 no fim);
o nome real é `date_range`.** No caminho antigo, `age` filtra por **recência da última observação**,
não pela idade do finding. O último scan do
sandbox foi 84 dias antes da coleta, e o corte ficou entre `age=80` (zero) e `age=90` (20) — na data
do último scan, não na data de descoberta, que vai de 2018 a 2026.

**Consequência:** `age` serve para frescor de dado e cobertura de scan. Uma skill que usar `age`
como "dias em aberto" produz número errado.

## O que a API de Exposure Management não tem

`last_fixed`, `time_taken_to_fix` e `severity_modification_type` **não existem** na API de Exposure
Management. Não é wrapper faltando: são campos da API de Vulnerability Management, alcançáveis só
por `POST /vulns/export`. É a razão de `mttr_collect` existir.

## Censo de plugins não é alcançável **por busca** — mas é por lote

`plugins_search_plugins` aceita palavra-chave e CVE, **não** lista de IDs de plugin. Foi por isso
que `censo_d4_m3` virou `false` em 2026-09-03.

**Essa conclusão vale para a busca, não para o censo.** `plugin_details_batch` recebe lista de IDs,
e o quadro de amostragem sai de `GET /workbenches/vulnerabilities`, que devolve todos os plugins da
severidade numa chamada — 121 críticos no sandbox. Juntando os dois, **o censo é alcançável**: 121
chamadas, 64 s, ~5.400 tokens.

Por isso `modo_plugins` vem `auto`, que faz censo quando a população cabe em `limite_censo` e cai
para amostra acima disso. O censo elimina o intervalo de confiança, a base de ponderação e o viés de
alocação — ver `docs/tools.md`.

**A amostragem continua existindo**, e não é legado: um tenant grande pode ter milhares de plugins
críticos, e a 528 ms por plugin mil plugins são nove minutos.

## Propagação de índice após escrita de tag

O índice do inventário demora a refletir uma escrita. Segundos depois de aplicar uma tag,
a busca por ela retornou vazio enquanto a API de tagging já havia confirmado sucesso; cerca de
quinze minutos depois passou a funcionar.

**Nunca validar escrita por leitura imediata do índice**, e nunca concluir que um filtro está
quebrado com base em leitura feita logo após uma escrita.

---

## O que a API direta alcança e o MCP oficial não

Medido em 2026-09-03, ao portar as consultas para a API REST. **Nenhum destes itens muda a fórmula
de indicador por conta própria** — cada mudança é decisão da skill, e está listada aqui para ser
decidida, não aplicada em silêncio.

| Item | Status pelo MCP oficial | Status pela API direta |
|---|---|---|
| `patch_publication_date` | "não alcançável" | **disponível** em `GET /plugins/plugin/{id}` |

**Por que importa.** M3 mede "mediana da idade da correção disponível" e hoje usa `Published` — a
data de publicação do *plugin de detecção* — como **proxy declarado**, porque a data do patch do
fabricante era inalcançável. Ela não é mais.

No sandbox as duas datas coincidem na maioria dos plugins da amostra, mas não em todos: o plugin
294870 tem `Published = 2026/01/21` e `patch_publication_date = 2026/01/20`.

**Não foi aplicado.** `plugin_details_batch` expõe cinco campos, e isso é regra fechada do projeto
por causa da economia de token. Trocar o proxy de M3 pelo dado real é uma decisão da skill, e custa
um campo a mais no lote.

---

## Indicadores que dependem da amostra não podem ser reproduzidos por número

**V1 e V2 não têm golden test contra o valor publicado no documento de execução**, e a razão é do
método, não do servidor: os dois são estimados sobre uma amostra estratificada, e a amostra daquela
execução não é recuperável.

Investigando a divergência, apareceu uma inconsistência no próprio documento. Ele publica
**V1 = 59,6%** com a amostra dele (estrato A 11/12, estrato B 1/8) e narra que a população era
**65/35**. Esses dois fatos não fecham:

| Reconstrução | Resultado |
|---|---|
| `share_A = 0,65`, ponderado por plugin | **64,0%** |
| `share_A = 0,595`, ponderado por plugin | **59,6%** ✅ |
| `share_A = 0,595`, ponderado por detecção | 62,7% |

O número publicado só se reconstrói com **ponderação por plugin** e a fatia de população de 0,595 —
que é a medida hoje, não a narrada. Duas consequências:

1. **A base de pesos daquela execução foi `por_plugin`**, e não o `por_deteccao` que o bloco de
   configuração da skill traz como default. A escolha muda o número: na mesma amostra de n=20 do
   sandbox, V1 dá **59,3%** por detecção e **54,6%** por plugin.
2. **Taxa ponderada sem base declarada não é verificável.** Por isso `ctem_validation` e
   `ctem_discovery` aceitam `ponderar` e devolvem `base_dos_pesos` no contexto.

O que o repositório testa é o **método**, sobre a fixture, com semente fixa — reprodutível entre
execuções e auditável.

## Contagens de VPR flutuam; as de CVSS e de estado não

Comparando a coleta de 2026-09-03 com a do mesmo dia registrada no documento:

| Medida | Documento | Medido | |
|---|---|---|---|
| corpus · ACTIVE · RESURFACED · FIXED | 5.486 · 5.425 · 11 · 50 | idênticos | estável |
| CVSS3 ≥ 7 | 3.377 | 3.377 | estável |
| CVSS3 ≥ 7 **e** VPR ≥ 0,1 | 3.314 | 3.314 | estável |
| VPR ≥ 0,1 | 4.462 | 4.462 | estável |
| **VPR ≥ 9** | 586 | **579** | flutua |
| **VPR ≥ 7** | 1.254 | **1.261** | flutua |
| **interseção CVSS≥7 ∧ VPR≥7** | 1.209 | **1.210** | flutua |

**Causa:** o VPR é recalculado pela Tenable a partir de atividade de ameaça, e findings atravessam
o corte nos dois sentidos. Tudo que não depende de um limiar de VPR bateu exato.

**Consequência para os testes:** contagem de VPR num limiar não serve de golden test contra dado ao
vivo — só contra a fixture. O que se testa ao vivo é a **monotonicidade** (0,1 > 7,0 > 9,0), que é
o que prova que o filtro está sendo aplicado.

**Consequência para o assessment:** P1 continuou 100% e a identidade de soma continuou fechando
(87 + 492 = 579), então o indicador não mudou. Vale declarar a data da coleta junto do número de
backlog crítico, porque ele não é reproduzível uma semana depois.

---

## Quatro vereditos da matriz que mudam na API direta

`_docs/matriz-confianca-filtros-mcp.md` foi medida **através do MCP oficial**. Este servidor fala
direto com a API REST, e ali quatro vereditos são outros. **A matriz não está errada** — ela
descreve o caminho dela. Rodar `ctem_preflight()` reexecuta tudo e é a fonte para este caminho.

1. **Filtro de data em findings não é ignorado em bloco.** Os operadores relativos (`within last`,
   `older than`, `newer than`) são ignorados; os de comparação (`<`, `>=`) são aplicados.
   *Prova:* `older than 3650d` → 50 e `within last 1d` → 50, mutuamente exclusivos e ambos com o
   corpus inteiro; mas `< 2020-01-01` → 0 e `>= 2020-01-01` → 50, que somam 50.
2. **`exists` em `finding_vpr_score` funciona.** O HTTP 400 vem de `value` vazio, e a mensagem é
   *"Missing value in filter"*. *Prova:* `exists` → 4.462 e `not exists` → 1.024, somando 5.486.
3. **`resolvable` está provado ignorado**, e não apenas presumido: `true` → 121, `false` → 121.
4. **`age` não é parâmetro desta API.** O nome real é `date_range`, e ele é aplicado
   (1 → 17, 30 → 118, 90 → 121). `age` é descartado em silêncio — o pior caso.

**Isto não reabre MTTR.** `last_fixed` e `time_taken_to_fix` continuam ausentes das 44 propriedades
de findings da API de Exposure Management. `mttr_collect` por `POST /vulns/export` segue sendo o
único caminho.
