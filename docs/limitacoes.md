# Limitações — o que a API não entrega, com prova

Cada linha aqui foi medida contra o tenant de laboratório, não presumida.
Fonte: `_docs/matriz-confianca-filtros-mcp.md`.

## Filtros aceitos e silenciosamente ignorados

O pior tipo de falha: a consulta parece filtrada, devolve o total do corpus inteiro, e o número sobe
para o relatório como se fosse resultado do filtro. **Não há sinal de que aconteceu.**

| Filtro | Prova |
|---|---|
| datas em findings (`last_updated`, `first_observed_at`, todo operador e formato) | `older than 3650d` devolveu 1840, o corpus inteiro, igual a `within last 1d`. Revalidado em 2026-09-03 com 50 `FIXED` |
| `authenticated` em workbenches | `true` → 20 e `false` → 20, resultados idênticos |
| `exploitable` em workbenches | `true` → 20, incluindo Mozilla Firefox SEoL e checagem de Spectre, que não têm exploit público |
| `filters` recebido como string | `"tag_count >= 1"` → 30 ativos do corpus; como array JSON → 9 |

O servidor rejeita todos eles antes de a requisição sair.

## Operador que a propriedade lista e não suporta

`exists` em `finding_vpr_score` responde **HTTP 400**. O caminho válido é `>= 0.1`, que é aplicado e
monotônico: 0,1 → 4.462 · 7,0 → 1.254 · 9,0 → 586.

## `age` não é idade

`age` filtra por **recência da última observação**, não pela idade do finding. O último scan do
sandbox foi 84 dias antes da coleta, e o corte ficou entre `age=80` (zero) e `age=90` (20) — na data
do último scan, não na data de descoberta, que vai de 2018 a 2026.

**Consequência:** `age` serve para frescor de dado e cobertura de scan. Uma skill que usar `age`
como "dias em aberto" produz número errado.

## O que a API de Exposure Management não tem

`last_fixed`, `time_taken_to_fix` e `severity_modification_type` **não existem** na API de Exposure
Management. Não é wrapper faltando: são campos da API de Vulnerability Management, alcançáveis só
por `POST /vulns/export`. É a razão de `mttr_collect` existir.

## Censo de plugins não é alcançável por busca

`plugins_search_plugins` aceita palavra-chave e CVE, **não** lista de IDs de plugin. Não há como
pedir `Scan Type` e `Published` para o conjunto de plugins que aparece nos findings do tenant.
D4 e M3 saem de amostra estratificada, com tamanho, alocação e intervalo de confiança declarados.

O quadro de amostragem certo é `workbenches_list_vulnerabilities(severity=...)`, que devolve plugin,
contagem de detecções, VPR e família de todos os plugins daquela severidade numa chamada — 121
plugins críticos no sandbox.

## Propagação de índice após escrita de tag

O índice do inventário demora a refletir uma escrita. Segundos depois de aplicar uma tag,
a busca por ela retornou vazio enquanto a API de tagging já havia confirmado sucesso; cerca de
quinze minutos depois passou a funcionar.

**Nunca validar escrita por leitura imediata do índice**, e nunca concluir que um filtro está
quebrado com base em leitura feita logo após uma escrita.
