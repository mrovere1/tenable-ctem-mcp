# Contrato das tools

Onze tools no total. Este arquivo cresce a cada marco; hoje documenta o que existe.

## Envelope de retorno

Todo indicador, em toda tool, devolve este envelope. Nunca desvia.

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

Se a consulta falhar, `valor` é `null`, `lacuna` é `true` e `causa` vem preenchida.
**Número parcial silencioso é proibido.**

`veredito_preflight` assume: `ok`, `aplicado`, `ignorado`, `indeterminado`, `corpus_vazio`,
`nao_aplicavel`.

## Erros

Erro nunca é stack trace nem exceção crua. Formato:

```json
{"erro": "falha_de_coleta", "causa": "credencial_invalida",
 "detalhe": "...", "lacuna": true, "coletado_em_utc": "..."}
```

Filtro negado pela deny-list:

```json
{"erro": "filtro_negado", "regra": "filters_precisa_ser_array_json",
 "detalhe": "...", "prova": "...", "lacuna": true}
```

A `prova` é a medição que sustenta a regra — quem lê o erro vê por que o filtro foi recusado.

---

## `ctem_discover_tenant(usar_cache: bool = True)`  — M0

Retrato do tenant numa chamada. Substitui ~10 chamadas da Fase A do Passo 0 da skill.

**Devolve:**

| Campo | Conteúdo |
|---|---|
| `tags` | `quantidade` de categorias e, em `categorias`, os valores de cada uma |
| `ativos` | `total` e `por_asset_class` |
| `exposure_classes` | total por classe: `VM`, `WAS`, `CLOUD`, `IDENTITY`, `OT`, `AI`, `CODE` |
| `scans` | `total_scans`, `com_historico`, e por scan: `runs` e `runs_completed` |
| `agentes` | `total`, `ativos`, `por_status` |
| `servido_do_cache` | `true` quando veio do cache de TTL curto |

**Atenção:** `asset_class` **não** é `exposure_classes`. Um tenant pode ter ativos com
`asset_class = IDENTITY` e `exposure_classes = IDENTITY` em zero — os ativos de identidade estão no
inventário sem carregar achados de Identity Exposure. D2 usa `exposure_classes`.

**Cache:** obrigatório, TTL curto. `usar_cache=False` força coleta nova.

**Não colapsa runs.** O colapso em dias distintos de avaliação é trabalho de `scan_cadence` (M4), e
é o que separa mediana de 1,42 dia de mediana de 21 dias em M1.

## `ctem_diagnostico()`  — M0

Diz se o servidor fala com o tenant, sem coletar indicador. Separa três causas que se parecem no
cliente: **credencial ausente**, **credencial inválida** e **TLS interceptado por proxy**.
Nunca imprime a chave, nem parte dela.

---

## Endpoints usados

Confirmados em developer.tenable.com em 2026-09-03.

| Uso | Endpoint |
|---|---|
| buscar ativos | `POST /api/v1/t1/inventory/assets/search` *(beta)* |
| buscar findings | `POST /api/v1/t1/inventory/findings/search` *(beta)* |
| buscar tags | `POST /api/v1/t1/tags/search` *(beta)* |
| categorias e valores de tag | `GET /tags/categories` · `GET /tags/values` |
| scans e histórico | `GET /scans` · `GET /scans/{scan_id}/history` |
| agentes | `GET /scanners/null/agents` |
| export de MTTR | `POST /vulns/export` |

Os endpoints de Exposure Management estão marcados como **beta** na documentação da Tenable: a
estrutura da resposta pode mudar. A leitura no servidor é defensiva e não presume formato.

O corpo de `/api/v1/t1/inventory/assets/search` é `{"query": {...}, "filters": [...]}`, com
paginação em `limit` e `offset` de query string — **nunca exposta ao chamador**. Cada cláusula de
`filters` é `{"property", "operator", "value": [...]}`, com `value` sempre array de strings.
