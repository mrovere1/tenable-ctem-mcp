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

## `ctem_scoping(mapeamento, indicadores=None)`  — M1

Estágio 1: **S1, S2, S3, S4**.

`mapeamento` é obrigatório e explícito — o servidor **não adivinha** o nome da categoria de tag:

```json
{"categoria_criticidade": "Criticidade", "categoria_owner": "Owner"}
```

Sem ele, S2 e S3 viram lacuna e a causa lista as categorias que existem, para o consultor apontar a
certa. `sugerir_categorias()` propõe candidatas por pista de nome, mas **não decide** — no sandbox
sugere `Owner` e `Team` para owner, e a escolha continua do operador.

| ID | Fórmula | Filtro literal |
|---|---|---|
| S1 | `assets(tag_count ≥ 1) / assets(total)` | `[{"property":"tag_count","operator":">=","value":["1"]}]` |
| S2 | assets com valor da categoria de criticidade / total | `[{"property":"tag_names","operator":"=","value":[<valores>]}]` |
| S3 | idem, categoria de owner | idem |
| S4 | existe categoria de criticidade **e** ≥1 ativo com `acr ≥ 9` | `[{"property":"acr","operator":">=","value":["9"]}]` |

**S4 é informativo e não pontua estágio.** A API não expõe se o ACR foi ajustado por humano ou se é
o valor automático da Tenable: S4 mede *declaração* de contexto, não *curadoria*. A lacuna
estrutural vai declarada no `contexto`.

> **Achado da validação de 2026-09-03.** `tag_names` guarda o **valor** da tag, não `Categoria:Valor`.
> `contains "Criticidade"` devolve **0**; `= ["Alta","Baixa","Crown Jewel","Média"]` devolve **8**.
> Um array de valores tem semântica de OU e já deduplica o ativo que carrega duas tags da mesma
> categoria — no sandbox, 1+0+2+6 = 9 tags mas **8** ativos distintos.

## `ctem_discovery(indicadores=None, superficies_licenciadas=None, corte_vpr_amostra=7.0, n_amostra=30)`  — M1

Estágio 2: **D1, D2, D3, D4**.

| ID | Fórmula | Nota |
|---|---|---|
| D1 | `hoje − time_start do run mais recente` · invertido | fonte é `scan_history`. **Nunca** filtro de data em findings (ignorado) nem `age` (é recência, não idade) |
| D2 | superfícies licenciadas cobertas / licenciadas | **razão percentual**, não contagem. `asset_class` não é `exposure_classes` |
| D3 | agentes ativos / `assets(asset_class = DEVICE)` | denominador é DEVICE — IDENTITY, ACCOUNT e GROUP não têm software instalado |
| D4 | plugins com `Scan Type = local` / amostra | amostra estratificada, alocação proporcional, IC de Wilson no `contexto` |

`indicadores=["D1","D3"]` evita as chamadas de plugin que D4 exigiria — é o que torna o custo de uma
reavaliação parcial proporcional ao pedido.

**D4 é proxy declarado:** plugin de tipo `local` só retorna resultado com credencial válida ou
agente. Não é leitura de status de credencial — e o parâmetro `authenticated` de workbenches é
comprovadamente ignorado.

## `plugin_details_batch(plugin_ids)`  — M1

**O maior ganho de token do projeto.** Devolve exatamente cinco campos por plugin: `scan_type`,
`published`, `exploit_available`, `exploitability`, `cisa_known_exploited`.

Medido no sandbox com 20 plugins da amostra:

| | chars | ~tokens |
|---|---|---|
| detalhe completo (97 atributos por plugin) | 127.812 | ~31.900 |
| `plugin_details_batch` | 3.615 | ~900 |
| **redução** | | **97,2%** |

**Não exponha campos extras aqui.** A economia depende disso, e é regra fechada.

Plugin que falhar entra em `lacunas` com a causa, e os outros continuam: resultado parcial
**declarado** é legítimo, parcial silencioso não é.

## `plugin_census(severity="critical")`  — M1

Quadro de amostragem numa chamada: plugin, contagem de detecções, VPR e família. Em cache por TTL
curto. É o denominador de D4, M3, V1 e V2. No sandbox: **121 plugins críticos, 706 detecções**.

Não existe censo por busca — `plugins_search_plugins` aceita palavra-chave e CVE, não lista de IDs.

### Amostragem, quando D4/V1/V2 usam amostra

Três regras, e a ordem importa:

1. **Alocação proporcional à população**, medida antes de amostrar. O erro a não repetir: na
   primeira execução real a amostra foi 60/40 por decisão de desenho enquanto a população era 65/35.
2. **Piso de 4 no estrato B.** Ele não existe para estimar taxa, existe para *encontrar casos*.
   Quando o piso é acionado o estrato fica sobre-representado de propósito.
3. **Ponderação por população** em toda taxa, com base declarada (`por_deteccao` ou `por_plugin`).
   Nunca calcular sobre a amostra inteira misturada.

O IC 95% de Wilson vai no `contexto` por estrato e para a amostra inteira. Larguras medidas:
n=10 → 53 pontos · n=20 → 40 · n=30 → 34 · n=50 → 27. **Com n=10 o intervalo não separa estágios.**

A amostra usa semente fixa (`20260903`): sem reprodutibilidade não existe golden test.

---

## Endpoints usados

Confirmados em developer.tenable.com em 2026-09-03.

| Uso | Endpoint |
|---|---|
| buscar ativos | `POST /api/v1/t1/inventory/assets/search` *(beta)* |
| buscar findings | `POST /api/v1/t1/inventory/findings/search` *(beta)* |
| buscar tags | `POST /api/v1/t1/tags/search` *(beta)* |
| propriedades de filtro | `GET /api/v1/t1/inventory/assets/properties` *(beta)* |
| censo de plugins | `GET /workbenches/vulnerabilities` com `filter.0.*` |
| detalhe de plugin | `GET /plugins/plugin/{id}` |
| categorias e valores de tag | `GET /tags/categories` · `GET /tags/values` |
| scans e histórico | `GET /scans` · `GET /scans/{scan_id}/history` |
| agentes | `GET /scanners/null/agents` |
| export de MTTR | `POST /vulns/export` |

Os endpoints de Exposure Management estão marcados como **beta** na documentação da Tenable: a
estrutura da resposta pode mudar. A leitura no servidor é defensiva e não presume formato.

O corpo de `/api/v1/t1/inventory/assets/search` é `{"query": {...}, "filters": [...]}`, com
paginação em `limit` e `offset` de query string — **nunca exposta ao chamador**. Cada cláusula de
`filters` é `{"property", "operator", "value": [...]}`, com `value` sempre array de strings.
