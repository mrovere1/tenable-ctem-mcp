# Pendência: o denominador de assets está errado — medido em 2026-09-08

**Status:** aprovado, **não implementado**. Aguarda a segunda revisão do Exchange nos PRs #154 e
#155. Não mexer no código antes disso.

## O que foi encontrado

O relatório do tenant de produção de 2026-09-08 publicou S1 = **25,3% de ativos com tag**, sobre um
corpus de 104.140. O cliente conferiu contra o console de licenciamento, onde o consumo é de 6.334 assets — 5.884 de
Vulnerability Management e 450 de ASM — e apontou a divergência.

A verificação contra o tenant confirmou: o corpus de 104 mil é o **Inventory do Tenable One**, que
conta objeto de Active Directory como asset.

| `asset_class` | Total | `tag_count ≥ 1` | `tag_count = 0` | Sem a propriedade |
|---|---:|---:|---:|---:|
| DEVICE | 6.091 | 5.884 | 0 | 207 |
| IDENTITY | 43.666 | 10.123 | 30.275 | 3.268 |
| ACCOUNT | 44.256 | 10.125 | 30.412 | 3.719 |
| GROUP | 9.968 | 175 | 9.741 | 52 |
| WEB_APPLICATION / CLOUD_RESOURCE | 0 | — | — | — |
| **Corpus** | **104.205** | **26.307** | **70.581** | |

IDENTITY + ACCOUNT + GROUP são 97.890 dos 104.205 — **94% do corpus**. Não consomem licença.

A origem provável, levantada pelo cliente e coerente com os dados: o template de scan de VM coleta
identidades e grupos do AD para montar attack path no Exposure Management. O que sustenta a
hipótese é `exposure_classes = IDENTITY` dar **0** enquanto `asset_class = IDENTITY` dá 43.666, com
Identity Exposure zerado no console de licenciamento. É exatamente a armadilha que a docstring do
`ctem_discover_tenant` já avisa: asset_class não é exposure_classes.

## A correção acordada

O denominador passa a ser `is_licensed = true` **combinado com** `asset_class`, e vale para **todos
os indicadores com denominador de assets — S1, S4, D3, V4**, não só os de escopo.

```
asset_class = DEVICE  AND  is_licensed = true      →  5.884   ← o mesmo inteiro do console de licenciamento
   … e tag_count >= 1                              →  5.884
   … e tag_count = 0                               →      0
```

Sobre a base certa, **S1 é 100%, não 25,3%** — estágio 5 contra estágio 2.

**`is_licensed` sozinho não serve.** Devolve 96.880, porque vem `true` também nas identidades
(40.394), contas (40.533) e grupos (9.916). Só a combinação com `asset_class` isola a base cobrada.

Junto da correção, publicar a **quebra por asset_class** ao lado do número, para ninguém voltar a
ler total de inventário como se fosse parque.

## Provas dos filtros, no padrão do preflight

- `is_licensed` é propriedade real: consta das 66 de `/api/v1/t1/inventory/assets/properties`, e
  `licensed`, `licensed_asset`, `license`, `licensing` respondem **400**, o que mostra que a API
  valida o nome.
- Par discriminante: `is_licensed = true` → 96.880, `false` → 26. Somam 96.906 contra corpus de
  104.205 — **não devolvem o corpus, logo o filtro é aplicado**. A diferença de 7.299 são assets
  sem a propriedade.
- Filtros combinados são aplicados de verdade: a soma por classe de `tag_count ≥ 1`
  (5.884 + 10.123 + 10.125 + 175) dá **26.307**, o global exato.

## O que NÃO foi resolvido, e não pode ser esquecido na implementação

1. **A tag é automática, e isso é sinal a favor — mas não substitui S2 e S3.** De 26.307 assets
   com tag, só **4** têm exatamente uma; o resto tem duas ou mais, o que confirma regra aplicando
   tag em lote. O cliente descreveu o padrão: a máquina é detectada, reconhecida como Windows 10 e
   já sai marcada (tag por sistema operacional), com classificação por SO em seguida. **Isso é
   padronização, não ruído** — regra automática e repetível é exatamente o que o modelo de
   maturidade premia, e a leitura anterior desta nota, que tratava tag automática como
   possível defeito, estava errada.

   O que a tag automática **não** entrega é contexto de negócio. Tag derivada de SO é
   **descritiva**; criticidade e dono são **atribuídas**, e é isso que S2 e S3 medem. Um parque
   100% tagueado por SO pode ter S2 e S3 em zero sem nenhuma contradição.

   Não foi possível confirmar isso pelos dados: `/api/v1/t1/inventory/assets/search` devolve uma
   projeção fixa (`acr`, `aes`, `asset_class`, `connectors`, `extra_properties`, `id`, `name`) e
   ignora `fields`, `properties` e `select`; `GET /api/v1/t1/inventory/assets/{id}` responde 404.
   **O catálogo de tags só volta com o papel da chave corrigido.** Ou seja: o 403 pode estar
   escondendo um achado de maturidade real em S2/S3, não apenas uma lacuna de ferramenta.

2. **A role foi corrigida em 2026-09-09 — para Basic [16], não Scan Manager — e isso muda o
   diagnóstico das lacunas.** `/session` passou de `permissions = 0` para `16`. Medido endpoint a
   endpoint:

   | Endpoint | 2026-09-08 | 2026-09-09 | Indicadores |
   |---|---|---|---|
   | `/workbenches/vulnerabilities` | 403 | OK — 2.444 | P1, D4, V1, V2 |
   | `/scans` | 403 | OK — 60 | M1, M2 |
   | `/vulns/export` | 403 | OK | M4 / MTTR |
   | `/scanners/null/agents` | (coletado) | **403** | **D3** |
   | `/tags/categories`, `/tags/values` | vazio | **vazio** | **S2, S3** |

   Duas anomalias, nenhuma explicada:

   **D3 regrediu.** O relatório de 2026-09-08 publicou D3 = 65,1% sobre 6.089 devices e citou 1.205
   agentes desligados — logo os agentes foram lidos com papel 0. Hoje, com Basic [16], o mesmo
   caminho (`/scanners/null/agents`, usado em `discovery.py:118`) responde 403 pedindo
   `VM.VM_EXPLORE`. Confirmar com quem alterou a role se algum privilégio saiu junto, ou se a
   coleta anterior usou outra chave. **Não tratar como resolvido.**

   **S2 e S3 não eram problema de privilégio.** Com o papel corrigido, `/tags/categories` e
   `/tags/values` respondem 200 com **zero itens**, enquanto o inventário mostra 26.307 assets com
   `tag_count >= 1`. São fontes diferentes: o que o Inventory do Tenable One conta como tag não
   está no catálogo de tags do VM, que é onde S2 e S3 procuram. Isso é coerente com a marcação
   automática descrita no item 1 — regra que reconhece o SO na detecção pode não popular o catálogo
   do VM. **Investigar de onde vêm as tags do inventário (`tag_ids`, `tag_names`, `external_tags`
   estão entre as 66 propriedades) antes de reescrever S2 e S3.**

3. **Os 450 assets de ASM exigem outra API, e por isso não aparecem.** `exposure_classes = ASM`
   → 0, `WAS` → 9, `WEB_APPLICATION` → 0: eles não estão na visão de inventário do Tenable One.
   O Attack Surface Management tem **base e credencial próprias** —
   `POST https://asm.cloud.tenable.com/api/1.0/inventory`, com chaves geradas no perfil de usuário
   do próprio ASM, não as `TIO_ACCESS_KEY`/`TIO_SECRET_KEY` do VM
   (https://developer.tenable.com/reference/navigate e
   https://docs.tenable.com/attack-surface-management/Content/Topics/UserProfile/GenerateAPIKeys.htm).

   Consequência de projeto: incluir o ASM significa **um segundo endereço base e um segundo par de
   credenciais** no `client.py`, que hoje assume um só. Isso é mudança de escopo, não ajuste de
   denominador — fica **fora** desta correção, e como item próprio a decidir. Enquanto não entrar,
   o relatório deve dizer que a base medida não inclui o ASM, em vez de omitir os 450 em silêncio.

4. **Mexe em decisão fechada.** O `CLAUDE.md` fixa "the measurement scope is the whole tenant — no
   filtering by environment or exclusion by tag". A correção não é exclusão por tag nem por
   ambiente, é o denominador passar a ser a base licenciada; a linha precisa ser reescrita junto,
   não contornada em silêncio.

5. **Golden tests.** Os números de 2026-09-02/03 do sandbox foram medidos sobre o corpus inteiro.
   Mudar o denominador muda S1, S4, D3 e V4 na fixture. Conforme o `CLAUDE.md`, isso é divergência
   a investigar, não teste a ajustar — o recálculo tem de ser deliberado e registrado aqui.

---

## Adendo de 2026-09-09 — role em Scan Manager, e o que ela resolveu

`/session` passou a `permissions = 40` (Scan Manager). Coleta completa: **14 dos 19 indicadores
com valor**, contra 10 em 2026-09-08. Agentes voltaram (5.214, sendo 4.007 ativos), D3 = 68,1%
sobre a base licenciada.

### `verdict()` confundia filtro ignorado com filtro saturado — corrigido

Efeito colateral do denominador novo: sobre a base licenciada, `tag_count >= 1` devolve os 5.885,
e a regra antiga ("filtrado igual ao corpus ⇒ ignorado") marcava um 100% legítimo como suspeito.
`verdict()` agora exige o **complemento**: `tag_count = 0` sobre a base dá 0, os dois somam a base,
logo o filtro foi aplicado. Dois filtros mutuamente exclusivos devolvendo ambos o corpus continuam
`ignored` — essa é a assinatura verdadeira. Cinco testes novos em `test_preflight.py` fixam os
casos; sem complemento a resposta segue conservadora (`ignored`).

**S1 = 100,0%, `applied`, n = 5.885 — estágio 5 pelos cortes `[20, 50, 80, 95]`.**

### S2 e S3: não é papel nem versão de API, é permissão por tag

Confirmado na documentação: ver tags exige papel (Basic a Administrator, todos servem) **mais a
permissão de access group `Can View`/`Can Use` sobre a tag**, criada automaticamente só para quem
cria a tag
(https://docs.tenable.com/vulnerability-management/Content/Settings/access-control/Permissions.htm).

Descartado que fosse endpoint ou versão: `/api/v3/tags/values`, `/api/v3/tags/values/search` e
`/tags/assets/assignments` respondem 403; `/api/v1/t1/inventory/tags` e `.../tags/search` dão 404;
`/tags/categories/{uuid}/values` devolve vazio igual. O sintoma é sempre o mesmo —
`pagination.total = 47` com lista vazia, ou seja, a contagem ignora o filtro de permissão e a
lista não.

**As 13 categorias visíveis** (nomes omitidos: dado do cliente) classificam inventário, sistema operacional, rede, site e servidores críticos.

Caminho alternativo que funciona: o inventário lê os nomes de tag direto no asset —
`tag_names contains "<valor de uma categoria de servidores>"` devolve **437** assets licenciados. Ou seja, o dado existe e é
legível pelo lado do Inventory; o bloqueio é específico da API de tags do VM. Se a permissão não
for concedida, S2 e S3 podem ser reescritos sobre `tag_names`, **desde que os valores sejam
declarados pelo operador** — não há como enumerá-los sem a permissão.

### M4 e a política de 30 dias

Export de 365 dias, `high` + `critical`, estado FIXED: **121.184 findings em 92 s**, sem pending.

| | n | p50 | p90 | média | máx | dentro de 30d | fora |
|---|---:|---:|---:|---:|---:|---:|---:|
| Critical | 48.468 | 4,0 d | 21,2 d | 13,0 d | 860,1 d | **92,4%** | 3.685 |
| High | 72.716 | 3,0 d | 22,0 d | 11,2 d | 860,1 d | **92,7%** | 5.321 |

**O guard subiu para 48,7%** (era 42,7% em 180 dias): quase metade dos findings está em lote, o que
significa que a data de correção é a data em que o scan rodou, não a data em que a correção
aconteceu. Por isso o p50 de 3-4 dias não é confiável — ele mede cadência.

**A cauda é confiável, e é onde está o achado.** Um artefato de lote empurra o número para BAIXO,
nunca para cima: findings que aparecem levando mais de 30 dias levaram pelo menos isso. Logo os
**9.006 findings fora da política** (3.685 critical + 5.321 high) são piso, não estimativa. Já os
92% de conformidade são teto otimista. É assim que o número deve ser publicado.

---

## Adendo de 2026-09-14 — implementado, fixture regravada em parte, golden tests recalculados

Os PRs #154 e #155 do `tenable/cyberagents-exchange` foram aprovados e mergeados (2026-09-11 e
2026-09-14), o que liberava a implementação. O código já tinha entrado em `3e7dd42`; faltavam a
fixture, os golden tests e a linha do `CLAUDE.md`.

### Duas correções que apareceram no caminho

1. **S2 e S3 dividiam contagem de todas as classes pela base licenciada.** O numerador
   (`tag_names = …`) não levava os filtros de licença, e no tenant de produção, com mais de 10 mil
   identidades tagueadas, a taxa passaria de 100%. Agora numerador e denominador usam
   `licensed_filters()`.
2. **`APPLICATION` faltava em `LICENSED_CLASSES` e em `ASSET_CLASSES`.** O asset de WAS do sandbox
   (Juice Shop, ACR 9) volta do Inventory com `asset_class = APPLICATION`, não `WEB_APPLICATION`, e
   é licenciado. Fora da base, o único Crown Jewel sumia e o S4 virava `false`. A quebra por classe
   também somava 28 dos 30. Decisão do usuário: incluir. `WEB_APPLICATION` fica, por ser valor
   documentado, mas deu zero no sandbox e em produção.

### A fixture

As 11 contagens novas foram gravadas ao vivo do sandbox (confirmado: corpus 30, igual à gravação;
`/session` com `permissions = 64`) por `_ferramentas/record-fixture/record_missing_queries.py`. O
script só envia contagem `limit=1` de `/assets/search` e reconfere todas as contagens já gravadas.

**Drift aceito, por decisão do usuário:** só as duas contagens antigas de `tag_count` mudaram
(`>= 1`: 9 → 8; `= 0`: 20 → 8). Nenhum indicador lê essas contagens depois da mudança. Todas as
outras bateram. D3 e V4 calculados ao vivo no mesmo dia deram os mesmos 7/7 que a mistura
fixture + contagens novas produz.

| Contagem na base licenciada (sandbox, 2026-09-14) | Total |
|---|---:|
| base licenciada | 8 |
| … DEVICE | 7 |
| … APPLICATION | 1 |
| … `tag_count >= 1` / `= 0` | 8 / 0 |
| … categoria de criticidade | 7 |
| … categoria de dono | 1 |
| … `acr >= 9` | 1 |

### Golden tests recalculados — deliberadamente

| Indicador | 2026-09-03 (corpus 30) | 2026-09-14 (base licenciada 8) |
|---|---|---|
| S1 | 30,0 (9/30) | **100,0** (8/8), complemento 0, `applied` |
| S2 | 26,7 (8/30) | **87,5** (7/8) |
| S3 | 6,7 (2/30) | **12,5** (1/8) |
| S4 | `true` | `true`, com `acr >= 9` = 1 fixado no teste |
| D3 | 87,5 (7/8 DEVICE) | **100,0** (7/7 DEVICE licenciado) |
| V4 | 87,5 (7/8 DEVICE) | **100,0** (7/7 DEVICE licenciado) |

O teste de snapshot agora fixa `licensed_total = 8`, `licensed_by_class = {DEVICE: 7,
APPLICATION: 1}` e que a quebra por classe soma o corpus.

### Ainda em aberto

- **O numerador do V4 não leva `is_licensed`.** Ele vem da busca de findings com
  `asset_class = DEVICE`; um DEVICE não licenciado com finding de EOL entraria no numerador. No
  sandbox, 7/7 ao vivo. Verificar se a busca de findings aceita `is_licensed` antes de mexer.
- Os itens 2 (D3 com papel Basic), 3 (ASM) e as tags de S2/S3 em produção seguem como estavam.
