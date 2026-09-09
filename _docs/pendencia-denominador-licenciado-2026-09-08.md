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
