---
name: tenable-ctem-maturity-assessment
description: >
  Mede indicadores objetivos do tenant Tenable One, classifica o cliente nos cinco estágios do
  Exposure Management Maturity Model da Tenable — Ad Hoc, Defined, Standardized, Advanced,
  Optimized — e entrega plano de evolução de três quarters. Use SEMPRE que o usuário pedir:
  maturidade CTEM, CTEM maturity, exposure management maturity, maturity assessment, avaliação de
  maturidade, em que estágio meu cliente está, diagnóstico CTEM, assessment de exposição, nível de
  maturidade em gestão de exposição, roadmap de maturidade, plano de evolução CTEM, gap analysis de
  CTEM, os cinco estágios do CTEM, scoping discovery prioritization validation mobilization. Use
  também em: madurez CTEM, evaluación de madurez, en qué etapa está, hoja de ruta de madurez.
  Avalia 19 indicadores nos cinco estágios, mapeia cada um aos oito critérios oficiais da Tenable,
  entrega estágio efetivo e estágio médio lado a lado e nomeia o estágio que limita o conjunto.
  Somente leitura.
---

# Skill: Tenable CTEM Maturity Assessment

Mede o tenant, classifica nos cinco estágios oficiais do Exposure Management Maturity Model da
Tenable e entrega o caminho para o estágio seguinte.

Audiência: CISOs, Security Managers, e Channel SEs conduzindo assessment em cliente ou parceiro.
Modo: **somente leitura.** Nenhuma ferramenta de escrita é chamada.

**As duas perguntas que ela responde:**
1. Em que estágio o cliente opera de fato — e qual estágio está segurando os outros?
2. O que precisa mudar, em ordem de esforço e impacto, para subir de patamar?

---

## Leitura obrigatória antes de começar

```
view references/mcp-preflight.md
view references/indicadores-maturidade.md
```

O primeiro traz o pré-voo de filtro, a armadilha de propagação de índice e a amostragem
estratificada. **O MCP aceita filtros que não aplica e não retorna erro** — sem o pré-voo esta skill
publica o total do corpus como se fosse resultado filtrado.

O segundo traz os 19 indicadores com fórmula, chamada MCP, cortes e origem de cada limiar.

---

## O fato que determina o desenho desta skill

**Nenhum material oficial da Tenable publica limiar numérico por estágio de maturidade.** O modelo
é qualitativo; a avaliação oficial usa oito critérios declaratórios sem faixas de score divulgadas.

Por isso a skill separa três camadas, e o relatório também:

| Camada | O que é | Configurável |
|---|---|---|
| **1 — Oficial** | Os cinco estágios, os oito critérios, as faixas de CES, AES, ACR e VPR | Não |
| **2 — Critério da skill** | Os cortes numéricos de cada indicador | Sim, no bloco `maturity_config` |
| **3 — Sempre visível** | Valor bruto, N, filtro literal, limiar aplicado e sua origem | Sempre presente |

Cravar um percentual como se fosse critério Tenable seria imprecisão. Cada corte aparece no
relatório rotulado com sua origem: `oficial Tenable`, `externo citado (CISA BOD 26-04)`,
`default da skill` ou `sobrescrito pelo operador`.

---

> **Operador de primeira execução:** o passo a passo completo — pré-requisitos, variáveis de
> ambiente, comando do coletor e checklist de entrega ao cliente — está em
> `references/roteiro-de-execucao.md`, nos três idiomas.

## Passo 0 — Descoberta e confirmação (OBRIGATÓRIO)

**Princípio: descobrir, apresentar, confirmar. Nunca adivinhar por palavra-chave e nunca oferecer
campo em branco.** O operador não deve ter que lembrar o nome exato de uma categoria de tag; a skill
consulta o tenant, mostra o que existe e pede o mapeamento escolhendo entre os valores reais.

A versão anterior deste passo tentava adivinhar a categoria de criticidade e de owner por lista de
palavras-chave. Isso falha em qualquer cliente que use nomenclatura própria — `Tier`, `BIA`,
`Classificação`, `P1/P2/P3`, `Gold/Silver/Bronze`, `Squad`, `CI Owner`, ou o nome em outro idioma.

### Fase A — Descoberta silenciosa, sem perguntar nada

Executar antes de qualquer pergunta, e guardar o resultado:

```
ctem_discover_tenant()
```

**Uma chamada.** Devolve categorias e valores reais de tag, total de ativos, contagem por
`asset_class`, `exposure_classes` presentes com o total de cada, scans com histórico e quantas
execuções cada um tem, e agentes por status. Substitui as ~10 chamadas que esta fase exigia.

O resultado fica em cache por TTL curto no servidor, então reconsultar durante a mesma execução não
custa chamada nova.

**Atenção que o retrato já traz explícita:** `asset_class` não é `exposure_classes`. Um tenant pode
ter ativos com `asset_class = IDENTITY` e `exposure_classes = IDENTITY` em zero — os ativos de
identidade estão no inventário sem carregar achados de Identity Exposure. D2 usa
`exposure_classes`.

### Fase B — Confirmação, com os valores reais como opções

Usar `ask_user_input_v0`. **Toda pergunta de mapeamento oferece as opções encontradas na Fase A,
mais "nenhuma delas".** Nunca texto livre onde uma lista serve.

### Fase B.1 — A tela de confirmação, antes de qualquer pergunta

**Não abrir com 14 perguntas.** Depois da Fase A, montar **uma tabela de proposta** com os 14
campos preenchidos com o melhor palpite da descoberta, mais a razão de cada palpite, e fazer
**uma** pergunta:

```
message: (PT) "Descobri o tenant e montei este mapeamento. Confira antes de eu medir —
              qualquer linha pode ser trocada."

<tabela: Campo | Valor proposto | Como cheguei nele | Alternativas encontradas>

questions:
  - question: (PT) "Seguir com este mapeamento?"
    type: single_select
    options:
      - "Seguir assim"
      - "Ajustar alguns campos — vou dizer quais"
      - "Rever campo por campo"
```

- **"Seguir assim"** → medir. É o caminho esperado quando a descoberta acertou.
- **"Ajustar alguns campos"** → perguntar **só** os campos que o operador nomeou, com as opções
  reais da Fase A.
- **"Rever campo por campo"** → a sequência completa de perguntas abaixo.

**Regras da proposta.** Cada linha traz *como* a skill chegou ao valor, e as alternativas que
existem no tenant — sem isso o operador não tem como julgar. Campos que a skill **não pode
propor** ficam explicitamente vazios na tabela e são perguntados de todo jeito, porque palpite
neles é chute: os **valores de maior criticidade** (a skill não conhece a ordem ordinal de `Alta`,
`Tier 1`, `Gold` ou `Classe A`), o **critério de priorização do cliente**, e o **idioma** do
relatório.

**Uma categoria pode ser o que a skill não esperava, e o caminho é oferecer, não adivinhar.** Se o
tenant tem `Location` com valores `Site 1` e `Site 2`, a proposta oferece `Location` como candidata
a **localidade** — não a ambiente. Localidade é *onde* o ativo está; ambiente é *produção contra
homologação*. Se naquele cliente os sites **forem** os ambientes, o operador reaponta na
confirmação e a skill passa a medir só produção. O inverso também vale: uma categoria chamada
`Ambiente` com valores `Matriz` e `Filial` é localidade, não ambiente. A skill nunca decide isso
pelo nome da categoria — ela propõe pelo nome e aceita a correção.

**A tabela de proposta confirmada vai inteira para a aba de Metodologia do relatório**, com a
coluna "como cheguei nele" preservada. É o que torna a reavaliação comparável e o que permite a um
segundo consultor auditar o recorte.

### Fase B.2 — As perguntas, quando o operador quer revisar

```
Pergunta 1 — Idioma do relatório?
  opções: ["Português (PT-BR)", "English (EN)", "Spanish (ESP)"]

Pergunta 2 — Qual categoria de tag representa a CRITICIDADE do ativo?
  tipo: single_select
  opções: [<todas as categorias encontradas na Fase A>, "Nenhuma — o cliente não tem"]
  → obrigatória. S2 e P1 dependem dela.

Pergunta 3 — Dentro dessa categoria, quais valores representam a MAIOR criticidade?
  tipo: multi_select
  opções: [<todos os valores da categoria escolhida em P2>]
  → a skill NÃO sabe se "Alta" é maior que "Média", nem interpretar "Tier 1", "P1", "Gold" ou
    "Classe A". A ordem ordinal tem de vir do operador. Sem isso, "Crown Jewel" é chute.

Pergunta 4 — Qual categoria de tag representa o DONO ou responsável pelo ativo?
  tipo: single_select
  opções: [<categorias da Fase A>, "Nenhuma — o cliente não tem"]
  → S3 e o agrupamento por dono dependem dela.

Pergunta 4b — Qual categoria representa LOCALIDADE (site, região, unidade)?
  tipo: single_select
  opções: [<categorias da Fase A>, "Nenhuma — o cliente não tem"]
  → NÃO filtra escopo e NÃO pontua nenhum indicador. Serve para o roadmap agrupar item por site
    e para o relatório dizer onde o problema está. É um campo separado de propósito: localidade
    e ambiente são coisas diferentes, e clientes usam nomes trocados para as duas.

Pergunta 5 — Qual categoria representa AMBIENTE (produção, homologação, desenvolvimento)?
  tipo: single_select
  opções: [<categorias da Fase A>, "Nenhuma — o cliente não tem"]
  → se existir, Pergunta 5b pede quais valores são produção, e a skill oferece medir a
    maturidade só em produção. Medir junto com laboratório distorce todos os indicadores.

Pergunta 6 — Quais scans representam a AVALIAÇÃO RECORRENTE do ambiente?
  tipo: multi_select
  opções: [<scans com status completed e histórico, com nome, data do último run e nº de execuções>]
  → D1, M1 e M2 saem daqui. Um tenant típico tem scans de teste, de PCI, de POC e um-off.
    Calcular cadência sobre todos mistura ritmo real com experimento e produz número errado.

Pergunta 7 — Há ativos a EXCLUIR do escopo do assessment?
  tipo: single_select
  opções: ["Não, avaliar tudo", "Excluir por tag", "Excluir por classe de ativo"]
  → se por tag: Pergunta 7b oferece as categorias e valores da Fase A.

Pergunta 8 — O cliente usa regras de exceção (accept ou recast) no Tenable VM?
  tipo: single_select
  opções: ["Não usa", "Usa pouco (menos de 10% do backlog)", "Usa muito (mais de 10%)", "Não sei"]
  → NÃO altera cálculo. Determina o texto de ressalva que vai no relatório. **Se M4 for coletado, o
    coletor**, a coluna `severidade_modificada` mede o campo direto e a ressalva passa a citar o
    número medido em vez da estimativa do operador — inclusive quando ele responde "Não sei".
    Ver a seção sobre exceções abaixo.

Pergunta 9 — Superfícies licenciadas pelo cliente?
  tipo: multi_select
  opções: ["VM","WAS","Cloud Security","Identity Exposure","OT Security","ASM","AI","Source Code"]
  → pré-marcar as que a Fase A encontrou em exposure_classes; o operador confirma ou corrige.

Pergunta 10 — Critério de priorização que o cliente usa HOJE?
  opções: ["VPR >= 7 (default)","VPR >= 9","CVSSv3 >= 7","CVSSv3 >= 9","Outro — vou informar","Não sei"]
  → **Default: `VPR >= 7`**, e é o valor pré-preenchido na tela de confirmação. A escolha do
    default não é arbitrária: medido no sandbox em 2026-09-03, trocar `CVSSv3 >= 7` por
    `VPR >= 7` reduz a fila imediata de 3.377 para 1.254 findings — 2.168 saem, 45 entram — e a
    cobertura de VPR dentro da fatia com CVSS ≥ 7 é de 98,1%, então o critério é aplicável a
    praticamente toda a fila que o CVSS selecionaria.
  → **Descritiva, não prescritiva.** Registra o que o cliente faz, não o que deveria fazer.
    Preencher com o critério recomendado quando o cliente usa outro **quebra P3**: o indicador
    compara o critério declarado com a oportunidade medida, e uma declaração falsa reporta
    maturidade que o cliente não tem.
  → "Não sei" é resposta válida e comum, e **não é o mesmo que aceitar o default**. Consequência
    explícita, para dois operadores não produzirem P3 diferente do mesmo tenant: **P3 = Ad Hoc**,
    e a oportunidade continua sendo medida com `vpr >= 7.0` como base de comparação, declarada
    como base default e não como critério do cliente.
  → **Aceitar o default sem verificar tem consequência declarada.** Se o operador clicar "Seguir
    assim" na tela de confirmação sem tocar nesta linha, `confirmado` fica `false`: P3 pontua com
    `VPR >= 7`, e o relatório escreve, na linha do indicador e na aba de Metodologia:
    *"critério de priorização assumido como default (VPR ≥ 7), não confirmado com o cliente"*.
    Sem esse rótulo, um default aceito por comodidade viraria uma declaração de maturidade que
    ninguém fez — e P3 é exatamente o indicador que mede se a declaração existe.
  → Como descobrir o critério real, em ordem de confiabilidade: o filtro dos dashboards que o
    time olha; o filtro da fila no ServiceNow ou Jira; o campo usado no SLA escrito; e só então
    o que a pessoa diz de memória.

Pergunta 11 — Padrão de prazo para o confronto de KEV?
  opções: ["CISA BOD 26-04 (3 / 14 / 60 dias)","SLA próprio do cliente","Sem confronto de prazo"]

Pergunta 12 — Cravar o estágio, ou entregar só os indicadores?
  opções: ["Cravar o estágio","Só os indicadores, sem classificar"]

Pergunta 13 — Perfil de limiares?
  opções: ["Default da skill","Conservador","Agressivo","Carregar perfil próprio"]

Pergunta 14 — Tamanho da amostra de plugins para V1 e V2?
  opções: ["Top 30 (recomendado)","Top 50","Top 20 (execução mais curta)"]
```

**Quando o operador responde "Nenhuma" num mapeamento**, o indicador que depende dele vira **lacuna
declarada com causa nomeada** — "o cliente não tem categoria de tag de owner" — e não uma lacuna
genérica. A diferença importa: a primeira é um achado de Scoping que vira item de roadmap; a segunda
parece falha da ferramenta.

**Registrar o mapeamento no relatório.** A aba de metodologia mostra, literalmente, qual categoria
foi tratada como criticidade, quais valores como maior criticidade, qual como owner, quais scans
entraram na cadência e o que foi excluído do escopo. Sem isso, dois assessments do mesmo cliente
feitos por consultores diferentes não são comparáveis.

**Perfil salvo.** Ao final, a skill oferece exportar o mapeamento como bloco YAML para o operador
guardar e reusar na reavaliação. Trocar o mapeamento entre execuções invalida a comparação, do mesmo
jeito que trocar o perfil de limiares.

```yaml
mapeamento_cliente:
  categoria_criticidade: "Business Impact"
  valores_maior_criticidade: ["Tier 1", "Mission Critical"]
  categoria_owner: "CI Owner"
  scans_recorrentes: [33, 40]
  usa_excecoes: "usa_pouco"
```

**O recorte da v1 é o tenant inteiro.** O perfil não tem `categoria_ambiente`,
`valores_producao` nem `excluir` porque nenhum indicador os aplicaria: o servidor mede o corpus
completo, sempre. Campos que o operador preenche e que ninguém consome são piores que campos
ausentes — o operador exclui LAB e SANDBOX, confere o YAML, e recebe um relatório do tenant todo
acreditando que o recorte valeu. Se o cliente precisa de recorte por ambiente ou exclusão de
laboratório, isso é v2 e entra como filtro de tag nos indicadores, não como campo de perfil.

---

## Exceções de risco — accept e recast

**Pergunta que todo cliente faz e que precisa de resposta honesta no relatório.**

O que a API da Tenable tem, e a skill **não** alcança pelo MCP:

| Campo da VM API | Definição da spec |
|---|---|
| `severity_modification_type` | `NONE`, `RECASTED` ou `ACCEPTED` — *"o tipo de modificação que um usuário fez na severidade"* |
| `severity_id` | a severidade **depois** do recast |
| `severity_default_id` | *"a severidade originalmente atribuída antes de o usuário recastear o risco"* |
| `recast_reason`, `recast_rule_uuid` | o comentário e a regra aplicada |
| `accepted_count`, `recasted_count` | por plugin, na resposta de workbenches |

O que isso significa para os números desta skill, e que vai declarado:

1. **Finding com risco aceito continua aparecendo como `ACTIVE`.** A API de Exposure Management, que
   é a que os tools `tenable_one_*` consomem, não tem nenhuma menção a recast, accept ou exceção — o
   enum de `state` é só `ACTIVE`, `RESURFACED` e `FIXED`. Não há como identificar nem excluir.
2. **Recast altera a severidade que o inventário reporta.** `severity_id` é o valor recasteado. Um
   Critical recasteado para Low é contado como Low por qualquer indicador baseado em severidade. Isso
   **deflaciona silenciosamente** o backlog crítico — o efeito é o oposto do que o operador espera.
3. `accepted_count` e `recasted_count` existem na resposta de workbenches, mas a saída formatada do
   MCP não os imprime. Não é possível dizer, sem um tenant que use exceções, se o wrapper descarta o
   campo ou se o valor era zero.

4. **Com `ctem_mobilization`, isso deixa de ser cego.** O `POST /vulns/export` devolve
   `severity_modification_type`, que M4 devolve em `contexto.severidade_modificada_diferente_de_none`. Quando M4
   existe, contar as linhas por valor (`NONE`, `RECASTED`, `ACCEPTED`) e **usar a contagem em vez
   da estimativa do operador**. O recorte do export costuma ser mais estreito que o do assessment
   (severidade e janela de dias), então a contagem é declarada com o recorte ao lado, nunca
   extrapolada para o backlog inteiro. Na coleta de referência de 2026-09-03, as 4 278 linhas
   vieram `NONE`: nenhuma severidade distorcida por exceção naquele recorte.

**Comportamento da skill.** A resposta da Pergunta 8 não muda nenhum cálculo — muda a ressalva:

| Resposta | Texto no relatório |
|---|---|
| Não usa | Nenhuma ressalva |
| Usa pouco | *"O cliente usa regras de exceção. O MCP não permite identificá-las, então elas estão contadas no backlog e um recast pode ter reduzido a severidade reportada. Impacto estimado pelo operador: abaixo de 10%."* |
| Usa muito | Mesma ressalva, **em destaque no topo do relatório**, com a recomendação de validar os números no console antes de levar ao cliente |
| Não sei | *"Não foi possível determinar se o cliente usa regras de exceção. Confirmar antes de usar estes números em decisão de investimento."* |
| Qualquer resposta, **com M4 coletado** | Substituir a estimativa pela medição: *"No recorte do export (severidades X, últimos N dias, M linhas), K findings tinham severidade modificada — J recasteados e L com risco aceito."* O número vem de `contexto.severidade_modificada_diferente_de_none`. Se `K = 0`, dizer isso: é a confirmação de que nenhuma severidade daquele recorte foi ajustada |

**Pedido técnico ao time do MCP**, junto com os outros: expor `severity_modification_type`,
`severity_default_id` e os contadores `accepted_count` e `recasted_count`. Sem eles, nenhuma skill
que conte backlog é exata em cliente que trabalha com exceções — e trabalhar com exceções é sinal de
processo maduro, justamente o cliente que esta skill quer avaliar bem.

---

## Passo 1 — Pré-voo e corpus

```
ctem_preflight()
```

**Uma chamada.** Devolve a tabela `PREFLIGHT` pronta — cada filtro testado **ao vivo**, com par
discriminante — e a `deny_list` dos filtros que o servidor rejeita antes de a requisição sair, cada
um com a regra e a prova medida. A tabela vai inteira para o relatório.

O servidor não herda veredito de documento. Três formas de prova: `par_exclusivo` (duas consultas
mutuamente exclusivas cujos totais têm de somar o corpus — "reduziu" não basta), `booleano`
(`true` e `false` com totais iguais significam parâmetro ignorado) e `monotonico` (escada de cortes
estritamente decrescente).

**Os denominadores vêm de `ctem_discover_tenant()`**, já coletado no Passo 0: `ativos.total`,
`ativos.por_asset_class.DEVICE`. O corpus de findings vem no pré-voo.

**Não montar filtro de data em findings à mão.** Os operadores relativos (`within last`,
`older than`, `newer than`) são aceitos e silenciosamente ignorados — o servidor os rejeita com
erro. Onde a skill precisa de tempo de avaliação, a fonte é `scan_cadence`; onde precisa de tempo
de correção, é `mttr_collect`.

---

## Passo 2 — Coletar os 19 indicadores

Seguir `references/indicadores-maturidade.md`, que traz por indicador a fórmula e a origem do
limiar. **A coleta são quatro chamadas**, uma por estágio, cada uma devolvendo os indicadores já
agregados:

```
ctem_scoping(mapeamento)          → S1, S2, S3, S4
ctem_discovery()                  → D1, D2, D3, D4
ctem_prioritization(mapeamento, corte_priorizacao_cliente, p2_valor)
                                  → P1, P2, P3 + as três filas comparadas
ctem_validation(mapeamento)       → V1, V2, V3, V4
ctem_mobilization(mapeamento)     → M1, M2, M3, M4
```

`mapeamento` são as respostas da Fase B do Passo 0:

```yaml
categoria_criticidade: "<nome da categoria>"   # obrigatório para S2, S4 e P1
categoria_owner:       "<nome da categoria>"   # obrigatório para S3
scans_recorrentes:     [<scan_id>, ...]        # obrigatório para M1 e M2
```

**O servidor não adivinha nenhum desses.** Sem eles o indicador vira lacuna e a causa lista as
opções que existem no tenant, para o consultor apontar a certa. Isso é deliberado: no sandbox, M1
dá mediana 21 dias com o scan recorrente declarado e 1,0 dia somando todos os scans com histórico —
dois estágios de diferença saindo de uma escolha que ninguém fez.

**Reexecução parcial.** Todo tool de estágio aceita `indicadores=["V2","V3"]` e calcula só o
subconjunto pedido. Use isso para recoletar um indicador que ficou em lacuna sem pagar os 17 de
novo — `ctem_validation(indicadores=["V3"])` não gasta as chamadas de plugin que V1 e V2 exigiriam.

**Cada indicador já vem com a evidência.** O envelope traz `valor`, `n`, `filtro_literal`,
`coletado_em_utc` e `veredito_preflight`; o `contexto` traz o que é específico do indicador
(estratos, intervalos, cortes, notas de proxy). Copie isso para `EVIDENCIA[id]` e acrescente só o
corte aplicado com sua origem, que é decisão da skill, não do servidor.

**Consulta que falhou não vira número.** Vem `valor: null` com `lacuna: true` e `causa` preenchida.
Número parcial silencioso não existe nesta cadeia.

### Censo em vez de amostra

`ctem_discovery`, `ctem_validation` e `ctem_mobilization` aceitam `modo_plugins`, que vem `auto`:
faz **censo** de todos os plugins da severidade quando a população cabe em `limite_censo` (300), e
cai para amostra estratificada acima disso. O modo usado vai no `filtro_literal` e em
`contexto.modo`.

Isto **substitui** `CONFIG.amostra_plugins.censo_d4_m3: false`. Aquela decisão foi correta para o
caminho antigo: `plugins_search_plugins` aceita palavra-chave e CVE, não lista de IDs. Mas
`plugin_details_batch` recebe lista de IDs, então o censo passou a ser alcançável — 121 plugins
críticos custam 64 s e ~5.400 tokens, ainda três vezes menos que os ~15.000 que o caminho antigo
gastava para **vinte** plugins.

No censo **não há intervalo de confiança, nem ponderação, nem alocação entre estratos**: a taxa é a
contagem. O portão de confiança da amostra (`portao_ic`) só se aplica quando `contexto.modo` for
`amostra`. Quando for `censo`, o relatório declara censo e não publica IC.

### 2.M4 — MTTR, o único indicador fora da API de Exposure Management

**M4 não exige mais CSV nem script externo.** `ctem_mobilization` chama `mttr_collect` internamente
e já aplica a guarda de cadência. O coletor `tenable_mttr_export.py` sai do pacote desta skill:
ele continua existindo como **origem do código** de `mttr.py` no servidor e como gerador das
fixtures dos golden tests, não como caminho de execução. Um caminho, não dois.

A razão de M4 ser especial não mudou: `last_fixed`, `time_taken_to_fix` e
`severity_modification_type` vivem na API de Vulnerability Management, em `POST /vulns/export`, e
**não estão entre as 44 propriedades de findings** da API de Exposure Management. Não é wrapper
faltando.

**Export demorado não trava a conversa.** Se estourar `mttr_max_wait_s`, M4 volta como lacuna
**recuperável**, com o `export_uuid` na causa. Chame `ctem_mobilization(indicadores=["M4"],
mttr_export_uuid="<uuid>")` para retomar. Nunca abra um export novo enquanto houver um aberto para
aquela chave: a API responde **409**.

**Nunca pedir chaves de API ao operador nesta conversa.** As credenciais vivem no ambiente do
processo do servidor MCP, em `TIO_ACCESS_KEY` e `TIO_SECRET_KEY`. Nenhum tool aceita chave como
parâmetro, e a skill jamais pede credencial.

**A guarda de cadência já vem aplicada.** `ctem_mobilization` cruza as janelas do MTTR contra as
datas de `scan_cadence` dos `scans_recorrentes` declarados, e devolve M4 como lacuna quando um dos
dois portões dispara:

1. `pct_em_lote` acima de `CONFIG.mttr.pct_em_lote_max`;
2. janelas formadas **só** por datas de scan — mesmo com `pct_em_lote` abaixo do corte.

O portão 2 é o mais forte, e é por isso que ele existe: o percentual depende do corte de lote
escolhido — no sandbox o mesmo dado dá 93,5% com corte 2 e 38,7% com corte 5, e o corte 5 passaria
pela guarda de 40%. A composição das datas não depende de escolha nenhuma.

**O que a skill ainda precisa fazer:** ler `contexto.p50_critical` e `contexto.p50_high`, mapear
cada um pelos seus cortes, e tomar o **menor dos dois estágios**. Mobilização madura fecha as duas
severidades, não compensa uma com a outra. O servidor entrega os dois números e os cortes; o
estágio é da skill.

Procedimento:

1. `ctem_mobilization` já chama `mttr_collect` internamente. Não há CSV a procurar nem script a
   rodar, e **nada a perguntar ao operador** — as credenciais vivem no ambiente do servidor MCP.
2. Se M4 voltar como lacuna **recuperável** (export ainda em andamento), a causa traz o
   `export_uuid`. Retomar com
   `ctem_mobilization(indicadores=["M4"], mttr_export_uuid="<uuid>")`.
   **Nunca** abrir um export novo enquanto houver um aberto: a API responde 409.
3. Se M4 voltar como lacuna **de mérito** (a guarda de cadência disparou), isso é resultado, não
   falha: declarar a lacuna com a causa que o servidor devolveu, `P = 16`, e o portão do Passo 4 se
   ajusta sozinho.

**Nada disso pede nada ao operador.** O fluxo antigo perguntava pelo caminho do CSV e, se não
houvesse, mandava rodar o coletor no terminal. Esse fluxo foi removido: não há arquivo a informar e
não há script a rodar.

**Cálculo.** Os dois p50 vêm prontos em `contexto.p50_critical` e `contexto.p50_high`, calculados
sobre `estado=FIXED` com `dias_para_corrigir` presente, por percentil **interpolado** (o método vai
declarado em `contexto.metodo_percentil`, junto do valor por posição mais próxima, para o leitor
medir o efeito da escolha).

Traduzir cada p50 para estágio pelos cortes de M4 em `references/indicadores-maturidade.md`, e:

```
M4 = o MENOR dos dois estágios
```

O menor, e não a média, pela mesma lógica do `estagio_efetivo`: mobilização madura fecha as duas
severidades, não compensa uma com a outra.

**Portões de M4, todos obrigatórios:**

| Condição | Comportamento |
|---|---|
| `n[sev] < CONFIG.mttr.n_minimo_por_severidade` (default 5) | aquela severidade **não** pontua |
| as duas severidades abaixo do mínimo | **M4 = lacuna**, com o `n` de cada uma declarado |
| `mttr_fonte = derivado` em mais de `max_derivado_pct` (default 30%) | M4 pontua, com ⚠️ de composição no relatório |
| `filtros_divergiram = true` no JSON de resumo | **M4 = lacuna.** Job reaproveitado por 409: o recorte não é o pedido. **Ler o booleano**, nunca comparar os dicionários — a API normaliza e adiciona defaults, então a comparação literal acusa divergência em toda execução |
| `pct_em_lote >= CONFIG.mttr.pct_em_lote_max` (default 40), **calculado pelo servidor com `lote_minimo_por_janela`** | **M4 = lacuna com causa nomeada:** *"MTTR dominado pela cadência de scan (X% dos findings fechados em lote); M1 e M2 já medem cadência"*. Ver abaixo |
| janelas `(first_found, last_fixed)` formadas só por pares de datas de scan | **M4 = lacuna**, mesmo com `pct_em_lote` abaixo do corte: o número é o intervalo entre scans. Checar contra `scan_history` |
| linhas `FIXED` com `dias_para_corrigir` vazio | fora do cálculo, contagem declarada. **Nunca** imputar valor |
| `severidade_modificada != NONE` em alguma linha | M4 pontua, com a ressalva de que a severidade foi ajustada por recast |

#### Por que a cadência de scan invalida M4, e não apenas o rotula

`time_taken_to_fix` mede **detecção a detecção**, não tempo de ação. Um ativo escaneado em 09/06,
não escaneado de novo, e visto limpo em 02/09 produz 85 dias para tudo que estava nele — inclusive
o que foi corrigido no primeiro dia. O coletor detecta isso agrupando findings do mesmo ativo com
a mesma `first_found` e a mesma `last_fixed`, e publica `cadencia_de_scan.pct_em_lote`.

Na skill de dashboard esse caso vira **rótulo** ("limite superior"), porque lá o número ainda
informa. Aqui vira **lacuna**, e a razão é estrutural: com `pct_em_lote` alto, M4 estaria medindo
a mesma coisa que M1 e M2 já medem — cadência de avaliação. Pontuar assim contaria cadência duas
vezes e chamaria de maturidade de remediação o que é maturidade de avaliação. É o mesmo princípio
que impediu P3 de pontuar sozinho pelo delta puro: **não pontuar como maturidade de processo o que
é característica do ambiente.**

Quando M4 vira lacuna por este motivo, o relatório é obrigado a escrever o achado em texto, porque
ele vale mais que o número perdido:

> *"O MTTR não é mensurável neste ambiente porque X% dos findings corrigidos foram vistos
> fechados no mesmo scan que os vizinhos do mesmo ativo — o número mediria intervalo entre scans,
> não tempo de correção. O maior lote é <ativo>, com N findings. Aumentar a frequência de
> avaliação nesse ativo é o que torna o MTTR mensurável, e é item de roadmap de Mobilization."*

#### O que a validação da coleta de 2026-09-03 mostrou, e o que a skill passa a exigir

Coleta real do sandbox, 4 278 findings, 31 `FIXED` com data. O resumo do coletor publicou
`pct_em_lote = 74,2%`. Recontado linha a linha com corte 2, o valor é **93,5%** — a diferença
não é erro de conta, é uma **escolha de método não declarada**: o coletor só conta um grupo como
lote a partir de **3** findings na mesma janela, e há três grupos de 2 que ele descarta.

Mais decisivo que o percentual: as 9 janelas `(first_found, last_fixed)` observadas são todas
pares tirados de **7 datas distintas** (27/01, 08/03, 07/06, 08/06, 09/06, 02/09, 03/09), que são
as datas de scan do tenant, e **29 dos 31** findings caem numa janela compartilhada. Neste tenant
o MTTR **é** o intervalo entre scans: mede cadência de avaliação, não tempo de correção. Maior
lote: 12 findings de um ativo, todos com 85,5 dias exatos. M4 é lacuna aqui, corretamente — e
seria lacuna pelos dois valores, 74,2% ou 93,5%.

**Consequência para a skill.** O coletor **1.1.0** já publica as três escolhas no resumo
(`lote_minimo_por_janela`, `sensibilidade_ao_corte`, `estados_incluidos_no_mttr`,
`metodo_percentil`) — quando esses campos existirem, ler dali. Se o resumo vier de uma versão
anterior (campos ausentes ⇒ coletor 1.0.0, corte de lote 3), **recontar** com os defaults
da skill e declarar o recálculo no relatório:

| Escolha de método | Por que importa | O que fazer |
|---|---|---|
| corte de lote (`lote_minimo_por_janela`) | no sandbox o mesmo recorte dá 93,5% com corte 2, 74,2% com 3, 64,5% com 4 e 38,7% com 5 — o corte 5 passaria a guarda de 40% e faria M4 pontuar | recontar com **2** (default da skill). Se o resumo usar outro corte, usar o valor recontado e dizer qual foi |
| estados incluídos no MTTR | o coletor calcula só sobre `FIXED`. Incluindo `REOPENED`, a média de High vai de 60,39 para 49,66 dias — 18% de diferença, e `REOPENED` é justamente o finding que voltou | manter só `FIXED` (um finding reaberto não foi corrigido), e **declarar** a exclusão com a contagem de `REOPENED` |
| método de percentil | `p90` de Critical dá 101,43 interpolado e 92,91 por posição mais próxima; com n=10 a escolha muda o número em 9% | usar `interpolado` (`CONFIG.mttr.metodo_percentil`) e nomear o método |

Nenhuma das três muda o veredito neste tenant. Todas mudam o número, e a camada 3 do modelo exige
que o leitor consiga refazer a conta — por isso as três vão escritas em `EVIDENCIA[M4]`.

**`severidade_modificada` agora mede a distorção por exceção.** No retorno de M4 esse campo vem
de `severity_modification_type`, que a API de Exposure Management não expõe — era ponto cego. Na
coleta do sandbox as 4 278 linhas vieram `NONE`: nenhum recast, nenhuma aceitação, então nenhuma
severidade do assessment está inflada ou deflacionada por exceção. Quando houver linhas diferentes
de `NONE`, contar e declarar por severidade: é a única medição direta que a skill tem do que as
exceções escondem, e vale para S3, P1 e P2, não só para M4.

Em `EVIDENCIA[M4]`, além dos campos padrão, registrar: `export_uuid` e `coletado_em_utc`,
`filtros_pedidos`, `filtros_divergiram`, `registros_analisados`, `pct_em_lote` **com o corte de
lote usado**, os estados incluídos no cálculo **com a contagem de `REOPENED` excluída**, o método
de percentil, a contagem de `severidade_modificada != NONE`, `n` e composição nativo/derivado por
severidade, e o estágio de cada severidade antes do mínimo.
A camada 3 do modelo exige que o leitor consiga refazer a conta.

---

## Passo 3 — Classificar

### 3.1 Estágio por indicador

Comparar o valor contra os quatro cortes, respeitando `invertido` quando menor é melhor.
Indicadores marcados `informativo` — S4 e V1 — **não** pontuam.

`P3` tem tabela de estágio própria, composta pelo critério que o cliente declara no Passo 0 e pela
oportunidade medida no backlog. Ver `references/indicadores-maturidade.md`. **P3 depende de P2:**
se P2 estiver em lacuna, P3 também.

Resultado: **17 indicadores pontuáveis**, cada um em um dos cinco estágios — 16 quando M4 vira
lacuna, o que agora acontece por mérito (guarda de cadência) ou por falha de coleta, não por
ausência de arquivo.

### 3.2 Estágio por estágio CTEM

Média dos estágios dos indicadores pontuáveis daquele estágio, arredondada para baixo. Arredondar
para baixo é deliberado: maturidade se demonstra, não se presume.

**A escala é o estágio, não a quantidade de indicadores.** Cada indicador é primeiro traduzido para
um dos cinco estágios pelos seus quatro cortes; só depois entra na média. Um estágio com três
indicadores alcança Optimized normalmente — basta que os três caiam em Optimized. Não há
normalização a fazer, porque a conversão para a escala de 1 a 5 já aconteceu indicador por
indicador.

Exemplo, para deixar concreto no relatório: **Scoping chega a Optimized** quando S1 ≥ 95%,
S2 ≥ 90% e S3 ≥ 90%.

**Nenhum estágio é classificado com menos de 2 indicadores com dado.** Com 0 ou 1, o estágio vira
`lacuna` e não entra em nada.

### 3.2.1 Assimetria de sustentação — declarar sempre

Os estágios **não têm o mesmo número de indicadores pontuáveis**:

| Estágio CTEM | Indicadores pontuáveis | Informativos |
|---|---|---|
| Scoping | 3 — S1, S2, S3 | S4 |
| Discovery | **4** — D1, D2, D3, D4 | — |
| Prioritization | 3 — P1, P2, P3 | — |
| Validation | 3 — V2, V3, V4 | V1 |
| Mobilization | **4** — M1, M2, M3, M4 | — |

Total: **17 pontuáveis**, **16** quando M4 vira lacuna. 2 informativos.

**M4 continua condicional, mas por outra razão.** Não depende mais de um arquivo existir: o
`ctem_mobilization` sempre tenta coletá-lo. M4 vira lacuna quando:

| Causa | O que é |
|---|---|
| a guarda de cadência dispara | **resultado, não falha** — o MTTR ali mede intervalo entre scans |
| o export estoura `max_wait_s` | lacuna **recuperável**: retomar pelo `export_uuid` |
| o job aplica recorte diferente do pedido | erro estruturado — o recorte não é a pergunta |
| n abaixo de `n_minimo_por_severidade` | amostra pequena demais para a severidade pontuar |

Em qualquer desses casos Mobilization volta a três indicadores e o total cai para 16. O portão de
confiança do Passo 4 é proporcional justamente para absorver isso sem recalibração manual.

A distribuição está quase equilibrada — três estágios com três indicadores, Discovery e
Mobilization com quatro.
Ainda assim o relatório é obrigado a mostrar a sustentação, porque um estágio com menos indicadores
se move com menos evidência.

Regras concretas:

1. Cada estágio aparece no relatório com **`n` sustentando**: "Prioritization — Advanced,
   sustentado por 3 de 3 indicadores".
2. Quando um estágio é classificado com **menos de 3 indicadores com dado** — por lacuna, não por
   desenho — e é ele que define o estágio efetivo, a skill acrescenta em destaque: *"o estágio
   efetivo está sustentado por apenas N indicadores; confirmar antes de transformar em plano de
   investimento"*.
3. A aba de metodologia repete a tabela acima, para o leitor saber o peso de cada estágio.

### 3.3 Os dois números do cliente, lado a lado

```
estagio_efetivo = menor entre os cinco estágios avaliados
estagio_medio   = média aritmética dos estágios avaliados, arredondada para baixo
```

**A diferença entre os dois é o argumento central do relatório.** Um cliente com médio
`Standardized` e efetivo `Ad Hoc` tem investimento em ferramenta que não vira resultado por causa de
um estágio bloqueante — e esse estágio é exatamente o escopo do serviço a vender. Quando os dois
coincidem, a evolução é incremental e distribuída, e a conversa muda de "corrigir uma lacuna" para
"subir um patamar".

**A skill é obrigada a nomear, em texto, qual estágio está puxando o efetivo para baixo**, e por
qual indicador. Não basta mostrar o número.

Justificativa do desenho, para o relatório: o efetivo usa o elo mais fraco porque os estágios do
CTEM são sequencialmente dependentes — sem contexto de negócio no Scoping, a priorização a jusante
já está comprometida, por boa que seja a ferramenta.

---

## Passo 4 — Portão de confiança

Antes de publicar qualquer estágio:

O portão é **proporcional aos pontuáveis daquela run**, não a um número fixo. Isso é necessário
porque M4 é condicional: 17 pontuáveis quando M4 pontua, 16 quando ele vira lacuna.

```
P        = pontuáveis aplicáveis nesta run   (17 com M4, 16 sem)
medidos  = pontuáveis que retornaram dado
normal   = teto(0,8125 × P)
com_aviso= teto(0,6250 × P)
```

| Condição | Comportamento |
|---|---|
| `medidos >= normal` | Classificar normalmente |
| `com_aviso <= medidos < normal` | Classificar, com aviso em destaque de que a base é parcial e listando o que falta |
| `medidos < com_aviso` | **Não classificar.** Entregar os indicadores disponíveis e o que precisa ser habilitado no tenant |
| `CONFIG.classificarEstagio = false` | **Não classificar**, independente da contagem. Entregar os 19 com faixas e distâncias até o corte seguinte |

Os dois coeficientes vêm da calibração original de 2026-09-02 (13 e 10 sobre 16) e a reproduzem
exatamente: `teto(0,8125 × 16) = 13` e `teto(0,6250 × 16) = 10`. Com 17 pontuáveis os cortes
passam a **14** e **11**. Arredondar para cima aqui, ao contrário do estágio — o portão protege
contra classificar com base fina, então o empate resolve pelo lado estrito.

O relatório é obrigado a imprimir `medidos / P` e qual dos três ramos foi aplicado.

No modo sem classificação, cada indicador ainda mostra a distância até o corte seguinte — "faltam
6 pontos percentuais em S1 para Advanced" — porque é isso que orienta ação sem cravar rótulo.

---

## Passo 5 — Roadmap de três quarters

Ordenar as lacunas por **esforço estimado contra impacto no estágio efetivo**. Impacto vem de quanto
o indicador está abaixo do corte seguinte e de quantos estágios ele destrava. Esforço é classificado
em três níveis, e o critério vai declarado:

| Esforço | Critério | Exemplos |
|---|---|---|
| Baixo | configuração no console, sem projeto | criar categoria de tag, ajustar agendamento de scan |
| Médio | projeto de semanas, com envolvimento de outra equipe | taguear a base instalada, implantar agente numa faixa de ativos |
| Alto | mudança de processo ou de contrato | licenciar superfície nova, redesenhar o processo de priorização |

Regra de sequenciamento: **primeiro o que destrava o estágio efetivo**, mesmo que o impacto
absoluto pareça menor. Subir Scoping de Ad Hoc para Defined vale mais que otimizar Mobilization,
porque o efetivo é o elo mais fraco.

Cada item do roadmap traz: indicador alvo, valor atual, corte a alcançar, esforço, e o que
concretamente fazer. Sem prazo em data — o relatório usa Q1, Q2, Q3 relativos ao início do projeto.

**Não converter melhoria de estágio em economia financeira** sem premissa fornecida pelo cliente.

---

## Passo 6 — Dashboard

Documento HTML único e autocontido, CSS e JS embutidos. Entregar na conversa e como arquivo.

### Forma dos gráficos — decisão deliberada

O radar tem duas fraquezas reais: distorce a área percebida, porque a área cresce com o quadrado do
valor, e a ordem dos eixos muda a forma do polígono com dados idênticos. A barra horizontal não tem
nenhuma das duas, e é a forma certa para comparar magnitude entre cinco categorias nomeadas.

Mas o radar tem uma força que a barra não tem: é o formato que a audiência de assessment reconhece
sem explicação, e é superior para sobrepor duas medições na reavaliação.

**Decisão: usar os dois na aba de Panorama**, radar em cima para reconhecimento e barra embaixo para
leitura, com as armadilhas do radar neutralizadas pelas regras abaixo.

**Duas formas na aba de Panorama, nesta ordem — decidido em 2026-09-02.**

**Em cima, o radar dos cinco estágios.** Pentágono com um eixo por estágio, escala de 1 a 5, anéis
de grade nos cinco níveis. Serve ao reconhecimento: assessment de maturidade usa radar há décadas e
o cliente entende sem explicação. O vértice do estágio bloqueante recebe a cor de acento.

Regras obrigatórias do radar, porque ele tem duas armadilhas conhecidas:
- **Ordem dos eixos fixa na sequência do CTEM** — Scoping, Discovery, Prioritization, Validation,
  Mobilization. Nunca reordenar, nem alfabeticamente nem por valor: a mesma medição em ordem
  diferente produz polígono de forma diferente, e o leitor lê forma.
- **Valor numérico impresso em cada vértice.** O olho lê área, e a área cresce com o quadrado do
  valor — um estágio 4 parece quatro vezes um estágio 2, não o dobro. O número ao lado do vértice
  corrige a leitura.

**Embaixo, a barra horizontal com ênfase.** Uma barra por estágio, escala comum de 1 a 5, linha de
base única. O estágio que define o efetivo em acento, os outros quatro em cinza de recessão, rótulo
direto com valor e nome do estágio. Duas marcas verticais discretas indicam o estágio efetivo e o
médio. É aqui que o valor se lê com precisão, e é aqui que o elo mais fraco salta.

A régua de escala fica alinhada ao mesmo referencial das barras: a marca do valor `v` em
`v / 5` da largura da trilha, **não** distribuída igualmente pela largura. Conferir na
renderização — é erro fácil de cometer e passa despercebido.

**Clique no estágio abre o resumo dos indicadores.** Tanto o vértice do radar quanto a barra são
clicáveis, com alvo maior que a marca. O clique abre um painel compacto com **só o essencial**:

| Coluna | Conteúdo |
|---|---|
| Indicador | ID e nome curto |
| Valor | valor bruto medido |
| Estágio | o estágio que aquele indicador atingiu |

Nada mais nesse painel — sem fórmula, sem filtro, sem N, sem origem do limiar. No pé dele, um único
link **"ver detalhe"** que leva à aba de Indicadores já filtrada naquele estágio, onde estão as
colunas completas. Indicadores informativos aparecem no painel marcados como `informativo, não
pontua`, e os em lacuna como `lacuna declarada` — importa o operador ver que existem, mesmo sem
pontuar.

**Os 19 indicadores são tabela, não gráfico.** Mais de sete classes que todas carregam significado
pedem tabela. Uma linha por indicador, com valor, N, estágio atingido, corte seguinte, distância e
origem do limiar.

### Paleta — validada, não escolhida por gosto

Superfície `#44494B`, texto `#FFFFFF` e `rgba(255,255,255,.72)`. Fonte Inter ou system-ui.

`#E7FF00` é **acento**, nunca cor de série. Use para o estágio bloqueante e o número em destaque.

Estágio é escala ordinal, então rampa sequencial de um matiz, validada contra `#44494B`:

| Estágio | Hex |
|---|---|
| Ad Hoc | `#FFF0DC` |
| Defined | `#FFC894` |
| Standardized | `#FF9A45` |
| Advanced / Optimized | `#EE7000` |

Cinza de recessão `#7E8688`, usado nas quatro barras que não são o estágio bloqueante e no polígono
da medição anterior na reavaliação. Neutro de ausência de dado `#9AA3A6`, **sempre com hachura a 45°
e rótulo** — lacuna não pode parecer um nível de maturidade.

No radar: contorno do polígono em `#FF9A45` com preenchimento `rgba(255,154,69,.30)`, vértices em
`#FF9A45` e o vértice do estágio bloqueante em `#E7FF00`. Anéis de grade em
`rgba(255,255,255,.10)`, o anel externo em `rgba(255,255,255,.22)`.

> **Não usar a dupla azul `#4EA5FF` + roxo `#BB8FF2` na mesma série.** Verificado com validador:
> ΔE de 2,5 em protanopia e 13,4 em visão normal, abaixo do piso de 15. São indistinguíveis para
> parte dos leitores.

Barras finas, extremidade arredondada de 4px na linha de base, gap de 2px entre segmentos, grid e
eixos recessivos, texto em cor de texto e nunca na cor da série, tooltip por marca no hover,
**uma escala por eixo e nunca eixo duplo**, e visão de tabela em toda aba com gráfico.

### Controles no cabeçalho — obrigatórios

**Seletor de idioma PT-BR / EN / ES.** Três botões no canto superior direito, o ativo marcado com
`aria-pressed="true"` e fundo de acento. A troca **re-renderiza tudo sem recarregar a página**:
KPIs, abas, gráficos, tabelas, roadmap e a aba de metodologia. Nada de recarregar nem de perder a
aba em que o leitor estava.

Implementação: um dicionário `L` com as três línguas para os rótulos e um dicionário `D` com os
dados que mudam de idioma — nomes de indicador, itens do roadmap, limitações, fórmulas. Uma função
`render()` que reconstrói o documento a partir de `L[LANG]` e `D[LANG]`, e uma `applySections()` que
reaplica a aba corrente. `setLang()` só troca `LANG` e chama `render()`.

**Botão "Exportar HTML".** Gera um arquivo único, autocontido e **com todas as funções do artefato
preservadas** — abas, cliques no radar e nas barras, drill-down, troca de idioma e a própria
exportação. Serve para o parceiro mandar ao cliente e o cliente abrir offline, sem depender de nada.

Implementação, e cada detalhe abaixo veio de um defeito encontrado em teste:

```javascript
function exportHTML(){
  const clone = document.documentElement.cloneNode(true);
  clone.setAttribute('data-lang', LANG);          // o exportado abre no idioma exportado
  const html = '<!DOCTYPE html>\n' + clone.outerHTML;
  const blob = new Blob([html], {type:'text/html;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'maturidade-ctem-' + LANG + '-<data>.html';
  document.body.appendChild(a); a.click(); a.remove();
}
```

E na inicialização:

```javascript
let LANG = document.documentElement.getAttribute('data-lang') || 'pt-br';
```

**Três armadilhas, todas encontradas em teste e todas obrigatórias de evitar:**

1. **Não mexer no atributo `hidden` das seções no clone.** A primeira versão removia `hidden` de
   todas as seções para "garantir que aparecessem", e o arquivo exportado abria com as cinco abas
   empilhadas de uma vez. A visibilidade tem de ser aplicada por `applySections()` na carga, não
   gravada no HTML.
2. **Passar o idioma pelo `data-lang` do `<html>`.** Sem isso o `let LANG` volta ao default e o
   arquivo exportado do inglês abre em português — exatamente o oposto do que o parceiro quer ao
   mandar para um cliente estrangeiro.
3. **Nada de recurso externo.** Sem CDN, sem fonte remota, sem imagem por URL. CSS e JS embutidos e
   imagens em `data:` URI. O arquivo tem de funcionar com o notebook desconectado.

Confirmar em teste, abrindo o arquivo exportado: uma só aba visível na carga, idioma correto,
troca de aba, drill-down, troca de idioma e re-exportação a partir do próprio exportado.

### Estrutura

```
header (título + seletor de idioma + exportar) → barra de KPIs → abas 1..5 → rodapé com fontes
```

**Barra de KPIs (5):** estágio efetivo · estágio médio · estágio que limita o conjunto ·
indicadores com dado, sobre os pontuáveis daquela run (17 com M4, 16 sem) ·
dias desde a última avaliação.

**Aba 1 — Panorama.** O radar dos cinco estágios, e abaixo dele a barra com ênfase. Depois, em
texto, a frase que nomeia o estágio bloqueante e o indicador responsável. Por último a tabela dos
cinco estágios com o estágio atingido e **quantos indicadores sustentaram cada um**.

Na **reavaliação**, quando o operador informa o resultado de uma execução anterior, o radar passa a
mostrar os dois polígonos sobrepostos — medição anterior em cinza de recessão, atual em laranja —
com legenda e as datas. É o caso em que o radar é claramente melhor que a barra, e o motivo de ele
estar aqui.

**Aba 2 — Indicadores.** A tabela dos 19, agrupada por estágio CTEM, com a coluna de origem do
limiar visível. Indicadores informativos e em lacuna marcados como tal. P3 mostra as duas partes que o compõem: o critério declarado e a oportunidade medida.

**Aba 3 — Critérios oficiais Tenable.** Os oito critérios, cada um com os indicadores da skill que
o compõem e o estágio resultante. É a aba que permite comparar com uma avaliação oficial que o
cliente já tenha respondido.

**Aba 4 — Roadmap.** Três quarters, itens ordenados, com esforço, impacto e o que fazer. O item que
destrava o estágio efetivo em destaque no Q1.

**Aba 5 — Metodologia e limitações.** Aba de primeira classe. Contém, nesta ordem: a tabela
`PREFLIGHT` completa; a declaração de cobertura e ponderação da amostra de plugins com os
intervalos de confiança; as fórmulas; as lacunas declaradas, cada uma com a causa nomeada e a
evidência que a sustenta; a **tabela de proposta confirmada do Passo 0**, com a coluna "como
cheguei nele" preservada; e a **tabela dos quatro perfis de limiar**, para o leitor saber qual
régua foi usada e o que as outras mudariam.

**São cinco abas, e só cinco.** Pré-voo e evidência **não** são abas próprias: eles vivem dentro
da Metodologia, porque o leitor que quer o número vai ao Panorama e o leitor que quer auditar vai
a um lugar só. Abrir aba para cada um deles espalha a auditoria e faz o relatório parecer um
relatório de ferramenta, não de assessment.

---

## Bloco de configuração

Vai no SKILL.md e é sobrescrevível na execução. Os perfis `conservador` e `agressivo` deslocam
todos os cortes em bloco; `custom` substitui indicador por indicador.

```yaml
maturity_config:
  perfil: default              # default | conservador | agressivo | custom
  classificar_estagio: true    # false = modo indicador puro, Passo 4
  arredondamento: baixo        # sempre para baixo; maturidade se demonstra
  agregacao: ambos             # ambos = efetivo e médio lado a lado (recomendado)
                               # minimo = só o elo mais fraco | media = só a média
  minimo_indicadores_por_estagio: 2
  portao_de_confianca:
    modo: proporcional         # proporcional (recomendado) | absoluto
    coef_normal: 0.8125        # teto(coef × pontuáveis). Em 16 dá 13; em 17 dá 14
    coef_com_aviso: 0.6250     # em 16 dá 10; em 17 dá 11
  mttr:
    dias: 180                  # janela do POST /vulns/export
    severidades: [critical, high]   # M4 pontua pelo menor estágio das duas
    max_wait_s: 240            # ao estourar, M4 vira lacuna RECUPERÁVEL com export_uuid
    n_minimo_por_severidade: 5 # abaixo disso a severidade não pontua em M4
    max_derivado_pct: 30       # acima disso M4 pontua com ⚠️ de composição
    pct_em_lote_max: 40        # acima disso M4 vira lacuna (guarda de cadência)
    lote_minimo_por_janela: 2  # findings na mesma janela para contar como lote. Ver nota abaixo
    metodo_percentil: interpolado   # interpolado | posicao_mais_proxima — precisa bater com o coletor
  amostra_plugins:
    n: 30                      # subiu de 20 em 2026-09-03: com N=10 o IC tem 50 pontos de largura
    n_teto: 60                 # limite da ampliação adaptativa
    alocacao: proporcional     # proporcional à fatia real de cada estrato na população
    piso_estrato_b: 4          # o estrato B existe para achar casos, não para estimar taxa
    ponderar: por_deteccao     # por_deteccao | por_plugin — base dos pesos ao combinar estratos
    portao_ic: true            # amplia em blocos de 10 enquanto o IC 95% atravessar um corte
    modo_plugins: auto         # auto | censo | amostra. SUBSTITUI censo_d4_m3.
                               # O censo passou a ser alcançável: plugins_search_plugins não aceita
                               # lista de IDs, mas plugin_details_batch aceita. Medido em
                               # 2026-09-04: 121 plugins críticos em 64 s e ~5.400 tokens.
                               # No censo não há IC, ponderação nem alocação — a taxa é a contagem.
    limite_censo: 300          # acima disso volta a amostra estratificada
  corte_priorizacao_cliente:
    metrica: vpr               # vpr | cvss3. Default: vpr
    valor: 7.0                 # default VPR >= 7.0
    confirmado: false          # true só quando o operador responde a Pergunta 10 ativamente.
                               # false = default aceito sem verificação com o cliente; P3 pontua,
                               # e o relatório é obrigado a escrever que o critério foi assumido
  referencia_prazo: cisa_bod_26_04   # cisa_bod_26_04 | sla_do_cliente | nenhum
  sla_do_cliente:
    critical_dias: null
    high_dias: null
  superficies_licenciadas: [VM]
  mapeamento_cliente:           # respostas da Fase B do Passo 0, reusar na reavaliação
    categoria_criticidade: null
    valores_maior_criticidade: []
    categoria_owner: null
    categoria_ambiente: null
    categoria_localidade: null      # só agrupa o roadmap; não filtra escopo
    valores_producao: []
    scans_recorrentes: []
    excluir: null
    usa_excecoes: nao_sei       # nao_usa | usa_pouco | usa_muito | nao_sei
  cortes:
    S1: [20, 50, 80, 95]
    S2: [10, 40, 70, 90]
    S3: [10, 40, 70, 90]
    D1: [90, 45, 14, 7]        # invertido
    D2: [25, 50, 75, 90]    # percentual das superficies licenciadas, nao contagem
    D3: [20, 50, 75, 90]
    D4: [25, 50, 75, 90]
    P1: [10, 40, 70, 90]     # redefinido em 2026-09-02: contexto de negocio no backlog critico
    P2: [40, 70, 90, 98]
    P3: composto             # critério declarado + oportunidade medida; tabela própria
    P3_oportunidade: [0.50, 0.20]   # cortes usados quando o cliente prioriza por CVSS
    V2: [180, 90, 30, 14]      # invertido, ancorado na CISA BOD 26-04
    V3: [25, 15, 8, 3]         # invertido. PERCENTUAL, como todo corte de taxa aqui
    V4: [30, 15, 7, 2]         # invertido
    M1: [90, 45, 14, 7]        # invertido. Intervalos entre DIAS distintos de avaliação
    colapsar_runs_do_mesmo_dia: true   # ver a nota de M1 abaixo. Nunca desligar sem declarar
    M2: [180, 90, 30, 14]      # invertido
    M3: [180, 90, 30, 14]      # invertido
    M4_critical: [90, 30, 15, 7]   # invertido. p50 de dias_para_corrigir, severidade Critical
    M4_high: [180, 60, 30, 14]     # invertido. p50 de dias_para_corrigir, severidade High
  invertidos: [D1, V2, V3, V4, M1, M2, M3, M4]
  informativos: [S4, V1]       # não pontuam estágio
  # P3 tem tabela de estágio própria e depende de P2 — ver references/indicadores-maturidade.md
```

**Perfis, aplicados sobre os cortes default:**

| Perfil | Efeito nos cortes | Quando usar |
|---|---|---|
| `default` | os cortes acima, como estão | assessment padrão. É o único perfil já rodado contra um tenant real |
| `conservador` | cortes percentuais **+10 pontos** · cortes de dias **−30%** | cliente regulado, ou quando o assessment precisa ser defensável em auditoria. O mesmo tenant tende a pontuar um estágio abaixo |
| `agressivo` | cortes percentuais **−10 pontos** · cortes de dias **+30%** | conversa inicial de adoção, para não travar tudo em Ad Hoc e perder o valor do diagnóstico. Declarar o perfil é obrigatório aqui: sem isso o número parece melhor do que a régua padrão diria |
| `custom` | carrega um bloco `maturity_config` próprio, corte por corte | cliente com SLA interno definido, ou parceiro que padronizou a própria régua entre contas. Todo corte sobrescrito aparece marcado como `sobrescrito pelo operador` na tabela de indicadores |

**O perfil desloca a régua, nunca a fórmula nem a fonte de dado.** Escolher perfil é escolher com
que severidade se lê o mesmo número. Por isso ele é uma das respostas da tela de confirmação do
Passo 0, e por isso o relatório precisa mostrar as quatro opções — o leitor tem de saber que o
resultado que está vendo depende de uma régua escolhida, e qual.

O perfil escolhido vai declarado no relatório. Trocar de perfil entre reavaliações **invalida a
comparação** — a skill deve avisar em destaque se o perfil da execução atual for diferente do
registrado numa execução anterior informada pelo operador.

---

## ACR e AES em ativo novo — pendente não é lacuna

**Ativo visto pela primeira vez ainda não tem ACR nem AES.** A Tenable calcula esses valores em até
24 horas do primeiro scan. Antes disso as propriedades vêm nulas, e isso **não** é lacuna de
maturidade nem valor zero — é cálculo em andamento.

Verificação obrigatória, antes de qualquer indicador que toque ACR ou AES:

```
pendentes = assets(asset_class = DEVICE) com acr ausente
```

Comportamento:

| Situação | Comportamento |
|---|---|
| Nenhum ativo pendente | Seguir normalmente |
| Alguns pendentes | Calcular o indicador **excluindo os pendentes do denominador** e declarar quantos ficaram de fora e por quê |
| Todos pendentes | O indicador vira `pendente de cálculo`, **não** `lacuna` e **nunca** zero. O relatório informa que a reexecução após 24 horas do primeiro scan terá o valor |

**Aviso obrigatório no topo do relatório** quando houver qualquer pendente, no idioma escolhido:

> PT: *"ACR e AES pendentes de cálculo em N de M ativos DEVICE. Esses ativos foram vistos pela
> primeira vez no scan mais recente e a Tenable calcula os valores em até 24 horas. Reexecutar depois
> desse prazo para ter a leitura completa."*

**Nota de desenho que reduz o impacto disso:** nesta skill o contexto de negócio é medido por **tag
de criticidade**, não por ACR — justamente porque o ACR é automático e o MCP não revela se foi
ajustado por humano. Por isso, num tenant recém-escaneado, o único indicador sem base é o S4, que é
informativo e não pontua. Um assessment que dependesse de ACR para pontuar ficaria inutilizável nas
primeiras 24 horas de um ambiente novo.

---

## Tratamento de lacunas

| Situação | Comportamento |
|---|---|
| Consulta vazia ou com falha | Indicador vira `lacuna`. **Nunca zero** — zero é um valor, lacuna é ausência |
| Filtro reprovado no pré-voo | Indicador vira `lacuna`, e o relatório mostra o filtro e os dois totais |
| Operador respondeu "Nenhuma" num mapeamento | O indicador vira **lacuna com causa nomeada** — "o cliente não tem categoria de tag de owner" — que é achado de Scoping e item de roadmap, não falha de ferramenta |
| Cliente usa regras de exceção | Nenhum cálculo muda, porque o MCP não expõe o campo. A ressalva da Pergunta 8 entra no relatório |
| Estágio com menos de 2 indicadores | Estágio vira `lacuna` e sai do cálculo do efetivo e do médio |
| `medidos < teto(0,625 × P)` pontuáveis com dado | Não classificar. Entregar indicadores e o que habilitar |
| Export de MTTR falhou ou estourou o tempo | M4 vira lacuna com causa nomeada, `P` cai para 16 e o portão se ajusta. Se houver `export_uuid` na causa, a lacuna é **recuperável**: retomar. **Nunca** estimar MTTR |
| `filtros_divergiram = true` | O servidor devolve **erro estruturado**, não número: o recorte não é o pedido. M4 vira lacuna |
| Guarda de cadência disparou | M4 vira lacuna. O número mediria cadência, que M1 e M2 já medem. O achado vai escrito no relatório — é resultado, não falha |
| Retorno sem corte de lote, estados ou método de percentil declarados | Não deve acontecer: o servidor declara os três. Se faltar, tratar como lacuna. Defaults da skill (lote ≥ 2, só `FIXED`, percentil interpolado) e declarar o recálculo. **Nunca** aceitar o número do resumo sem saber o método |
| `severidade_modificada_diferente_de_none > 0` | Contar por severidade e declarar. Sem esse campo o assessment é cego a recast e aceitação — com ele, a ressalva é obrigatória em S3, P1, P2 e M4 |
| Superfície não licenciada | Mensagem clara de superfície não licenciada. Nunca falhar, nunca reportar zero |
| Tenant sem histórico de scan | D1, M1 e M2 viram lacuna. Declarar que o estágio Mobilization ficou sem base |
| Última avaliação há mais de 30 dias | Abrir o relatório com aviso de dado defasado e a data |
| ACR ou AES ausente em ativo novo | `pendente de cálculo`, nunca lacuna e nunca zero. Excluir do denominador e declarar |
| Detalhe de plugin indisponível | Contar à parte. **Nunca** tratar ausência de dado como ausência de exploit |
| IC 95% da amostra atravessa um corte no teto de N | **Não classificar** aquele indicador. Reportar a faixa e dizer que a amostra não separa os dois estágios |
| Ativos com nome repetido | Achado de padronização de nomenclatura, **não** duplicidade de inventário. Se cada um tem agente próprio, são ativos distintos e o denominador está correto |

---

## Rótulos por idioma

| Elemento | PT-BR | EN | ES |
|---|---|---|---|
| Título | Avaliação de Maturidade CTEM | CTEM Maturity Assessment | Evaluación de Madurez CTEM |
| Estágio efetivo | Estágio efetivo | Effective stage | Etapa efectiva |
| Estágio médio | Estágio médio | Average stage | Etapa promedio |
| Estágio que limita | Estágio que limita o conjunto | Limiting stage | Etapa limitante |
| Aba 1 | Panorama | Overview | Panorama |
| Aba 2 | Indicadores | Indicators | Indicadores |
| Aba 3 | Critérios oficiais Tenable | Official Tenable criteria | Criterios oficiales de Tenable |
| Aba 4 | Roadmap | Roadmap | Hoja de ruta |
| Aba 5 | Metodologia e limitações | Methodology and limitations | Metodología y limitaciones |
| Estágios | Ad Hoc · Definido · Padronizado · Avançado · Otimizado | Ad Hoc · Defined · Standardized · Advanced · Optimized | Ad Hoc · Definido · Estandarizado · Avanzado · Optimizado |
| Scoping | Escopo | Scoping | Alcance |
| Discovery | Descoberta | Discovery | Descubrimiento |
| Prioritization | Priorização | Prioritization | Priorización |
| Validation | Validação | Validation | Validación |
| Mobilization | Mobilização | Mobilization | Movilización |
| Lacuna declarada | Lacuna declarada | Declared gap | Brecha declarada |
| Informativo | Informativo, não pontua | Informational, not scored | Informativo, no puntúa |
| Origem do limiar | Origem do limiar | Threshold source | Origen del umbral |
| Exportar | Exportar HTML | Export HTML | Exportar HTML |
| Arquivo gerado | Arquivo gerado | File generated | Archivo generado |
| Pendente de cálculo | Pendente de cálculo | Pending calculation | Pendiente de cálculo |
| Critério da skill | Critério da skill, não da Tenable | Skill criterion, not Tenable's | Criterio de la skill, no de Tenable |
| Distância até o próximo | Falta para o próximo estágio | Gap to next stage | Falta para la próxima etapa |
| Esforço | Baixo · Médio · Alto | Low · Medium · High | Bajo · Medio · Alto |

---

## Notas de precisão

1. **Separar fato de interpretação.** O relatório distingue dado do tenant, cálculo da skill e
   recomendação. O indicador é dado; o estágio é cálculo; o roadmap é recomendação.
2. **Nenhum limiar por estágio é oficial da Tenable.** Rotular indicador por indicador.
3. **Lacuna não é zero.** Um indicador sem dado nunca vira zero, nem entra em média.
4. **Arredondar estágio para baixo.** Maturidade se demonstra.
5. **A BOD 26-04 é referência**, não obrigação do cliente, salvo se ele for agência federal dos EUA.
6. **MTTR vem de fora do MCP, e a origem vai escrita.** O MCP não expõe `last_fixed` nem
   `time_taken_to_fix` — os dois vivem na API de Vulnerability Management, em `POST /vulns/export`.
   M4 só pontua quando a guarda de cadência libera; do contrário é lacuna declarada, nunca
   estimativa. Quando pontua,
   o relatório mostra a composição nativo/derivado e o `n` de cada severidade. Cadência de
   avaliação (M1, M2) continua medindo outra coisa e medindo bem: **MTTR pergunta quanto tempo se
   leva para fechar; cadência pergunta se se está olhando.**
7. **Percentual de amostra não é percentual de backlog.** Declarar a cobertura.
8. **Não converter maturidade em número financeiro** sem premissa do cliente.

---

## Gancho de serviço para o parceiro

1. **Assessment inicial pago.** O diagnóstico é o produto: dezenove indicadores medidos, estágio
   efetivo e médio, e o estágio bloqueante nomeado.
2. **Execução das lacunas.** O roadmap de três quarters já vem ordenado por esforço e impacto, e o
   Q1 é a proposta de trabalho imediata.
3. **Reavaliação trimestral.** Rodar de novo mostra movimento de estágio com a mesma régua. É o que
   transforma o assessment em contrato recorrente em vez de entrega única.

O argumento mais forte é a diferença entre estágio médio e efetivo: mostra ao cliente que ele já
pagou por capacidade que não está convertendo em resultado, e aponta exatamente onde.

---

## Fontes citáveis no relatório

- Tenable — Exploring the Exposure Management Maturity Model: https://www.tenable.com/blog/exploring-the-exposure-management-maturity-model
- Tenable — Exposure Management Maturity Assessment, os oito critérios: https://assess.tenable.com/exposure-management-maturity-assessment
- Tenable — How to chart a path to exposure management maturity: https://www.tenable.com/guides/how-to-chart-a-path-to-exposure-management-maturity
- Tenable Docs — Exposure Management Metrics, faixas de CES, AES, ACR e VPR: https://docs.tenable.com/exposure-management/Content/getting-started/metrics.htm
- Tenable — CISO's guide to CISA BOD 26-04: https://www.tenable.com/blog/bod-26-04-ciso-reporting-risk-metrics
- Tenable — VPR Drivers: https://developer.tenable.com/docs/vpr-drivers-tio
