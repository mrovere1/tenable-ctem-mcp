# Roteiro de execução — OBSOLETO desde 2026-09-04

> **Este roteiro descrevia a execução manual do coletor `tenable_mttr_export.py` no terminal do
> operador, com o CSV alimentando M4.** Esse caminho não existe mais: `ctem_mobilization` chama
> `mttr_collect` internamente, e o coletor saiu do pacote da skill.
>
> O coletor continua existindo como **origem do código** de `mttr.py` no servidor MCP e como
> gerador das fixtures dos golden tests — não como caminho de execução. Um caminho, não dois:
> se o MCP falhar, todos os indicadores falham, e manter contingência só para M4 não mudaria o
> resultado da skill.
>
> Ver `docs/tools.md` do `tenable-ctem-mcp` para o contrato de `mttr_collect` e
> `mttr_cadence_guard`, e `docs/troubleshooting.md` para 401, 409 e TLS.

---

O conteúdo abaixo fica registrado para quem precisar entender de onde vieram os números de
referência de 2026-09-03.

---

# Roteiro de execução — CTEM Maturity Assessment

Trilíngue: **PT-BR** abaixo, **EN** e **ES** nas seções seguintes. Versão longa, com
troubleshooting de TLS corporativo, erro 409 e tenant atípico: peça ao autor da skill o documento
`roteiro-execucao-parceiro.md`.

Duração típica: **10 min** de coleta (o export roda no servidor da Tenable) + **15 a 25 min** de
assessment, dependendo do tamanho do tenant.

---

## PT-BR

### 1. Pré-requisitos

| Item | Como confirmar |
|---|---|
| Python 3.9 ou superior | `python3 --version` |
| Chave de API do Tenable Vulnerability Management | console → **Settings › My Account › API Keys** |
| Permissão da chave | a chave precisa ver os findings que você quer medir. Chave de usuário com escopo reduzido devolve export parcial, e o resumo registra o volume — confira |
| Saída HTTPS para `cloud.tenable.com` | `curl -sI https://cloud.tenable.com` deve responder |
| MCP Tenable conectado nesta sessão | a skill valida no pré-voo e para se não estiver |

**FedRAMP ou região própria:** `export TIO_URL=https://sua-instancia.tenable.com`.

### 2. Coletar o CSV de MTTR

O coletor roda **no seu terminal**, com as chaves **no seu ambiente**. A skill nunca pede
credencial: ela pede o caminho do arquivo. O script não aceita chave por argumento nem por prompt.

```bash
# 1. valide a instalação, sem rede e sem chave
python3 scripts/tenable_mttr_export.py --autoteste

# 2. exporte as chaves nesta sessão de terminal
export TIO_ACCESS_KEY=xxxxxxxxxxxxxxxx
export TIO_SECRET_KEY=yyyyyyyyyyyyyyyy

# 3. colete: 180 dias, critical e high
python3 scripts/tenable_mttr_export.py --days 180 --severity critical,high
```

Saem dois arquivos no diretório atual:

- `tenable_mttr_findings_AAAAMMDD.csv` — uma linha por finding;
- `tenable_mttr_resumo_AAAAMMDD.json` — as estatísticas e o registro da coleta.

**Um export por chave de cada vez.** Um segundo pedido responde `409`; o script reaproveita o job
em andamento e avisa. Se o CSV já existe porque você rodou a skill `tenable-mttr-dashboard`,
**reuse o arquivo** em vez de coletar de novo.

**Se falhar na verificação de certificado** (rede corporativa que inspeciona TLS):

```bash
python3 scripts/tenable_mttr_export.py --diagnostico-tls        # diz a causa, não envia nada
python3 scripts/tenable_mttr_export.py --ca-macos-keychain ...  # macOS com proxy corporativo
export TIO_CA_BUNDLE=/caminho/do/bundle.pem                     # ou aponte o bundle da empresa
```

Sem CSV o assessment **roda**, com 16 indicadores em vez de 17: M4 vira lacuna declarada. O que
não acontece nunca é MTTR estimado.

### 3. Rodar o assessment

Peça em linguagem natural, informando o caminho do CSV:

> *"Rode o assessment de maturidade CTEM neste tenant. O CSV de MTTR está em
> `/caminho/tenable_mttr_findings_20260903.csv`."*

A skill faz, nesta ordem:

1. **Fase A — descoberta silenciosa.** Lê categorias de tag, classes de ativo, scans, histórico e
   agentes. Não pergunta nada ainda.
2. **Fase B — 14 perguntas de confirmação**, já com os valores reais do tenant como opções.
   As que mais mudam o resultado:
   - **Pergunta 2 e 3** — qual categoria de tag é criticidade, e quais valores são os mais altos.
     A skill não sabe se `Tier 1` é maior que `Tier 2`, nem interpretar `Gold`/`Silver`. Sem essa
     resposta, S2 e P1 viram lacuna.
   - **Pergunta 6** — quais scans são a avaliação recorrente. Contar scan de POC e de teste junto
     produz cadência errada. Escolha só os que representam o ritmo real.
   - **Pergunta 9** — superfícies licenciadas. Marcar surface que o cliente não tem penaliza
     Discovery indevidamente.
   Responder *"Nenhuma"* é resposta válida: o indicador vira lacuna com a causa nomeada, e isso
   é um achado de Scoping, não falha da ferramenta.
3. **Pré-voo dos filtros do MCP.** Alguns filtros são aceitos e silenciosamente ignorados pela
   API. A skill testa cada um e publica a tabela `PREFLIGHT` no relatório.
4. **Coleta e classificação** dos 17 indicadores.
5. **Relatório HTML** com radar e barras lado a lado, clique para ver os indicadores do estágio,
   botões PT/EN/ES e botão de exportar um HTML offline para enviar ao cliente.

### 4. O que confirmar antes de enviar ao cliente

- [ ] A aba de metodologia mostra o mapeamento usado (categoria de criticidade, owner, ambiente,
      scans, exclusões). Sem isso, dois assessments do mesmo cliente não são comparáveis.
- [ ] O portão de confiança passou: **14 dos 17** indicadores com dado, ou 11 com aviso. Abaixo
      disso a skill entrega indicadores e **não** crava estágio — está correto, não force.
- [ ] ACR e AES presentes. Em ativo novo eles só existem ~24 h depois do primeiro scan.
- [ ] Se M4 pontuou, o relatório diz o corte de lote, os estados incluídos e o método de
      percentil. Se M4 virou lacuna por cadência de scan, o achado está escrito em texto — ele
      vale mais para o cliente que o número perdido.
- [ ] Salve o bloco YAML `mapeamento_cliente` que a skill oferece no fim. Na reavaliação, use o
      mesmo mapeamento e o mesmo perfil de limiares: trocar qualquer um invalida a comparação.

### 5. O que este assessment não mede

Patch Management e Cloud Security não entram: os tools `tenable_one_*` não alcançam esses dados.
Findings com risco aceito continuam contados no backlog, e um recast reduz a severidade reportada
— a Pergunta 8 determina a ressalva. Quando há CSV do coletor, a coluna `severidade_modificada`
mede isso diretamente e a ressalva passa a citar o número medido.

---

## EN

### 1. Prerequisites

Python 3.9+, a Tenable Vulnerability Management API key (console → **Settings › My Account › API
Keys**) whose scope covers the findings you want to measure, HTTPS egress to `cloud.tenable.com`,
and the Tenable MCP connected in this session. For FedRAMP or a dedicated region, set
`export TIO_URL=https://your-instance.tenable.com`.

### 2. Collect the MTTR CSV

The collector runs **in your terminal**, with the keys **in your environment**. The skill never
asks for credentials — it asks for the file path, and the script accepts no key by argument or
prompt.

```bash
python3 scripts/tenable_mttr_export.py --autoteste          # offline self-test, no key needed
export TIO_ACCESS_KEY=xxxxxxxxxxxxxxxx
export TIO_SECRET_KEY=yyyyyyyyyyyyyyyy
python3 scripts/tenable_mttr_export.py --days 180 --severity critical,high
```

Two files are written: `tenable_mttr_findings_YYYYMMDD.csv` and
`tenable_mttr_resumo_YYYYMMDD.json`. **One export per key at a time** — a second request returns
`409` and the script reuses the running job. Reuse an existing CSV instead of re-collecting.

TLS interception on a corporate network: `--diagnostico-tls` reports the cause without sending
anything, `--ca-macos-keychain` uses the macOS keychains, or point `TIO_CA_BUNDLE` at your
company bundle.

Without the CSV the assessment still runs, with 16 scored indicators instead of 17 — M4 becomes a
declared gap. MTTR is never estimated.

### 3. Run the assessment

> *"Run the CTEM maturity assessment on this tenant. The MTTR CSV is at
> `/path/tenable_mttr_findings_20260903.csv`."*

Phase A discovers the tenant silently; Phase B asks 14 confirmation questions with the tenant's
real values as options. The ones that most affect the result: **Q2/Q3** (which tag category is
asset criticality, and which of its values are the highest — the skill cannot know that `Tier 1`
outranks `Tier 2`), **Q6** (which scans are the recurring assessment — including POC and test
scans produces a wrong cadence), and **Q9** (licensed surfaces — claiming a surface the customer
does not own unfairly penalizes Discovery). Answering *"None"* is a valid answer: the indicator
becomes a gap with a named cause, which is a Scoping finding rather than a tool failure.

Then the MCP filter pre-flight (some filters are accepted and silently ignored by the API — the
skill tests each one and publishes the `PREFLIGHT` table), the 17 indicators, and an HTML report
with radar and bars side by side, click-through per stage, PT/EN/ES buttons and an offline-export
button.

### 4. Before sending it to the customer

Check that the methodology tab shows the mapping used; that the confidence gate passed (**14 of
17** indicators with data, or 11 with a warning — below that the skill delivers indicators and
does not assign a stage, which is correct); that ACR and AES are present (they appear ~24 h after
a new asset's first scan); that a scoring M4 states its batch cut-off, included states and
percentile method, or that a gap-by-cadence M4 has its finding written out in prose. Save the
`mapeamento_cliente` YAML block the skill offers at the end and reuse it, with the same threshold
profile, on the re-assessment — changing either invalidates the comparison.

### 5. Out of scope

Patch Management and Cloud Security are not covered: the `tenable_one_*` tools cannot reach that
data. Accepted-risk findings remain counted in the backlog and a recast lowers the reported
severity — Q8 sets the caveat. When the collector CSV is present, the `severidade_modificada`
column measures this directly and the caveat cites the measured number.

---

## ES

### 1. Requisitos previos

Python 3.9+, una clave de API de Tenable Vulnerability Management (consola → **Settings › My
Account › API Keys**) cuyo alcance cubra los findings que quiere medir, salida HTTPS hacia
`cloud.tenable.com` y el MCP de Tenable conectado en esta sesión. Para FedRAMP o una región
propia: `export TIO_URL=https://su-instancia.tenable.com`.

### 2. Recolectar el CSV de MTTR

El recolector se ejecuta **en su terminal**, con las claves **en su entorno**. La skill nunca pide
credenciales: pide la ruta del archivo, y el script no acepta claves por argumento ni por prompt.

```bash
python3 scripts/tenable_mttr_export.py --autoteste          # autotest sin red y sin clave
export TIO_ACCESS_KEY=xxxxxxxxxxxxxxxx
export TIO_SECRET_KEY=yyyyyyyyyyyyyyyy
python3 scripts/tenable_mttr_export.py --days 180 --severity critical,high
```

Se generan `tenable_mttr_findings_AAAAMMDD.csv` y `tenable_mttr_resumo_AAAAMMDD.json`. **Un export
por clave a la vez**: un segundo pedido responde `409` y el script reutiliza el trabajo en curso.
Si el CSV ya existe, reutilícelo en lugar de recolectar otra vez.

Con inspección TLS corporativa: `--diagnostico-tls` indica la causa sin enviar nada,
`--ca-macos-keychain` usa los llaveros de macOS, o apunte `TIO_CA_BUNDLE` al bundle de la empresa.

Sin el CSV el assessment **funciona**, con 16 indicadores en vez de 17: M4 queda como brecha
declarada. El MTTR nunca se estima.

### 3. Ejecutar el assessment

> *"Ejecute el assessment de madurez CTEM en este tenant. El CSV de MTTR está en
> `/ruta/tenable_mttr_findings_20260903.csv`."*

La Fase A descubre el tenant en silencio; la Fase B hace 14 preguntas de confirmación con los
valores reales del tenant como opciones. Las que más cambian el resultado: **P2/P3** (qué
categoría de etiqueta es la criticidad del activo y cuáles de sus valores son los más altos — la
skill no puede saber que `Tier 1` supera a `Tier 2`), **P6** (qué scans son la evaluación
recurrente — incluir scans de POC y de prueba produce una cadencia equivocada) y **P9**
(superficies licenciadas — marcar una que el cliente no tiene penaliza Discovery injustamente).
Responder *"Ninguna"* es una respuesta válida: el indicador queda como brecha con causa nombrada,
y eso es un hallazgo de Scoping, no una falla de la herramienta.

Después vienen el pre-vuelo de filtros del MCP (algunos filtros se aceptan y se ignoran en
silencio; la skill prueba cada uno y publica la tabla `PREFLIGHT`), los 17 indicadores y un
informe HTML con radar y barras lado a lado, detalle por etapa al hacer clic, botones PT/EN/ES y
un botón para exportar un HTML offline.

### 4. Antes de enviarlo al cliente

Verifique que la pestaña de metodología muestre el mapeo utilizado; que la compuerta de confianza
haya pasado (**14 de 17** indicadores con dato, u 11 con aviso — por debajo de eso la skill
entrega indicadores y **no** asigna etapa, y eso es correcto); que ACR y AES estén presentes
(aparecen ~24 h después del primer scan de un activo nuevo); y que un M4 que puntúa declare su
corte de lote, los estados incluidos y el método de percentil, o que un M4 en brecha por cadencia
tenga el hallazgo escrito en prosa. Guarde el bloque YAML `mapeamento_cliente` que la skill ofrece
al final y reutilícelo, con el mismo perfil de umbrales, en la reevaluación: cambiar cualquiera de
los dos invalida la comparación.

### 5. Fuera de alcance

Patch Management y Cloud Security no se cubren: las herramientas `tenable_one_*` no alcanzan esos
datos. Los findings con riesgo aceptado siguen contados en el backlog y un recast baja la
severidad reportada — la P8 define la salvedad. Con el CSV del recolector, la columna
`severidade_modificada` mide esto directamente y la salvedad cita el número medido.
