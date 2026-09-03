# Validação da coleta em `_dados/` — 2026-09-03

Fonte: `_dados/tenable_mttr_findings_20260903.csv` (4 278 linhas, 20 colunas) e
`_dados/tenable_mttr_resumo_20260903.json`. Método: recálculo independente de cada estatística a
partir do CSV, sem usar o resumo como referência, e comparação campo a campo.

## O que confere

| Campo | Resumo | Recálculo | Veredito |
|---|---|---|---|
| linhas totais | 4 278 | 4 278 | confere |
| estados | — | OPEN 4 239 · FIXED 31 · REOPENED 8 | confere com a soma |
| MTTR Critical média / p50 / p90 / máx | 52,93 / 42,94 / 101,43 / 178,07 | idênticos | confere |
| MTTR High média | 60,39 | 60,39 (só `FIXED`) | confere, com ressalva abaixo |
| origem `time_taken_to_fix` nativo | 100% | 100% (0 derivados) | confere |
| `severidade_modificada` | — | `NONE` nas 4 278 linhas | confere |

## Três divergências, todas por escolha de método não declarada

1. **`REOPENED` fora do MTTR.** O resumo calcula só sobre `FIXED`. Incluindo os 8 `REOPENED`, a
   média de High cai de **60,39 para 49,66 dias** (18%) e a de Medium de 95,95 para 64,08.
   A exclusão é defensável — um finding reaberto não foi corrigido — mas não está escrita.

2. **`pct_em_lote` subcontado.** O resumo publica **74,2%**. O coletor só conta um grupo como
   lote a partir de **3** findings na mesma janela `(ativo, first_found, last_fixed)` e descarta
   três grupos de 2. Com corte 2 o valor é **93,5%**. Sensibilidade no mesmo CSV:

   | corte de lote | findings em lote | % |
   |---|---|---|
   | ≥ 2 | 29 / 31 | 93,5% |
   | ≥ 3 | 23 / 31 | 74,2% |
   | ≥ 4 | 20 / 31 | 64,5% |
   | ≥ 5 | 12 / 31 | 38,7% |

   O corte 5 passaria a guarda de 40% da skill de maturidade e faria M4 pontuar. Por isso a skill
   passou a **recontar do CSV** em vez de ler o percentual do resumo.

3. **Método de percentil não nomeado.** `p90` de Critical é 101,43 interpolado e 92,91 por
   posição mais próxima. O resumo usa interpolado (confirmado), mas com n=10 a escolha muda o
   número em 9% e precisa estar declarada.

## O achado que importa mais que o percentual

As 9 janelas `(first_found, last_fixed)` observadas são **todas pares tirados de 7 datas**:
27/01, 08/03, 07/06, 08/06, 09/06, 02/09, 03/09 — as datas de scan do tenant. **29 dos 31**
findings corrigidos caem numa janela compartilhada com outro finding do mesmo ativo. O maior lote
tem 12 findings de um único ativo, todos com 85,51 dias exatos.

Neste tenant o MTTR **é** o intervalo entre scans: mede cadência de avaliação, não tempo de
correção. M4 é lacuna aqui pelos dois valores de `pct_em_lote`, 74,2% ou 93,5%.

## `severidade_modificada` fecha um ponto cego

O campo vem de `severity_modification_type` do `POST /vulns/export`, que a API de Exposure
Management não expõe — nenhum tool `tenable_one_*` alcança. As 4 278 linhas vieram `NONE`:
nenhum recast, nenhuma aceitação, portanto nenhuma severidade do assessment está distorcida por
exceção neste tenant. É a única medição direta de exceção que o assessment tem, e vale para S3,
P1 e P2, não só para M4.

## Alterações aplicadas em `tenable-ctem-maturity-assessment.skill`

- `cortes`: `M4_critical: [90, 30, 15, 7]` e `M4_high: [180, 60, 30, 14]`; `M4` em `invertidos`.
- `mttr`: `pct_em_lote_max: 40`, `lote_minimo_por_janela: 2`, `metodo_percentil: interpolado`.
- Portão de cadência passa a **recontar do CSV**, e ganha um segundo portão: janelas formadas só
  por pares de datas de scan ⇒ M4 = lacuna, mesmo com `pct_em_lote` abaixo do corte.
- Tabela das três escolhas de método, com o efeito numérico medido de cada uma.
- `EVIDENCIA[M4]` passa a exigir corte de lote usado, estados incluídos com a contagem de
  `REOPENED` excluída, método de percentil e contagem de `severidade_modificada != NONE`.
- Duas linhas novas de tratamento de lacuna: resumo sem método declarado, e CSV com recast.
- `references/indicadores-maturidade.md` atualizado com os mesmos números.

## Aplicado no coletor em 2026-09-03 — versão 1.1.0

`_ferramentas/mttr-export/tenable_mttr_export.py`:

1. corte de lote agora **2** por default, ajustável em `--lote-minimo`, e declarado no resumo em
   `lote_minimo_por_janela`. O resumo também traz `sensibilidade_ao_corte` (o percentual com
   cortes 2 a 5) e `datas_que_formam_as_janelas` — este último permite detectar o caso
   "MTTR = intervalo entre scans" independentemente do percentual;
2. `estados_incluidos_no_mttr: ["FIXED"]` com nota explicando a exclusão, mais
   `reabertos_no_recorte` e `mttr_dias_media_se_incluir_reabertos` por severidade;
3. `metodo_percentil` declarado, com a docstring da função nomeando o método (tipo 7).

Verificação: o autoteste (`--autoteste`) foi estendido para cobrir o corte de lote, a contagem de
`REOPENED` e a presença dos campos declarativos, e passa. Reprocessando o CSV de `_dados/` com o
coletor 1.1.0, a saída reproduz exatamente os números desta validação: `pct_em_lote` 93,5% com
corte 2, sensibilidade 93,5 / 74,2 / 64,5 / 38,7, 9 janelas sobre 7 datas, High 60,39 só com
`FIXED` e 49,66 incluindo os 5 reabertos.

Propagado para `tenable-mttr-dashboard.skill` (SKILL.md, `references/coleta-mttr.md` e a cópia do
coletor em `scripts/`) e para `_ferramentas/mttr-export/LEIA-ME.md`.
