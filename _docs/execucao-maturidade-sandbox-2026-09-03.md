# Teste de aceitação de ponta a ponta — 2026-09-03

Primeira execução completa da skill `tenable-ctem-maturity-assessment` com todos os pré-requisitos
disponíveis: ACR e AES calculados, 6 novos ativos escaneados, e o CSV do coletor 1.1.0 alimentando M4.
Relatório: `execucao-maturidade-sandbox-2026-09-03.html`.

## Resultado

| | |
|---|---|
| Estágio efetivo | **1 — Ad Hoc** (elo mais fraco) |
| Estágio médio | **2 — Definido** (média 2,55, arredondada para baixo) |
| Portão de confiança | **16 de 17** com dado, mínimo 14 — passou sem aviso |
| Lacuna | M4 (MTTR), com causa nomeada |

| Etapa | Efetivo | Média | Indicadores |
|---|---|---|---|
| Escopo | 1 | 1,67 | S1 30,0% · S2 26,7% · S3 6,7% · S4 informativo |
| Descoberta | 4 | 4,75 | D1 0,5 d · D2 100% · D3 87,5% · D4 100% |
| Priorização | 1 | 3,00 | P1 100% · P2 81,6% · P3 não declarado |
| Validação | 1 | 1,33 | V1 informativo 59,6% · V2 1.003 d · V3 18,0% · V4 87,5% |
| Mobilização | 1 | 2,00 | M1 21 d · M2 140 d · M3 779 d · M4 lacuna |

## Achados

1. **O escopo trava o programa.** 6,7% dos ativos com dono declarado, 26,7% com criticidade.
   Descoberta em Avançado não compensa: o efetivo é o menor.
2. **As tags existentes estão nos ativos certos.** 100% do backlog VPR ≥ 9 está em ativo com
   criticidade, contra 26,7% de cobertura no inventário. Verificado por soma exata:
   Crown Jewel 88 + Média 498 = 586 = total VPR ≥ 9.
3. **Validação é o ponto mais frágil.** Mediana de 1.003 dias no CISA KEV (9 plugins com KEV na
   amostra) e 7 de 8 dispositivos com software fora de suporte.
4. **M4 é lacuna, e a prova ficou definitiva.** As 7 datas que formam as janelas do CSV são
   **todas** dias de execução do scan 33 — 7 de 7, cruzado contra `scan_history`. O MTTR ali é o
   intervalo entre scans.
5. **Nenhuma severidade distorcida por exceção**: 4.278 de 4.278 linhas com
   `severidade_modificada = NONE`.

## Três defeitos encontrados na própria skill, corrigidos

1. **M1 estava errado.** A fórmula era "mediana do intervalo entre runs `completed` consecutivos".
   O scan recorrente tem 12 runs em 9 dias distintos, com quatro pares relançados no mesmo dia —
   a mediana dos intervalos crus deu **1,42 dia**, número sem sentido. Colapsando em dias
   distintos de avaliação: intervalos de 140, 40, 2, 89, 1, 1, 85 e 1 dias, mediana **21 dias**.
   Standardized em vez de Optimized, dois estágios de diferença. Corrigido, com
   `colapsar_runs_do_mesmo_dia: true`.
2. **`censo_d4_m3: true` não é implementável.** `plugins_search_plugins` aceita palavra-chave e
   CVE, não lista de IDs de plugin, então não há censo possível por esse caminho. Default virou
   `false`, e a nota aponta `workbenches_list_vulnerabilities(severity=...)` como o quadro de
   amostragem certo — devolve plugin, contagem, VPR e família de todos os plugins da severidade
   numa chamada (121 plugins críticos neste tenant).
3. **Duas entradas novas no pré-voo.** O parâmetro `filters` em **texto livre** é ignorado em
   silêncio: `filters="tag_count >= 1"` devolveu os 30 ativos do corpus, sem erro; o mesmo filtro
   como array JSON devolveu 9. É a armadilha mais fácil de cometer, porque
   `list_inventory_properties` sugere exatamente essa sintaxe ao listar operadores. E o operador
   `exists` responde **HTTP 400** em `finding_vpr_score` — usar `vpr_min="0.1"`. Propagado para
   `tenable-exploitability-reality-check`, que carrega a mesma referência.

## Amostragem

Amostra estratificada de 20 plugins críticos sobre os 121 do tenant, alocação proporcional:
estrato A (VPR ≥ 7) 12 plugins, estrato B 8. Todos com `Scan Type = local` nos dois estratos.
Exploit disponível: 11/12 em A (IC 95% 64,6% a 98,5%) e 1/8 em B (2,2% a 47,1%), ponderado 59,6%.
Proporção com KEV na amostra: 9/20 (IC 95% 25,8% a 65,8%).

## Verificação do relatório

Renderizado em Chromium headless: troca de idioma nos três botões, drill-down por etapa no radar e
na barra, alinhamento dos ticks de escala conferido em pixels (esperado e real idênticos nos cinco
cortes), e o **arquivo exportado** reaberto com o idioma, a aba e a etapa selecionada preservados.
Sem erro de console além do fetch da fonte do Google, que degrada para a fonte do sistema offline.
