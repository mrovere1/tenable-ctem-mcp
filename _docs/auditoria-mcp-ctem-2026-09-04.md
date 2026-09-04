# Auditoria do MCP CTEM Assessment

Data: 2026-09-04

## Resumo executivo

Foi realizada uma auditoria read-only do repositório do MCP CTEM Assessment e da skill associada. A checagem não alterou configurações, código, documentação existente, ambiente ou artefatos de deploy.

A arquitetura geral está consistente com o plano: MCP em Python 3.12 via stdio, credenciais exclusivamente por variáveis de ambiente, paginação interna, cache com TTL, tratamento estruturado de erros, fixtures e testes cobrindo boa parte dos indicadores.

Apesar disso, há desalinhamentos importantes entre o código, a skill, o ZIP da skill e parte da documentação. O ponto de maior atenção é que o ZIP da skill parece conter uma versão antiga do fluxo, com coletor CSV e chamadas diretas antigas, enquanto o diretório da skill já aponta para o novo MCP.

Recomendação: não redistribuir ou considerar o pacote finalizado antes de corrigir os achados de prioridade alta.

## Escopo da checagem

Arquivos e áreas revisadas:

- `_docs/plano-mcp-ctem.md`
- `README.md`
- `CLAUDE.md`
- `docs/`
- `_skills/tenable-ctem-maturity-assessment/`
- `_skills/tenable-ctem-maturity-assessment.skill.zip`
- `src/tenable_ctem_mcp/`
- `tests/`
- `.gitignore`
- estado Git local

Comandos de validação executados:

- `git status --short --branch`
- `git diff --stat`
- `rg` para busca de referências relevantes
- `zipinfo` e `unzip -p` para inspecionar o ZIP da skill
- parse AST read-only de `src/` e `tests/`
- import read-only do pacote `tenable_ctem_mcp`

Observação: `pytest` não foi executado para evitar escrita em `.pytest_cache` ou `__pycache__`.

## Resultado geral

Estado do repositório:

- Working tree limpo em `main`.
- Nenhuma alteração tracked detectada após a auditoria.
- Artefatos locais ignorados presentes: `.DS_Store`, `.pytest_cache`, `.venv`, `__pycache__`.
- `.gitignore` cobre caches, `.env`, chaves, certificados e arquivos de exportação sensíveis.

Validação técnica leve:

- Parse AST de `src/` e `tests/` passou.
- Import do pacote passou.
- Servidor MCP importou corretamente.
- Foram identificadas 13 tools decoradas com `@mcp.tool`.

## Achados priorizados

### P0 - ZIP da skill parece estar stale

O diretório `_skills/tenable-ctem-maturity-assessment/` está atualizado para usar o MCP novo, incluindo chamadas como:

- `ctem_discover_tenant`
- `ctem_preflight`
- `ctem_scoping`
- `ctem_discovery`
- `ctem_prioritization`
- `ctem_validation`
- `ctem_mobilization`

Porém, o arquivo `_skills/tenable-ctem-maturity-assessment.skill.zip` ainda contém referências antigas, incluindo:

- `scripts/tenable_mttr_export.py`
- fluxo manual por CSV
- chamadas diretas antigas como `tagging_list_tag_categories_and_values`
- `tenable_one_search_assets`
- `scan_list_scans`
- `agent_list_agents`

Risco:

Se o deploy ou instalação da skill usar o ZIP, o operador poderá executar o fluxo antigo em vez do fluxo MCP atual.

Orientação:

Regerar o ZIP a partir do diretório atualizado da skill e validar seu conteúdo antes de distribuir. A validação deve confirmar que o ZIP não contém mais o script antigo de MTTR nem instruções de CSV manual.

### P0 - Roteiro de execução contém instruções obsoletas

O arquivo `_skills/tenable-ctem-maturity-assessment/references/roteiro-de-execucao.md` começa indicando que está obsoleto, mas ainda mantém instruções antigas de execução por CSV e script local.

Exemplos de conteúdo conflitante:

- coleta de CSV via `python3 scripts/tenable_mttr_export.py`
- orientação para procurar `tenable_mttr_findings_*.csv`
- tratamento de M4 como lacuna quando CSV não existe
- descrição de 17 indicadores pontuáveis condicionados ao CSV

Isso contradiz o `SKILL.md`, que já indica que M4 deve ser calculado pelo MCP.

Risco:

Mesmo que o `SKILL.md` esteja correto, um operador ou modelo que consulte o roteiro pode seguir instruções antigas e produzir avaliação inconsistente.

Orientação:

Atualizar o roteiro para refletir o fluxo atual via MCP ou substituí-lo por um aviso curto apontando para o `SKILL.md` como fonte autoritativa.

### P0 - Inconsistência de unidade no indicador V3

O código de `src/tenable_ctem_mcp/indicators/validation.py` retorna V3 como percentual, por exemplo `18.0`.

Entretanto, os thresholds da skill aparecem como frações:

- `0.25`
- `0.15`
- `0.08`
- `0.03`

Risco:

Se o classificador comparar `18.0` contra thresholds fracionários, V3 pode ser classificado incorretamente.

Orientação:

Escolher uma unidade canônica para V3:

- manter o código em percentual e ajustar thresholds para `25`, `15`, `8`, `3`; ou
- alterar o código para retornar fração, por exemplo `0.18`.

Depois disso, alinhar `SKILL.md`, docs e testes.

### P1 - Evidências e guards de M4 incompletos no contrato MCP/skill

O `SKILL.md` exige evidências e gates para M4, incluindo:

- `n` por severidade
- percentual de MTTR derivado vs. nativo
- divergência de filtros
- batch guard
- janelas de datas de scan
- contagem de severidade modificada
- estados incluídos, incluindo `REOPENED`
- método de percentil

O código em `src/tenable_ctem_mcp/indicators/mobilization.py` repassa somente parte dessas informações ao contexto do indicador.

Risco:

A skill pode exigir uma conclusão metodológica que o MCP não entrega integralmente, gerando relatório com evidência insuficiente ou decisões de maturidade sem todos os guards previstos.

Orientação:

Expandir o payload retornado por `ctem_mobilization` para incluir todos os campos exigidos pela skill ou reduzir explicitamente os requisitos da skill ao contrato real do MCP.

### P1 - Escopo coletado pela skill não parece ser aplicado nos cálculos

A skill coleta ou descreve campos de escopo como:

- criticidade
- owner
- ambiente
- localidade
- produção
- exclusões, como LAB/SANDBOX

No código dos indicadores, o uso efetivo parece restrito principalmente a:

- `categoria_criticidade`
- `categoria_owner`
- `scans_recorrentes`

Não foi identificado uso consistente de ambiente, localidade, produção ou exclusões para filtrar os cálculos principais.

Risco:

Se o assessment deveria respeitar escopo, produção ou exclusões, o resultado pode refletir o tenant completo em vez do recorte acordado.

Orientação:

Definir formalmente se o MCP v1 calcula sempre tenant-wide ou se deve aplicar escopo. Se deve aplicar escopo, implementar filtros de tags e exclusões nos indicadores afetados, especialmente M1, M2, M3, M4 e V3.

### P1 - Documentação contraditória sobre filtros

`docs/limitacoes.md`, `CLAUDE.md` e alguns comentários de código mantêm afirmações antigas sobre filtros de findings, especialmente em relação a:

- operadores de data
- `exists`
- `finding_vpr_score`
- `age`
- `date_range`

O próprio `docs/limitacoes.md` mais abaixo traz orientação mais nova e mais precisa, criando contradição interna.

Risco:

Operadores e modelos podem tomar decisões erradas sobre quais filtros são confiáveis, mesmo que o preflight e os testes já reflitam comportamento mais atual.

Orientação:

Consolidar `docs/limitacoes.md`, `CLAUDE.md` e comentários no código em uma única posição autoritativa baseada nos testes/preflight atuais.

### P2 - Bug no modo sem colapso de `scan_cadence`

Em `src/tenable_ctem_mcp/cadence.py`, quando `colapsar_runs_do_mesmo_dia=False`, os intervalos crus são calculados, mas a mediana geral ainda usa os intervalos colapsados.

Validação observada em fixture:

- `colapsar_runs_do_mesmo_dia=True` retornou `mediana_dias=21.0`
- `colapsar_runs_do_mesmo_dia=False` também retornou `mediana_dias=21.0`
- um scan individual tinha intervalos crus diferentes

Risco:

O default atual é `True`, então o impacto no fluxo principal parece limitado. Porém o modo diagnóstico sem colapso pode apresentar resultado enganoso.

Orientação:

Corrigir a agregação geral para usar intervalos crus quando `colapsar_runs_do_mesmo_dia=False` e adicionar teste cobrindo a mediana geral nesse modo.

### P2 - Contagem de tools está desatualizada em alguns documentos

O servidor registra 13 tools, mas alguns documentos ainda indicam 11 tools.

Locais com drift:

- `docs/tools.md`
- `CLAUDE.md`
- comentário inicial de `src/tenable_ctem_mcp/server.py`

Risco:

Baixo funcionalmente, mas atrapalha troubleshooting e validação por operadores.

Orientação:

Atualizar a contagem para 13 tools e separar claramente:

- tools de assessment por etapa
- tools auxiliares/primitivas
- tool diagnóstica

### P3 - Artefatos locais ignorados existem no workspace

Foram observados artefatos locais ignorados:

- `.DS_Store`
- `.pytest_cache`
- `.venv`
- `__pycache__`

Risco:

Baixo para Git, pois estão ignorados. O risco aparece se algum ZIP ou pacote for montado diretamente a partir do filesystem sem filtro.

Orientação:

Ao gerar artefatos de distribuição, usar fonte limpa baseada em Git ou lista explícita de inclusão.

## Ordem recomendada de correção

1. Regerar e validar o ZIP da skill.
2. Corrigir ou remover o roteiro obsoleto de execução.
3. Resolver a unidade do indicador V3 entre código, testes e skill.
4. Alinhar o contrato de M4 entre MCP e skill.
5. Definir e implementar a política de escopo/tag filtering.
6. Corrigir `scan_cadence` no modo sem colapso.
7. Consolidar documentação de filtros e contagem de tools.
8. Revisar processo de empacotamento para evitar artefatos locais.

## Validações recomendadas após correções

Executar somente após autorização:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -p no:cacheprovider
```

Validar ZIP da skill:

```bash
zipinfo -1 _skills/tenable-ctem-maturity-assessment.skill.zip
unzip -p _skills/tenable-ctem-maturity-assessment.skill.zip tenable-ctem-maturity-assessment/SKILL.md | rg "tenable_mttr_export|CSV|ctem_mobilization|ctem_discover_tenant"
```

Validar tools registradas:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python - <<'PY'
import ast
from pathlib import Path

path = Path("src/tenable_ctem_mcp/server.py")
tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

tools = []
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == "tool":
                tools.append(node.name)

print(len(tools))
for tool in tools:
    print(tool)
PY
```

## Conclusão

O MCP está em bom estado estrutural, mas a entrega ainda tem riscos de consistência operacional. Os problemas mais críticos não parecem ser de autenticação ou arquitetura do servidor, e sim de empacotamento, documentação divergente e contratos de indicador entre skill e MCP.

Antes de considerar o deploy como pronto para uso recorrente, o recomendado é alinhar primeiro o artefato ZIP e a skill autoritativa, depois resolver V3 e M4, que têm maior chance de afetar diretamente a classificação de maturidade CTEM.
