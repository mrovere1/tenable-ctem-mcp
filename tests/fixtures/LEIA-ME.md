# Fixtures

`sandbox_2026-09-03.json` são respostas reais da API Tenable, gravadas do tenant de laboratório em
2026-09-03 e **higienizadas estruturalmente**. Permitem rodar `pytest` inteiro **sem tenant nenhum**
e sem nenhuma chave.

## Como foram higienizadas

Estruturalmente, olhando a **chave** de cada campo — não por regex sobre o texto. Regex já falhou
uma vez: `"schedule_uuid": "template-01df1e4e-…"` passou porque o identificador tem prefixo e o
`\b` nunca casava, e IPs `31.0.0.x` passaram porque o padrão só cobria faixas privadas.

| Sai | Fica |
|---|---|
| `*uuid*`, `ip`, `ipv4/6`, `mac`, `fqdn`, `netbios`, `hostname`, `email`, `login`, `owner`, `target*` | id de plugin e de scan (identificadores públicos da Tenable, não do cliente) |
| `name` dentro de `/agents` e `/scans` (é nome de máquina) | nome e família de plugin, nome de categoria e valor de tag |
| — | contagens, totais, datas de run, scores |

Sem o que fica, não há golden test. `tests/test_fixture_safety.py` falha se algo escapar.

## Uma redução declarada

O pré-voo chama `/workbenches/vulnerabilities` dez vezes variando parâmetros, e de todas elas lê
**apenas `len(vulnerabilities)`**. Guardar dez cópias dos mesmos 121 plugins completos dobrava o
arquivo sem acrescentar prova nenhuma, então nessas respostas cada plugin virou `{"plugin_id": N}` —
o que preserva a contagem, que é o único dado lido. Elas trazem o campo `_reduzida` dizendo isso.

**A chamada base do censo está intacta**, com nome, família, contagem e VPR: é dela que saem D4,
V1, V2 e M3.

## Como são consumidas

`tests/conftest.py` substitui `client.chamar` e `client.paginar` por uma reprodução indexada pela
assinatura `[método, caminho, corpo, params]`. Consulta que não estiver gravada **quebra o teste** —
nunca devolve vazio, porque vazio viraria número errado.
