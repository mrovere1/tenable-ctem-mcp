# Registrar o servidor no Claude Code

## O conflito, e como ele se resolve

`claude mcp add` grava a configuração em `~/.claude.json`. Passar as chaves ali com `--env` as
**escreveria em arquivo de configuração** — exatamente o que o `CLAUDE.md` deste projeto proíbe:

> Credenciais: somente via variáveis de ambiente `TIO_ACCESS_KEY`, `TIO_SECRET_KEY`, `TIO_URL`.
> Nunca como parâmetro de tool, nunca em log.

A saída não é abrir exceção. É que **um processo filho herda o ambiente do pai**: se as chaves
estiverem exportadas no shell que lança o Claude Code, o servidor MCP as recebe sem que ninguém
precise gravá-las em lugar nenhum.

## O caminho recomendado

```bash
# 1. no shell, antes de abrir o cliente
export TIO_ACCESS_KEY=...
export TIO_SECRET_KEY=...
# export TIO_URL=https://cloud.tenable.com        # só se não for o padrão
# export TIO_CA_BUNDLE=/caminho/ca-da-empresa.pem # só em rede que inspeciona TLS

# 2. registrar o servidor, SEM --env
claude mcp add tenable-ctem -- /caminho/para/mcp-ctem/.venv/bin/python -m tenable_ctem_mcp.server

# 3. abrir o cliente A PARTIR DESSE shell
claude
```

Para tornar permanente, ponha os `export` no seu `~/.zshrc` — ou, melhor, num arquivo carregado só
quando você vai trabalhar neste projeto, para as chaves não ficarem no ambiente de tudo.

## Conferir antes de rodar a skill

Com o cliente aberto, chame:

```
ctem_diagnostico()
```

| `veredito` | O que fazer |
|---|---|
| `ok` | seguir |
| `credencial_ausente` | o cliente não herdou o ambiente — reabra a partir do shell com os `export` |
| `credencial_invalida` | chave de outro container, ou espaço no fim da variável |
| `falha` com causa `tls_proxy_corporativo` | defina `TIO_CA_BUNDLE` — ver `troubleshooting.md` |

`ctem_diagnostico` não imprime a chave nem parte dela.

## Rodar a skill de ponta a ponta

1. Instale a skill de `_skills/tenable-ctem-maturity-assessment/`.
2. Peça o assessment de maturidade CTEM.
3. Confira contra esta lista:

| O que verificar | Esperado |
|---|---|
| Passo 0 Fase A | **uma** chamada, `ctem_discover_tenant` — não dez |
| Passo 1 | **uma** chamada, `ctem_preflight`, e a tabela vai inteira para o relatório |
| Passo 2 | **cinco** chamadas, uma por estágio |
| Total de chamadas de coleta | **~7**, contra as ~40 do caminho antigo |
| Nenhum pedido de CSV | a skill não pode perguntar por `tenable_mttr_findings_*.csv` |
| Nenhum pedido de credencial | a skill nunca pede chave |
| D4/V1/V2/M3 | `contexto.modo` = `censo`, sem intervalo de confiança |
| M1 | mediana calculada sobre **dias distintos**; o contexto traz `mediana_sem_colapso_dias` |
| M4 no sandbox | **lacuna**, com a guarda de cadência nomeando a causa |
| Indicadores no relatório | 19, sendo 16 com dado e M4 em lacuna |

**M4 como lacuna é o resultado correto neste tenant**, não um defeito a corrigir: as 7 datas que
formam as janelas do MTTR são 7 de 7 datas de execução de scan.

## Reiniciar é obrigatório

Toda mudança no servidor exige reiniciar o cliente. Para iterar durante o desenvolvimento, use o
Inspector, que recarrega na hora e mostra o JSON cru:

```bash
npx @modelcontextprotocol/inspector uv run python -m tenable_ctem_mcp.server
```
