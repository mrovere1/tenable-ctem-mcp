# tenable-ctem-mcp

Servidor MCP **local (stdio)** que entrega os 17 indicadores do assessment de CTEM da Tenable já
agregados, mais MTTR — o que a API de Exposure Management não alcança diretamente.

> **Community / partner tooling. Não é produto Tenable e não tem suporte da Tenable.**
> Validado em laboratório. Teste no seu ambiente antes de usar em produção.
> Issues no GitHub são o canal, sem SLA prometido.

## O que ele é

Um servidor local que move a agregação para o servidor e devolve números prontos. Cada indicador vem
com `valor`, `n`, `filtro_literal`, `coletado_em_utc` e `veredito_preflight`. Consulta que falhou
vira **lacuna declarada com causa** — número parcial silencioso é proibido.

| | Via MCP oficial | Com este servidor |
|---|---|---|
| Chamadas para os 17 indicadores | ~40 | ~7 (**4 para os 15 de S a V**, medido) |
| Detalhe de 20 plugins | 20 chamadas, ~31.900 tokens | 1 chamada, ~900 tokens (**−97,2%**, medido) |
| MTTR | impossível; exige script Python fora | 1 tool |
| Cadência (M1) | 12 runs crus, colapsados no cliente | já colapsado: mediana **21 d**, não 1,42 |

## O que ele não é

Clone do MCP oficial da Tenable, MCP genérico, servidor hospedado, ou produto Tenable.

## Instalação

Requer Python 3.12.

```bash
uv venv --python 3.12
uv pip install .
```

> **Não use `-e` (editável) aqui.** Em venv criada pelo `uv`, o `.pth` do install editável do
> hatchling é descartado pelo `_virtualenv.pth`, que ordena depois dele, e o pacote fica
> inimportável por `python -m`. Para desenvolver, use `uv run python -m tenable_ctem_mcp.server`,
> que resolve o projeto sem depender do `.pth`.

## Credenciais

**Somente por variável de ambiente.** Nunca como parâmetro de tool, nunca em arquivo de config,
nunca em log. A chave é gerada no seu tenant em **Settings › My Account › API Keys**.

```bash
export TIO_ACCESS_KEY=...
export TIO_SECRET_KEY=...
export TIO_URL=https://cloud.tenable.com     # opcional
```

Permissão necessária: papel Basic [16], ou os privilégios `VM.VM_EXPLORE` e
`ASSET_INVENTORY.CYBER_ASSET_MANAGEMENT.READ`.

### Rede que inspeciona TLS

```bash
export TIO_CA_BUNDLE=/caminho/para/ca-da-empresa.pem
export TIO_CA_KEYCHAIN=1          # macOS: usar o Keychain como fonte de confiança
```

**Não existe opção para desabilitar a verificação de certificado, e não deve existir.** Sem
verificação, as chaves de API do tenant seguem por um canal que pode estar sendo lido por terceiro.
Ver `docs/troubleshooting.md`.

## Uso

```bash
# desenvolvimento: o Inspector mostra o JSON cru de request e response
npx @modelcontextprotocol/inspector uv run python -m tenable_ctem_mcp.server

# registrar no Claude Code
claude mcp add tenable-ctem -- /caminho/para/.venv/bin/python -m tenable_ctem_mcp.server
```

As chaves vêm do ambiente do **processo do servidor**. Se o cliente não herdar o seu shell, passe-as
na configuração do cliente — nunca como parâmetro de tool.

## Tools

Onze no total. Contrato completo em `docs/tools.md`.

| Estado | Tool |
|---|---|
| **M0 — pronto** | `ctem_discover_tenant`, `ctem_diagnostico` |
| **M1 — pronto** | `ctem_scoping`, `ctem_discovery`, `plugin_details_batch`, `plugin_census` |
| **M2 — pronto** | `ctem_prioritization`, `ctem_validation` |
| **M3 — pronto** | `ctem_preflight` |
| **M4 — pronto** | `mttr_collect`, `mttr_cadence_guard`, `scan_cadence` |
| M5 | `ctem_mobilization` |

## Testes

```bash
.venv/bin/python -m pytest
```

Roda inteiro **sem tenant nenhum**: as fixtures são respostas gravadas e higienizadas.
`tests/test_fixture_safety.py` falha se qualquer fixture contiver padrão de chave, IP privado ou
hostname.

## Licença

MIT. Ver `LICENSE`.
