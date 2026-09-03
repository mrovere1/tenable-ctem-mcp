# Troubleshooting

Casos reais encontrados neste projeto, não documento especulativo.

## `401 não autorizado`

Duas causas, nesta ordem de frequência:

1. **Chave de outro container.** A chave é do tenant onde foi gerada. Conferir em
   Settings › My Account › API Keys do tenant certo.
2. **Espaço no fim da variável de ambiente.** O `export` copiado de um documento carrega espaço
   invisível. O servidor faz `.strip()` nas duas chaves, mas confira também se a variável não tem
   quebra de linha.

`ctem_diagnostico()` separa credencial ausente de credencial inválida sem imprimir a chave.

## `403 sem permissão`

A chave precisa do papel **Basic [16]**, ou dos privilégios `VM.VM_EXPLORE` (Vulnerability
Management) e `ASSET_INVENTORY.CYBER_ASSET_MANAGEMENT.READ` (Exposure Management).

## `409` no export de MTTR

Já existe um export aberto para aquela chave. **Não peça outro** — retome pelo `export_uuid`:

```
mttr_collect(export_uuid="<uuid devolvido antes>")
```

É por isso que `mttr_collect` devolve `{status: "pendente", export_uuid}` ao estourar `max_wait_s`
em vez de levantar exceção.

## Falha de certificado TLS

Rede corporativa que inspeciona TLS apresenta um certificado assinado por CA interna, que está no
Keychain do macOS mas não no bundle do Python. **É o proxy do cliente, não o MCP.**

```bash
export TIO_CA_BUNDLE=/caminho/para/ca-da-empresa.pem
export TIO_CA_KEYCHAIN=1        # macOS
```

Se o Python veio do python.org sem certificados, rode uma vez
`/Applications/Python\ 3.12/Install\ Certificates.command`.

**O servidor não oferece opção de desabilitar a verificação.** Sem ela, as chaves de API do tenant
seguem por um canal que pode estar sendo lido por terceiro.

## Coleta vazia

Não é erro: é **resultado**. Vira lacuna declarada, e a janela usada vai no relatório.

## Número que parece filtrado e é o corpus inteiro

O caso do `filters` em texto livre. `filters="tag_count >= 1"` devolveu os 30 ativos do corpus, sem
erro; o mesmo filtro como array JSON devolveu 9. A deny-list do servidor **rejeita antes de chegar
à API** — ver `src/tenable_ctem_mcp/preflight.py`.

## `ACR` e `AES` vazios

Ativo novo. São calculados cerca de **24 h após o primeiro scan**. Pendente não é lacuna: declare
como pendente e reavalie depois.

## `pct_em_lote` alto no MTTR

**Não é defeito.** É o MTTR medindo o intervalo entre scans, e não o tempo de correção. No sandbox,
as 9 janelas `(first_found, last_fixed)` eram todas pares tirados de 7 datas — as datas de scan do
tenant. A skill declara M4 como lacuna de propósito nesse caso.

## `429 Too Many Requests`

O limite da Tenable é **dinâmico**: a plataforma calcula quantas requisições aceita por minuto
conforme a carga. A resposta traz `retry-after` em segundos, e o cliente honra esse header. Não há
número fixo a ajustar. https://developer.tenable.com/docs/rate-limiting

## `ModuleNotFoundError: No module named 'tenable_ctem_mcp'`

Instalação **editável** (`uv pip install -e .`) em venv criada pelo `uv`. O `.pth` que o hatchling
grava (`_editable_impl_tenable_ctem_mcp.pth`) ordena **antes** do `_virtualenv.pth` do uv, que
reescreve `sys.path` e o descarta. Sintoma exato: `uv run python -m ...` funciona e
`.venv/bin/python -m ...` não.

```bash
uv pip install .          # instalação normal, sem -e
```

Para desenvolver sem reinstalar a cada edição, lance com `uv run python -m tenable_ctem_mcp.server`.
Os testes não são afetados: o `pyproject.toml` define `pythonpath = ["src"]` para o pytest.
