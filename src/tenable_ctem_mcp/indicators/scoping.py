"""Estagio 1 - Scoping (S1, S2, S3, S4).

Criterios oficiais correspondentes: Asset Visibility e People | Process.

S2 e S3 exigem o MAPEAMENTO de categoria como parametro explicito. O servidor
nao adivinha o nome da categoria: se o chamador nao disser qual e a de
criticidade e a de owner, o indicador vira lacuna e o retorno lista as
categorias que existem, para o consultor apontar a certa.

Propriedades de filtro confirmadas contra a API direta em 2026-09-03:
  tag_count  ops: = != >= > <= < exists not exists
  tag_names  ops: contains not contains = != exists not exists size...
  acr        ops: = != >= > <= < exists not exists

ACHADO da validacao: `tag_names` guarda o VALOR da tag, nao "Categoria:Valor".
`contains "Criticidade"` devolve 0; `= ["Alta","Baixa","Crown Jewel","Media"]`
devolve 8. Um array de valores tem semantica de OU e ja deduplica o ativo que
carrega duas tags da mesma categoria.
"""

from __future__ import annotations

import json
from typing import Any

from .. import Indicador
from ..client import ErroApi, chamar, total_de
from ..preflight import validar_filters, veredito

BUSCA_ATIVOS = "/api/v1/t1/inventory/assets/search"

INDICADORES = ("S1", "S2", "S3", "S4")

# Nomes procurados sem distincao de acentuacao ou caixa. Nao assumir nome.
PISTAS_CRITICIDADE = ("criticidade", "criticality", "criticality tier",
                      "business criticality", "crown jewel", "tier", "importancia",
                      "importância")
PISTAS_OWNER = ("owner", "dono", "responsavel", "responsável", "responsible",
                "custodian", "team", "squad", "departamento", "department",
                "business unit", "bu")


def _contar(filters: list[dict] | None) -> int | None:
    corpo = {"filters": validar_filters(filters)} if filters else {}
    return total_de(chamar("POST", BUSCA_ATIVOS, corpo=corpo, params={"limit": 1}))


def _literal(filters: list[dict] | None) -> str:
    return (json.dumps(filters, separators=(",", ":"), ensure_ascii=False)
            if filters else "sem filtro (corpus)")


def _pct(numerador: int, denominador: int) -> float | None:
    return round(100.0 * numerador / denominador, 1) if denominador else None


def sugerir_categorias(categorias: dict[str, list[str]]) -> dict[str, list[str]]:
    """Sugere qual categoria e de criticidade e qual e de owner, sem decidir.

    A decisao continua do operador: o mapeamento e parametro explicito. Isto
    aqui so evita que ele tenha de ler nove categorias para achar duas.
    """
    def casa(nome: str, pistas: tuple[str, ...]) -> bool:
        n = nome.strip().lower()
        return any(p in n for p in pistas)

    return {
        "criticidade": [c for c in categorias if casa(c, PISTAS_CRITICIDADE)],
        "owner": [c for c in categorias if casa(c, PISTAS_OWNER)],
    }


def _por_categoria(mapeamento: dict, chave: str, categorias: dict[str, list[str]]
                   ) -> tuple[str | None, list[str]]:
    """Devolve (nome da categoria, valores dela) a partir do mapeamento."""
    nome = mapeamento.get(chave)
    if not nome:
        return None, []
    valores = categorias.get(nome)
    if valores is None:
        # Casa sem distincao de caixa antes de desistir.
        for k, v in categorias.items():
            if k.strip().lower() == str(nome).strip().lower():
                return k, list(v)
        return nome, []
    return nome, list(valores)


def calcular(mapeamento: dict, indicadores: list[str] | None = None,
             retrato: dict | None = None) -> list[dict]:
    """S1 a S4. `indicadores=None` calcula todos os quatro.

    `mapeamento` aceita:
      categoria_criticidade: str
      categoria_owner: str
    """
    pedidos = [i.upper() for i in (indicadores or INDICADORES)]
    saida: list[Indicador] = []

    from .discovery import descobrir_tenant
    retrato = retrato or descobrir_tenant()
    categorias = retrato["tags"]["categorias"]
    total_ativos = retrato["ativos"]["total"]

    # --- S1: % de ativos com ao menos uma tag ---------------------------
    if "S1" in pedidos:
        f = [{"property": "tag_count", "operator": ">=", "value": ["1"]}]
        try:
            com_tag = _contar(f)
            saida.append(Indicador.ok(
                "S1", _pct(com_tag, total_ativos), n=total_ativos,
                filtro_literal=f"{_literal(f)} sobre corpus de {total_ativos} ativos",
                veredito_preflight=veredito(total_ativos, com_tag),
                contexto={"com_tag": com_tag, "total": total_ativos}))
        except ErroApi as e:
            saida.append(Indicador.lacuna_declarada("S1", causa=str(e),
                                                    filtro_literal=_literal(f)))

    # --- S2 e S3: cobertura por categoria de tag ------------------------
    for ind, chave, rotulo in (("S2", "categoria_criticidade", "criticidade"),
                               ("S3", "categoria_owner", "owner")):
        if ind not in pedidos:
            continue
        nome, valores = _por_categoria(mapeamento, chave, categorias)
        if not nome:
            saida.append(Indicador.lacuna_declarada(
                ind,
                causa=(f"mapeamento nao informou `{chave}`. O servidor nao "
                       f"adivinha o nome da categoria de {rotulo}."),
                filtro_literal="nao executado"))
            continue
        if not valores:
            saida.append(Indicador.lacuna_declarada(
                ind,
                causa=(f"a categoria {nome!r} nao existe no tenant, ou nao tem "
                       "valores. Categorias disponiveis: "
                       + ", ".join(sorted(categorias))),
                filtro_literal="nao executado"))
            continue
        f = [{"property": "tag_names", "operator": "=", "value": valores}]
        try:
            n = _contar(f)
            saida.append(Indicador.ok(
                ind, _pct(n, total_ativos), n=total_ativos,
                filtro_literal=(f"{_literal(f)} (categoria {nome!r}) sobre corpus "
                                f"de {total_ativos} ativos"),
                veredito_preflight=veredito(total_ativos, n),
                contexto={"categoria": nome, "valores": valores,
                          "com_tag": n, "total": total_ativos}))
        except ErroApi as e:
            saida.append(Indicador.lacuna_declarada(ind, causa=str(e),
                                                    filtro_literal=_literal(f)))

    # --- S4: Crown Jewels declarados (informativo) ----------------------
    if "S4" in pedidos:
        f = [{"property": "acr", "operator": ">=", "value": ["9"]}]
        nome_crit, _ = _por_categoria(mapeamento, "categoria_criticidade", categorias)
        try:
            com_acr_alto = _contar(f)
            declarado = bool(nome_crit) and (com_acr_alto or 0) >= 1
            saida.append(Indicador.ok(
                "S4", declarado, n=total_ativos,
                filtro_literal=(f"{_literal(f)} E existe categoria de criticidade "
                                f"({nome_crit!r})"),
                veredito_preflight=veredito(total_ativos, com_acr_alto),
                contexto={
                    "ativos_com_acr_maior_igual_9": com_acr_alto,
                    "categoria_de_criticidade": nome_crit,
                    "informativo": True,
                    "lacuna_estrutural": (
                        "A API nao expoe se o ACR foi ajustado por humano ou se e o "
                        "valor automatico da Tenable. S4 mede DECLARACAO de contexto, "
                        "nao curadoria. Por isso e informativo e nao pontua estagio."),
                }))
        except ErroApi as e:
            saida.append(Indicador.lacuna_declarada("S4", causa=str(e),
                                                    filtro_literal=_literal(f)))

    return [i.para_dict() for i in saida]
