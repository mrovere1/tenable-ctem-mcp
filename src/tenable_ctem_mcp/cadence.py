"""Colapso de runs de scan em DIAS DISTINTOS de avaliacao.

Este modulo existe por causa de um numero errado que passou despercebido.

A formula original de M1 era "mediana do intervalo entre runs `completed`
consecutivos". Um scan relancado minutos depois e a MESMA avaliacao, nao um
novo ciclo de cadencia. No sandbox, os 12 runs do scan recorrente incluem
quatro pares no mesmo dia, e a mediana dos 11 intervalos crus deu 1,42 DIA -
numero sem sentido para um tenant que avaliou em 9 dias ao longo de 12 meses.

Colapsando em dias distintos: intervalos de 140, 40, 2, 89, 1, 1, 85 e 1 dias,
mediana 21 DIAS. Standardized em vez de Optimized - dois estagios de diferenca.

O colapso acontece NO SERVIDOR, sempre. Nunca no cliente: foi exatamente por
estar no cliente que o erro sobreviveu a uma execucao inteira.

M2 (maior lacuna) NAO muda com o colapso - o maior intervalo e o mesmo.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .client import ErroApi, paginar


def _dias_distintos(runs: list[dict], apenas_completed: bool = True) -> list[str]:
    """Datas UTC distintas em que houve avaliacao, em ordem."""
    dias = set()
    for r in runs:
        if apenas_completed and r.get("status") != "completed":
            continue
        ts = r.get("time_start")
        if isinstance(ts, int) and ts > 0:
            dias.add(datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d"))
    return sorted(dias)


def _intervalos(dias: list[str]) -> list[int]:
    ds = [datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc) for d in dias]
    return [int((ds[i + 1] - ds[i]).total_seconds() // 86400) for i in range(len(ds) - 1)]


def _mediana(v: list[float]) -> float | None:
    if not v:
        return None
    s = sorted(v)
    m = len(s) // 2
    return float(s[m]) if len(s) % 2 else (s[m - 1] + s[m]) / 2


def scan_cadence(scan_ids: list[str | int], colapsar_runs_do_mesmo_dia: bool = True,
                 apenas_completed: bool = True) -> dict[str, Any]:
    """Colapsa runs em dias distintos e devolve intervalos, mediana e maximo.

    `colapsar_runs_do_mesmo_dia=False` existe para o relatorio poder MOSTRAR a
    diferenca, nunca para ser o default. Desligar exige declarar - a saida traz
    `mediana_sem_colapso` junto, sempre, para o contraste ficar visivel.
    """
    por_scan: dict[str, Any] = {}
    todos_os_dias: set = set()
    lacunas: list[dict] = []

    for sid in scan_ids:
        try:
            runs = paginar("GET", f"/scans/{sid}/history", campo="history")
        except ErroApi as e:
            lacunas.append({"scan_id": sid, "causa": str(e)[:200]})
            continue

        usados = [r for r in runs
                  if not apenas_completed or r.get("status") == "completed"]
        dias = _dias_distintos(runs, apenas_completed)
        todos_os_dias |= set(dias)

        # Intervalos crus: entre runs consecutivos, sem colapsar. E o que
        # produz a mediana sem sentido, e vai junto para o contraste.
        marcas = sorted(r["time_start"] for r in usados
                        if isinstance(r.get("time_start"), int))
        crus = [round((marcas[i + 1] - marcas[i]) / 86400.0, 2)
                for i in range(len(marcas) - 1)]
        colapsados = _intervalos(dias)

        por_scan[str(sid)] = {
            "runs": len(runs),
            "runs_considerados": len(usados),
            "dias_distintos": len(dias),
            "datas": dias,
            "intervalos_colapsados_dias": colapsados,
            "mediana_dias": _mediana(colapsados),
            "maximo_dias": max(colapsados) if colapsados else None,
            "mediana_sem_colapso_dias": _mediana(crus),
            "runs_relancados_no_mesmo_dia": len(usados) - len(dias),
        }

    dias_gerais = sorted(todos_os_dias)
    intervalos_gerais = _intervalos(dias_gerais)
    escolhidos = intervalos_gerais if colapsar_runs_do_mesmo_dia else None
    if not colapsar_runs_do_mesmo_dia:
        crus_gerais: list[float] = []
        for v in por_scan.values():
            crus_gerais.extend(v["intervalos_colapsados_dias"])
        escolhidos = crus_gerais

    return {
        "scans": por_scan,
        "colapsar_runs_do_mesmo_dia": colapsar_runs_do_mesmo_dia,
        "dias_distintos_de_avaliacao": len(dias_gerais),
        "datas": dias_gerais,
        "intervalos_dias": intervalos_gerais,
        "mediana_dias": _mediana(escolhidos or []),
        "maximo_dias": max(intervalos_gerais) if intervalos_gerais else None,
        "lacunas": lacunas,
        "aviso": (None if colapsar_runs_do_mesmo_dia else
                  "COLAPSO DESLIGADO. Um scan relancado minutos depois conta como "
                  "novo ciclo de cadencia, o que nao e verdade. Declare isso no "
                  "relatorio."),
        "nota": ("O colapso acontece no servidor, sempre. Sem ele, a mediana de "
                 "M1 no sandbox e 1,42 dia; com ele, 21 dias - dois estagios de "
                 "diferenca. M2 (maior lacuna) nao muda com o colapso."),
    }
