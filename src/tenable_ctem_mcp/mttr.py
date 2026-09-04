"""MTTR por POST /vulns/export.

PORTADO de _ferramentas/mttr-export/tenable_mttr_export.py 1.1.0. Nao foi
reescrito do zero: percentil interpolado, comparacao semantica de filtros,
deteccao de lote e a redacao das notas ja estavam resolvidos e conferidos
contra o CSV de referencia.

O que MUDA na porta para o servidor, e e a razao de a porta existir:
`aguardar` nao bloqueia ate acabar. Um tool que segura a conexao por dez
minutos estoura o timeout do cliente MCP. Ao estourar `max_wait_s` devolve
`{status: "pendente", export_uuid}` para a chamada seguinte retomar - pedir um
export novo responderia 409.

Este e o unico caminho para MTTR, e continua sendo depois do M3: `last_fixed`,
`time_taken_to_fix` e `severity_modification_type` nao estao entre as 44
propriedades de findings da API de Exposure Management. Nao e wrapper faltando.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from .client import ErroApi, ErroTLS, base_url, chamar, log

VERSAO_COLETOR = "1.1.0 (portado)"

SEVERIDADES_VALIDAS = ("info", "low", "medium", "high", "critical")
ESTADOS_VALIDOS = ("OPEN", "REOPENED", "FIXED")


class ErroFiltroDivergente(ErroApi):
    """O recorte que o job aplicou nao e o que foi pedido.

    Vira erro estruturado, NUNCA numero: um MTTR calculado sobre outro recorte
    parece certo e nao tem sinal de que esta errado.
    """


# ----------------------------------------------------------------------------
# Export  (portado: abrir_export 436, aguardar 475)
# ----------------------------------------------------------------------------

def abrir_export(dias: int | None, severidades: list[str], estados: list[str],
                 num_assets: int, tags: dict) -> tuple[str, dict, bool]:
    filtros: dict[str, Any] = {"state": estados}
    if severidades:
        filtros["severity"] = severidades
    if dias:
        # `since` com state=FIXED devolve o que foi corrigido a partir da data;
        # com OPEN/REOPENED devolve o que foi visto a partir da data.
        # A spec proibe combinar `since` com first_found/last_found/last_fixed.
        filtros["since"] = int(time.time()) - dias * 86400
    for chave, valores in (tags or {}).items():
        filtros[f"tag.{chave}"] = valores

    corpo = {
        "num_assets": num_assets,
        "include_unlicensed": False,
        "include_plugin_output": False,   # reduz o volume drasticamente
        "filters": filtros,
    }
    resp = chamar("POST", "/vulns/export", corpo=corpo)

    if "_conflito" in resp:
        conflito = resp["_conflito"]
        uuid_ativo = conflito.get("active_job_id")
        if not uuid_ativo:
            raise ErroApi(f"409 sem active_job_id: {conflito}", causa="conflito")
        log(f"Ja existe export em andamento; reaproveitando o job {uuid_ativo}. "
            "Os filtros dele podem diferir dos pedidos; o resumo registra os reais.")
        return uuid_ativo, filtros, True

    uuid = resp.get("export_uuid")
    if not uuid:
        raise ErroApi(f"Resposta sem export_uuid: {resp}", causa="resposta_inesperada")
    return uuid, filtros, False


def aguardar(uuid: str, max_wait_s: int) -> tuple[list[dict], dict, bool]:
    """Baixa chunks conforme ficam prontos. Devolve (findings, status, pendente).

    Diferenca central em relacao ao coletor de linha de comando: aqui o estouro
    de tempo NAO e excecao nem espera maior - e um retorno com `pendente=True`,
    que o chamador transforma em {status: "pendente", export_uuid}.
    """
    limite = time.time() + max_wait_s
    baixados: set = set()
    findings: list[dict] = []
    status: dict = {}
    intervalo = 5
    while True:
        status = chamar("GET", f"/vulns/export/{uuid}/status")
        estado = status.get("status", "?")
        disponiveis = list(status.get("chunks_available") or [])
        for cid in disponiveis:
            if cid in baixados:
                continue
            bruto = chamar("GET", f"/vulns/export/{uuid}/chunks/{cid}", bruto=True)
            try:
                lote = json.loads(bruto)
            except json.JSONDecodeError as e:
                raise ErroApi(f"chunk {cid} nao e JSON valido: {e}",
                              causa="chunk_invalido")
            if isinstance(lote, list):
                findings.extend(lote)
            baixados.add(cid)

        if status.get("chunks_failed"):
            log(f"  AVISO: chunks com falha: {status['chunks_failed']}.")

        if estado == "FINISHED":
            return findings, status, False
        if estado == "ERROR":
            raise ErroApi(f"Export terminou em ERROR. Motivo: {status.get('reason')}",
                          causa="export_error")
        if estado == "CANCELLED":
            raise ErroApi("Export foi cancelado.", causa="export_cancelado")
        if time.time() > limite:
            return findings, status, True

        time.sleep(intervalo)
        intervalo = min(intervalo + 5, 30)


# ----------------------------------------------------------------------------
# Normalizacao  (portado: iso_para_epoch 529, epoch_para_iso 558, normalizar 564)
# ----------------------------------------------------------------------------

def iso_para_epoch(valor) -> int | None:
    """Aceita ISO 8601 ou epoch (int/str). Devolve int epoch ou None."""
    if valor in (None, "", 0):
        return None
    if isinstance(valor, (int, float)):
        return int(valor)
    texto = str(valor).strip()
    if texto.isdigit():
        return int(texto)
    texto = texto.replace("Z", "+00:00")
    if "." in texto:   # trunca fracao de segundo com mais de 6 digitos
        cabeca, resto = texto.split(".", 1)
        digitos = ""
        for ch in resto:
            if ch.isdigit():
                digitos += ch
            else:
                resto = resto[len(digitos):]
                break
        else:
            resto = ""
        texto = f"{cabeca}.{digitos[:6]}{resto}"
    try:
        return int(datetime.fromisoformat(texto).timestamp())
    except ValueError:
        return None


def epoch_para_iso(epoch) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def normalizar(f: dict, agora: int) -> dict:
    asset = f.get("asset") or {}
    plugin = f.get("plugin") or {}
    cves = plugin.get("cve") or []
    if isinstance(cves, str):
        cves = [cves]

    primeiro = iso_para_epoch(f.get("first_found"))
    ultimo = iso_para_epoch(f.get("last_found"))
    corrigido = iso_para_epoch(f.get("last_fixed"))
    nativo = f.get("time_taken_to_fix")

    dias, fonte = None, ""
    if isinstance(nativo, (int, float)) and nativo > 0:
        dias, fonte = round(nativo / 86400.0, 2), "nativo"
    elif corrigido and primeiro and corrigido >= primeiro:
        dias, fonte = round((corrigido - primeiro) / 86400.0, 2), "derivado"

    estado = (f.get("state") or "").upper()
    idade_aberta = None
    if estado in ("OPEN", "REOPENED") and primeiro:
        idade_aberta = round((agora - primeiro) / 86400.0, 2)

    ipv4 = asset.get("ipv4")
    nome_ip = (ipv4 or [""])[0] if isinstance(ipv4, list) else (ipv4 or "")
    return {
        "finding_id": f.get("finding_id", ""),
        "asset_uuid": asset.get("uuid") or asset.get("id") or "",
        "asset_nome": (asset.get("hostname") or asset.get("name")
                       or asset.get("fqdn") or nome_ip or ""),
        "plugin_id": plugin.get("id", ""),
        "plugin_nome": plugin.get("name", ""),
        "cve": ";".join(cves),
        "severidade": f.get("severity", ""),
        "severidade_modificada": f.get("severity_modification_type", ""),
        "vpr": ((plugin.get("vpr") or {}).get("score", "")
                if isinstance(plugin.get("vpr"), dict) else ""),
        "cvss3_base": plugin.get("cvss3_base_score", ""),
        "estado": estado,
        "first_found": epoch_para_iso(primeiro),
        "last_found": epoch_para_iso(ultimo),
        "last_fixed": epoch_para_iso(corrigido),
        "resurfaced_date": epoch_para_iso(iso_para_epoch(f.get("resurfaced_date"))),
        "time_taken_to_fix_seg": nativo if isinstance(nativo, (int, float)) else "",
        "dias_para_corrigir": dias if dias is not None else "",
        "mttr_fonte": fonte,
        "dias_em_aberto": idade_aberta if idade_aberta is not None else "",
        "fonte_scan": f.get("source", ""),
    }


# ----------------------------------------------------------------------------
# Analise  (portado: comparar_filtros 618, detectar_lotes 653, percentil 710)
# ----------------------------------------------------------------------------

def comparar_filtros(pedidos, aplicados) -> tuple[bool, dict]:
    """Comparacao SEMANTICA, nao literal.

    A API nao devolve o que foi enviado: normaliza a severidade (maiuscula, em
    outra ordem) e acrescenta TODOS os filtros de data com valor zero. Comparar
    os dois dicionarios literalmente acusaria divergencia em toda execucao - e
    e por isso que o consumidor le `filtros_divergiram`, nunca os dois dicts.
    """
    if not isinstance(pedidos, dict) or not isinstance(aplicados, dict):
        return True, {"erro": "filtros ausentes ou em formato inesperado"}

    def norm(v):
        if isinstance(v, (list, tuple)):
            return {str(x).strip().lower() for x in v}
        if isinstance(v, str):
            return v.strip().lower()
        return v

    div: dict[str, Any] = {}
    for k, pedido in pedidos.items():
        if k not in aplicados:
            div[k] = {"pedido": pedido, "aplicado": "<ausente>"}
        elif norm(pedido) != norm(aplicados[k]):
            div[k] = {"pedido": pedido, "aplicado": aplicados[k]}
    # Chaves que o job trouxe e nao foram pedidas so contam se tiverem valor:
    # as de data vem sempre com 0 e sao default da API, nao filtro aplicado.
    for k, v in aplicados.items():
        if k in pedidos or v in (0, "", None, [], {}, False):
            continue
        div[k] = {"pedido": "<nao pedido>", "aplicado": v}
    return bool(div), div


def detectar_lotes(linhas: list[dict], corte: int = 2) -> dict:
    """Acha findings fechados em lote: mesmo ativo, mesma first_found, mesma
    last_fixed. Todos compartilham o MESMO dias_para_corrigir por construcao, e
    esse valor e o INTERVALO ENTRE DOIS SCANS, nao o tempo de acao da equipe.

    Um ativo escaneado em 09/06, nao escaneado de novo, e visto limpo em 02/09
    produz 85 dias para tudo que estava nele - inclusive o que foi corrigido no
    primeiro dia. Sem esta deteccao o relatorio confunde cadencia com MTTR.

    O `corte` entra no resumo porque MUDA o percentual: no CSV de referencia de
    2026-09-03 deu 93,5% com corte 2, 74,2% com 3, 64,5% com 4 e 38,7% com 5 -
    e o limiar de alerta da skill e 40%. Com corte 5 o mesmo dado passaria pela
    guarda. Quem le o numero precisa saber com que corte ele foi feito.
    """
    grupos: dict[tuple, list] = {}
    for l in linhas:
        if l["estado"] != "FIXED" or not l["dias_para_corrigir"]:
            continue
        grupos.setdefault((l["asset_nome"], l["first_found"], l["last_fixed"]), []).append(l)

    total = sum(1 for l in linhas
                if l["estado"] == "FIXED" and l["dias_para_corrigir"])

    def _pct(c: int) -> float:
        n = sum(len(v) for v in grupos.values() if len(v) >= c)
        return round(n / total * 100, 1) if total else 0.0

    lotes = {k: v for k, v in grupos.items() if len(v) >= corte}
    em_lote = sum(len(v) for v in lotes.values())
    detalhe = sorted(
        ({"ativo": k[0], "first_found": k[1], "last_fixed": k[2],
          "findings": len(v), "dias_para_corrigir": float(v[0]["dias_para_corrigir"])}
         for k, v in lotes.items()), key=lambda d: -d["findings"])

    # Se um punhado de datas explica TODAS as janelas, essas datas sao as datas
    # de scan e o MTTR e o intervalo entre elas. O consumidor cruza contra o
    # historico de scan - e foi assim que M4 virou lacuna no sandbox: as 7 datas
    # eram, 7 de 7, dias de execucao do scan 33.
    datas: set = set()
    for k in grupos:
        datas.add(str(k[1])[:10])
        datas.add(str(k[2])[:10])

    # TODAS as janelas, inclusive as de um finding so. `lotes` ja vem filtrado
    # pelo corte, entao alimentar a guarda com ele exclui as janelas unitarias
    # do denominador e inflaciona o percentual - aqui deu 100% contra os 93,5%
    # reais, e sumiu uma das 7 datas.
    janelas = sorted(
        ({"ativo": k[0], "first_found": k[1], "last_fixed": k[2],
          "findings": len(v), "dias_para_corrigir": float(v[0]["dias_para_corrigir"])}
         for k, v in grupos.items()), key=lambda d: -d["findings"])

    return {
        "findings_em_lote": em_lote,
        "findings_com_mttr": total,
        "janelas": janelas,
        "pct_em_lote": round(em_lote / total * 100, 1) if total else 0.0,
        "lote_minimo_por_janela": corte,
        "sensibilidade_ao_corte": {str(c): _pct(c) for c in (2, 3, 4, 5)},
        "janelas_distintas": len(grupos),
        "datas_que_formam_as_janelas": sorted(datas),
        "lotes": detalhe,
        "nota_janelas": ("`janelas` traz TODAS as janelas, inclusive as de um "
                         "finding so; `lotes` traz apenas as que atingem o corte. "
                         "Passe `janelas` para mttr_cadence_guard - passar `lotes` "
                         "exclui as unitarias do denominador e inflaciona o "
                         "percentual."),
    }


def percentil(ordenados: list[float], p: float) -> float | None:
    """Percentil INTERPOLADO: interpolacao linear entre as duas posicoes
    vizinhas (tipo 7 do R, default do numpy, PERCENTIL.INC do Excel).

    Com n pequeno a escolha muda o numero: no CSV de referencia o p90 de
    critical com n=10 deu 101,43 interpolado e 92,91 por posicao mais proxima -
    9% de diferenca. Por isso o metodo vai DECLARADO no resumo.
    """
    if not ordenados:
        return None
    if len(ordenados) == 1:
        return round(ordenados[0], 2)
    pos = (len(ordenados) - 1) * (p / 100.0)
    baixo = int(pos)
    alto = min(baixo + 1, len(ordenados) - 1)
    peso = pos - baixo
    return round(ordenados[baixo] * (1 - peso) + ordenados[alto] * peso, 2)


def percentil_posicao_mais_proxima(ordenados: list[float], p: float) -> float | None:
    """O outro metodo, para o resumo poder mostrar o efeito da escolha."""
    if not ordenados:
        return None
    i = int(round((len(ordenados) - 1) * (p / 100.0)))
    return round(ordenados[i], 2)


def resumir(linhas: list[dict], filtros: dict, uuid: str, status: dict,
            corte_lote: int = 2) -> dict:
    por_sev: dict[str, dict] = {}
    for l in linhas:
        sev = l["severidade"] or "sem_severidade"
        b = por_sev.setdefault(sev, {"corrigidos": [], "nativo": 0, "derivado": 0,
                                     "sem_data": 0, "abertos": [], "total": 0,
                                     "reabertos": 0, "reabertos_com_data": []})
        b["total"] += 1
        if l["estado"] == "REOPENED":
            b["reabertos"] += 1
            if l["dias_para_corrigir"] != "":
                b["reabertos_com_data"].append(float(l["dias_para_corrigir"]))
        if l["estado"] == "FIXED":
            if l["dias_para_corrigir"] != "":
                b["corrigidos"].append(float(l["dias_para_corrigir"]))
                b[l["mttr_fonte"]] += 1
            else:
                b["sem_data"] += 1
        elif l["dias_em_aberto"] != "":
            b["abertos"].append(float(l["dias_em_aberto"]))

    saida = {}
    for sev, b in sorted(por_sev.items()):
        ordenados = sorted(b["corrigidos"])
        abertos = sorted(b["abertos"])
        saida[sev] = {
            "findings_no_recorte": b["total"],
            "corrigidos_com_data": len(ordenados),
            "corrigidos_sem_data": b["sem_data"],
            "origem_nativo_time_taken_to_fix": b["nativo"],
            "origem_derivado_last_fixed_menos_first_found": b["derivado"],
            "mttr_dias_media": (round(sum(ordenados) / len(ordenados), 2)
                                if ordenados else None),
            "mttr_dias_p50": percentil(ordenados, 50),
            "mttr_dias_p90": percentil(ordenados, 90),
            "mttr_dias_p90_posicao_mais_proxima": percentil_posicao_mais_proxima(
                ordenados, 90),
            "mttr_dias_max": round(ordenados[-1], 2) if ordenados else None,
            "abertos_no_recorte": len(abertos),
            "idade_dias_p50_abertos": percentil(abertos, 50),
            "idade_dias_p90_abertos": percentil(abertos, 90),
            "reabertos_no_recorte": b["reabertos"],
            "reabertos_excluidos_do_mttr": len(b["reabertos_com_data"]),
            "mttr_dias_media_se_incluir_reabertos": (
                round((sum(ordenados) + sum(b["reabertos_com_data"]))
                      / (len(ordenados) + len(b["reabertos_com_data"])), 2)
                if (ordenados or b["reabertos_com_data"]) else None),
        }

    divergiu, divergencias = comparar_filtros(filtros, status.get("filters"))
    recast = sum(1 for l in linhas
                 if l["severidade_modificada"] not in ("", "NONE", None))
    return {
        "ferramenta": f"tenable_mttr_export.py {VERSAO_COLETOR}",
        "coletado_em_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base_url": base_url(),
        "export_uuid": uuid,
        "filtros_pedidos": filtros,
        "filtros_aplicados_pelo_job": status.get("filters"),
        "filtros_divergiram": divergiu,
        "filtros_divergencias": divergencias,
        "nota_comparacao_filtros": (
            "A API normaliza os filtros e devolve todos os de data com valor 0. "
            "Use `filtros_divergiram`, que ja compara de forma semantica; comparar "
            "os dois dicionarios literalmente acusa divergencia em toda execucao."),
        "cadencia_de_scan": detectar_lotes(linhas, corte_lote),
        "severidade_modificada_diferente_de_none": recast,
        "nota_severidade_modificada": (
            "Vem de `severity_modification_type`, que a API de Exposure Management "
            "NAO expoe: e a unica medicao direta de recast e aceitacao que o "
            "assessment alcanca, e vale para S3, P1 e P2, nao so para M4."),
        "metodo_percentil": (
            "interpolado - interpolacao linear entre as duas posicoes vizinhas "
            "(tipo 7 do R, default do numpy, PERCENTIL.INC do Excel). O valor por "
            "posicao mais proxima vai junto, em "
            "`mttr_dias_p90_posicao_mais_proxima`, para o leitor medir o efeito "
            "da escolha."),
        "estados_incluidos_no_mttr": ["FIXED"],
        "nota_estados": (
            "O MTTR e calculado SO sobre findings FIXED. REOPENED sao contados em "
            "`reabertos_no_recorte` e ficam FORA da media: um finding reaberto nao "
            "foi corrigido. `mttr_dias_media_se_incluir_reabertos` existe para o "
            "leitor medir o efeito da exclusao - no CSV de referencia a media de "
            "high ia de 60,39 para 49,66 dias."),
        "nota_cadencia": (
            "`time_taken_to_fix` mede deteccao a deteccao, nao tempo de acao. "
            "Findings do mesmo ativo com a mesma first_found e a mesma last_fixed "
            "foram todos vistos corrigidos no MESMO scan: o valor deles e o "
            "intervalo entre dois scans. Se `pct_em_lote` for alto, o MTTR e "
            "LIMITE SUPERIOR determinado pela cadencia e nao mede a equipe. Leia "
            "junto `lote_minimo_por_janela`, `sensibilidade_ao_corte` e "
            "`datas_que_formam_as_janelas`: se poucas datas explicam todas as "
            "janelas, essas datas sao as datas de scan - confirme contra "
            "scan_cadence."),
        "status_final_do_job": status.get("status"),
        "total_chunks": status.get("total_chunks"),
        "chunks_com_falha": status.get("chunks_failed") or [],
        "registros_analisados": len(linhas),
        "endpoint": "POST /vulns/export (Tenable Vulnerability Management API)",
        "definicao_mttr": (
            "dias_para_corrigir = time_taken_to_fix/86400 quando a API devolve o "
            "campo (mttr_fonte=nativo); senao (last_fixed - first_found)/86400 "
            "(mttr_fonte=derivado). Findings FIXED sem nenhuma das duas datas "
            "entram em corrigidos_sem_data e NAO entram na media."),
        "mttr_por_severidade": saida,
    }


# ----------------------------------------------------------------------------
# A tool
# ----------------------------------------------------------------------------

def mttr_collect(days: int = 180, severities: list[str] | None = None,
                 tags: dict | None = None, max_wait_s: int = 240,
                 export_uuid: str | None = None, estados: list[str] | None = None,
                 num_assets: int = 100, corte_lote: int = 2) -> dict[str, Any]:
    """Abre (ou retoma) o export, agrega e devolve o resumo.

    Tres comportamentos obrigatorios, todos herdados do coletor:
      1. estouro de max_wait_s -> {status: "pendente", export_uuid}, sem excecao
      2. filtros_divergiram -> erro estruturado, nunca numero
      3. falha de TLS -> causa diagnosticada, nunca excecao crua
    """
    severities = [s.lower() for s in (severities or ["critical", "high"])]
    invalidas = [s for s in severities if s not in SEVERIDADES_VALIDAS]
    if invalidas:
        raise ValueError(f"severidade invalida: {invalidas}. Use {SEVERIDADES_VALIDAS}.")
    estados = [e.upper() for e in (estados or list(ESTADOS_VALIDOS))]

    try:
        if export_uuid:
            uuid, filtros, retomado = export_uuid, {}, True
        else:
            uuid, filtros, retomado = abrir_export(days, severities, estados,
                                                   num_assets, tags or {})

        findings, status, pendente = aguardar(uuid, max_wait_s)

        if pendente:
            # NAO levanta excecao, e NAO devolve numero parcial: devolve o
            # bilhete para a proxima chamada retomar. Pedir outro export
            # responderia 409.
            return {
                "status": "pendente",
                "export_uuid": uuid,
                "status_do_job": status.get("status"),
                "chunks_prontos": status.get("finished_chunks"),
                "total_chunks": status.get("total_chunks"),
                "findings_baixados_ate_agora": len(findings),
                "como_retomar": (f"chame mttr_collect novamente com "
                                 f"export_uuid='{uuid}'. NAO abra um export novo: "
                                 "a API responde 409 enquanto este estiver aberto."),
            }

        agora = int(time.time())
        linhas = [normalizar(f, agora) for f in findings]
        resumo = resumir(linhas, filtros or status.get("filters") or {},
                         uuid, status, corte_lote)

        if resumo["filtros_divergiram"] and not retomado:
            raise ErroFiltroDivergente(
                "O job aplicou um recorte diferente do pedido, entao o numero "
                "nao corresponde a pergunta. Divergencias: "
                + json.dumps(resumo["filtros_divergencias"], ensure_ascii=False),
                causa="filtros_divergiram")

        resumo["status"] = "concluido"
        resumo["export_retomado"] = retomado
        if retomado and resumo["filtros_divergiram"]:
            resumo["aviso_retomada"] = (
                "Export retomado: os filtros deste job podem nao ser os que voce "
                "pediu. Os filtros reais estao em `filtros_aplicados_pelo_job`.")
        return resumo

    except ErroTLS:
        # Sobe intacto: client.py ja diagnosticou a causa (proxy corporativo
        # interceptando TLS) e o servidor nunca oferece desligar a verificacao.
        raise


def mttr_cadence_guard(janelas: list[dict], datas_de_scan: list[str] | None = None,
                       corte_alerta_pct: float = 40.0) -> dict[str, Any]:
    """Recebe as janelas do MTTR e diz se ele esta medindo cadencia de scan.

    Dois portoes, e o segundo e o que importa mais:
      1. `pct_em_lote` acima do corte -> M4 e lacuna;
      2. janelas formadas SO por datas de scan -> M4 e lacuna, mesmo com
         pct_em_lote abaixo do corte.

    O portao 2 existe porque o percentual depende do corte de lote escolhido, e
    o corte 5 faria o mesmo dado passar. A composicao das datas nao depende de
    escolha nenhuma.
    """
    linhas = [dict(j) for j in (janelas or [])]
    total = sum(int(j.get("findings") or 0) for j in linhas)

    def pct(c: int) -> float:
        n = sum(int(j["findings"]) for j in linhas if int(j.get("findings") or 0) >= c)
        return round(n / total * 100, 1) if total else 0.0

    datas: set = set()
    for j in linhas:
        for k in ("first_found", "last_fixed"):
            if j.get(k):
                datas.add(str(j[k])[:10])

    do_scan = {str(d)[:10] for d in (datas_de_scan or [])}
    coincidem = sorted(datas & do_scan) if do_scan else []
    todas_de_scan = bool(do_scan) and datas.issubset(do_scan)
    sens = {str(c): pct(c) for c in (2, 3, 4, 5)}

    motivos = []
    if sens["2"] >= corte_alerta_pct:
        motivos.append(f"pct_em_lote com corte 2 e {sens['2']}%, acima do corte de "
                       f"alerta de {corte_alerta_pct}%")
    if todas_de_scan:
        motivos.append(f"as {len(datas)} datas que formam as janelas sao TODAS datas "
                       "de execucao de scan: o MTTR aqui e o intervalo entre scans")

    return {
        "pct_em_lote": sens["2"],
        "corte_usado": 2,
        "corte_de_alerta_pct": corte_alerta_pct,
        "sensibilidade_ao_corte": sens,
        "datas_que_formam_as_janelas": sorted(datas),
        "datas_de_scan_informadas": sorted(do_scan),
        "datas_que_coincidem_com_scan": coincidem,
        "todas_as_datas_sao_de_scan": todas_de_scan,
        "veredito": "lacuna" if motivos else "pode_pontuar",
        "motivos": motivos,
        "nota": ("O percentual depende do corte de lote escolhido - com corte 5 o "
                 "mesmo dado passaria pela guarda. A composicao das datas nao "
                 "depende de escolha nenhuma, e por isso e o portao mais forte."),
    }
