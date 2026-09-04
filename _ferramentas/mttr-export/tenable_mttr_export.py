#!/usr/bin/env python3
r"""
tenable_mttr_export.py - standalone MTTR collector.

NOT AN EXECUTION PATH OF THIS PROJECT. It is kept here for two reasons only:
it is the ORIGIN OF THE CODE that became src/tenable_ctem_mcp/mttr.py, and it
generated the recorded fixtures the golden tests run against.

The assessment does not call it. `ctem_mobilization` calls `mttr_collect`
internally, and there is deliberately one execution path, not two. Nothing needs
to be run by hand and no CSV is carried anywhere.

The original header follows, unchanged, because it documents the reasoning that
produced the port.

---

tenable_mttr_export.py - coletor de MTTR real da Tenable Vulnerability Management.

Por que este script existe
--------------------------
O MCP Tenable consome a API de Exposure Management, e nela o campo `last_fixed`
NAO existe. Sem data de correcao, nao ha MTTR: so aproximacao. O campo existe na
API de Vulnerability Management, no export de vulnerabilidades, que o MCP ainda
nao encapsula. Este script chama esse endpoint diretamente e grava um CSV que a
skill de MTTR consome como entrada.

Fonte (spec OpenAPI oficial Tenable_Vulnerability_Management_API.json):
  POST /vulns/export                              operationId exports-vulns-request-export
  GET  /vulns/export/{export_uuid}/status         operationId exports-vulns-export-status
  GET  /vulns/export/{export_uuid}/chunks/{id}    operationId exports-vulns-download-chunk
  POST /vulns/export/{export_uuid}/cancel         operationId exports-vulns-export-cancel

Campos de saida usados (schema do chunk de download):
  first_found        ISO timestamp — quando um scan detectou o finding pela primeira vez
  last_found         ISO timestamp — quando um scan detectou pela ultima vez
  last_fixed         ISO timestamp — quando um scan deixou de detectar o finding corrigido
  time_taken_to_fix  inteiro em segundos — tempo que a organizacao levou para corrigir
  state              OPEN | REOPENED | FIXED
  resurfaced_date    ISO timestamp — quando a vulnerabilidade ressurgiu

O `time_taken_to_fix` e calculado pela propria Tenable. Este script prefere esse
valor. So cai para `last_fixed - first_found` quando o campo vem vazio, e nesse
caso marca a linha com mttr_source=derivado para que o relatorio possa separar.

Postura de seguranca
--------------------
Somente leitura de dado. O unico POST e o que abre o job de export, que e o
mecanismo padrao de leitura em volume da Tenable; nao altera nada no tenant.
Nao ha nenhuma chamada que crie, edite ou apague objeto. As chaves sao lidas de
variavel de ambiente e nunca sao impressas nem gravadas em arquivo.

Requisitos
----------
Python 3.8 ou superior. Nenhuma dependencia externa: usa somente a biblioteca
padrao. Nao precisa de pip install.

Uso
---
  export TIO_ACCESS_KEY=xxxxxxxx
  export TIO_SECRET_KEY=yyyyyyyy
  python3 tenable_mttr_export.py --days 180 --severity critical,high

  # ambiente FedRAMP
  export TIO_URL=https://fedcloud.tenable.com

Se der erro de certificado TLS
------------------------------
Nao e problema de rede e nao melhora tentando de novo. Rode:

  python3 tenable_mttr_export.py --diagnostico-tls

Ele diz qual das duas causas e a sua e some. As saidas:

  A) Python do python.org sem certificados instalados:
       /Applications/Python\ 3.14/Install\ Certificates.command
  B) rede corporativa inspecionando TLS (CA interna no Keychain):
       python3 tenable_mttr_export.py --ca-macos-keychain --days 180

Tambem aceita --ca-bundle /caminho/ca.pem ou TIO_CA_BUNDLE no ambiente.
A verificacao de certificado NUNCA e desligada: sem ela as chaves de API do
tenant seguiriam por um canal que pode estar sendo lido por terceiro.

Saidas gravadas no diretorio corrente (ou em --outdir):
  tenable_mttr_findings_<data>.csv   uma linha por finding
  tenable_mttr_resumo_<data>.json    MTTR por severidade e registro da coleta

Permissao necessaria: papel Basic [16] ou o privilegio VM.VM_EXPLORE.
"""

import argparse
import csv
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

VERSAO = "1.1.0"
UA = f"tenable-mttr-export/{VERSAO} (Tenable channel SE toolkit)"

SEVERIDADES_VALIDAS = ("info", "low", "medium", "high", "critical")
ESTADOS_VALIDOS = ("OPEN", "REOPENED", "FIXED")


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

class ErroApi(Exception):
    pass


def _chaves():
    ak = os.environ.get("TIO_ACCESS_KEY", "").strip()
    sk = os.environ.get("TIO_SECRET_KEY", "").strip()
    if not ak or not sk:
        raise ErroApi(
            "Defina TIO_ACCESS_KEY e TIO_SECRET_KEY no ambiente antes de rodar.\n"
            "  export TIO_ACCESS_KEY=...\n  export TIO_SECRET_KEY=..."
        )
    return ak, sk


def _base_url():
    return os.environ.get("TIO_URL", "https://cloud.tenable.com").rstrip("/")


class ErroTLS(ErroApi):
    """Falha de verificacao de certificado. NAO e erro transitorio: nao tentar de novo."""


AJUDA_TLS = r"""
Falha ao verificar o certificado TLS de {host}.

Isto NAO e problema de rede e nao melhora tentando de novo. O Python nao esta
achando a cadeia de certificados. Duas causas possiveis:

  A) Python instalado do python.org sem os certificados. Rode uma vez:
       /Applications/Python\ 3.14/Install\ Certificates.command
     (ajuste a versao para a sua)

  B) A rede corporativa inspeciona TLS e apresenta um certificado assinado por
     uma CA interna, que esta no Keychain do macOS mas nao no bundle do Python.
     Neste caso rode com o Keychain do macOS como fonte de confianca:
       python3 {prog} --ca-macos-keychain <demais argumentos>

Para saber qual das duas e a sua, rode:
       python3 {prog} --diagnostico-tls

Se preferir apontar o bundle na mao:
       python3 {prog} --ca-bundle /caminho/para/ca.pem <demais argumentos>
   ou   export TIO_CA_BUNDLE=/caminho/para/ca.pem

Nao existe opcao para desligar a verificacao, e nao deve existir: sem
verificacao as chaves de API do tenant seguem por um canal que pode estar
sendo lido por terceiro.
"""

_CTX = {"ctx": None, "origem": ""}


def estado_store_padrao():
    """Diz se este Python tem, de fato, um conjunto de CAs utilizavel.
    Distinguir 'store ausente' de 'store presente mas nao confia nesta cadeia'
    é o que separa a causa A da causa B."""
    try:
        import certifi
        return True, f"certifi em {certifi.where()}"
    except ImportError:
        pass
    vp = ssl.get_default_verify_paths()
    for atr in ("cafile", "openssl_cafile"):
        c = getattr(vp, atr, None)
        if c and os.path.exists(c) and os.path.getsize(c) > 0:
            return True, f"{atr}={c}"
    for atr in ("capath", "openssl_capath"):
        d = getattr(vp, atr, None)
        if d and os.path.isdir(d):
            try:
                if any(os.scandir(d)):
                    return True, f"{atr}={d}"
            except OSError:
                pass
    return False, ("nenhum arquivo de CAs encontrado — certifi nao instalado e "
                   f"openssl_cafile ({vp.openssl_cafile}) nao existe")


def _pem_do_keychain():
    """Monta um bundle PEM a partir dos Keychains do macOS (inclui CAs corporativas
    instaladas por MDM). Usa o binario `security`, presente em todo macOS."""
    import subprocess, tempfile
    chaveiros = ["/System/Library/Keychains/SystemRootCertificates.keychain",
                 "/Library/Keychains/System.keychain"]
    pedacos = []
    for k in chaveiros:
        if not os.path.exists(k):
            continue
        try:
            out = subprocess.run(["security", "find-certificate", "-a", "-p", k],
                                 capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            raise ErroTLS(f"Nao consegui ler o Keychain {k}: {e}")
        if out.returncode == 0 and "BEGIN CERTIFICATE" in out.stdout:
            pedacos.append(out.stdout)
    if not pedacos:
        raise ErroTLS("Nenhum certificado encontrado nos Keychains do macOS. "
                      "Esta opcao so funciona em macOS.")
    fh = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8")
    fh.write("\n".join(pedacos))
    fh.close()
    n = "\n".join(pedacos).count("BEGIN CERTIFICATE")
    log(f"       {n} certificados lidos do Keychain do macOS")
    return fh.name


def configurar_tls(ca_bundle=None, usar_keychain=False):
    """Monta o contexto SSL uma unica vez. A verificacao NUNCA e desligada."""
    if usar_keychain:
        caminho = _pem_do_keychain()
        _CTX["ctx"] = ssl.create_default_context(cafile=caminho)
        _CTX["origem"] = f"Keychain do macOS ({caminho})"
        return
    caminho = ca_bundle or os.environ.get("TIO_CA_BUNDLE", "").strip()
    if caminho:
        if not os.path.exists(caminho):
            raise ErroTLS(f"Bundle de CA nao encontrado: {caminho}")
        _CTX["ctx"] = ssl.create_default_context(cafile=caminho)
        _CTX["origem"] = f"bundle informado ({caminho})"
        return
    tem, detalhe = estado_store_padrao()
    if not tem and sys.platform == "darwin":
        # Este Python nao tem CAs proprias. Em vez de falhar, cair no Keychain do
        # macOS — que e a mesma raiz de confianca que o Safari usa e que o proprio
        # usuario administra. A verificacao segue LIGADA; so muda a fonte das CAs.
        log(f"AVISO: este Python nao tem conjunto de CAs proprio ({detalhe}).")
        log("       Usando o Keychain do macOS como fonte de confianca. A verificacao")
        log("       de certificado continua ativa. Para corrigir na origem, rode uma vez")
        log("       /Applications/Python\\ <versao>/Install\\ Certificates.command")
        try:
            caminho = _pem_do_keychain()
            _CTX["ctx"] = ssl.create_default_context(cafile=caminho)
            _CTX["origem"] = f"Keychain do macOS, por ausencia de store proprio ({caminho})"
            return
        except ErroTLS as e:
            log(f"       Nao consegui usar o Keychain: {e}")
    _CTX["ctx"] = ssl.create_default_context()
    _CTX["origem"] = f"padrao do Python ({detalhe})"
    if not tem:
        log(f"AVISO: este Python nao tem conjunto de CAs utilizavel ({detalhe}).")
        log("       A verificacao TLS vai falhar. Rode --diagnostico-tls, ou use "
            "--ca-bundle.")


def contexto():
    if _CTX["ctx"] is None:
        configurar_tls()
    return _CTX["ctx"]


def diagnostico_tls():
    """Descobre por que a verificacao de certificado falhou e CONCLUI qual e a causa.
    Nao envia chave de API nem dado nenhum: abre a conexao, le a cadeia e fecha."""
    import socket
    from urllib.parse import urlparse
    alvo = urlparse(_base_url())
    host = alvo.hostname or "cloud.tenable.com"
    porta = alvo.port or 443

    tem_store, detalhe_store = estado_store_padrao()
    print(f"Python:     {sys.version.splitlines()[0]}")
    print(f"Executavel: {sys.executable}")
    print(f"OpenSSL:    {ssl.OPENSSL_VERSION}")
    print(f"Conjunto de CAs deste Python: "
          f"{'PRESENTE — ' + detalhe_store if tem_store else 'AUSENTE — ' + detalhe_store}")
    print(f"Host testado: {host}:{porta}\n")

    res = {}
    for chave, rotulo, kwargs in (("padrao", "padrao do Python", {}),
                                  ("keychain", "Keychain do macOS", {"usar_keychain": True})):
        try:
            configurar_tls(**kwargs)
            with socket.create_connection((host, porta), timeout=20) as sock:
                with contexto().wrap_socket(sock, server_hostname=host) as ss:
                    c = ss.getpeercert()
                    em = dict(x[0] for x in c.get("issuer", []))
                    res[chave] = ("ok", em.get("organizationName") or em.get("commonName") or "?")
                    print(f"  OK   verificacao com {rotulo}: emissor {res[chave][1]}")
        except ErroTLS as e:
            res[chave] = ("indisponivel", str(e))
            print(f"  --   {rotulo}: indisponivel ({e})")
        except ssl.SSLError as e:
            res[chave] = ("falhou", str(e))
            print(f"  X    verificacao com {rotulo} FALHOU: {e}")
        except OSError as e:
            res[chave] = ("erro", str(e))
            print(f"  X    {rotulo}: erro de conexao {e}")

    # Leitura da cadeia SEM verificar, so para identificar inspecao de TLS.
    # Nenhum dado e enviado nesta conexao.
    print("\nCadeia realmente apresentada pela rede (leitura sem verificar, "
          "nenhum dado enviado):")
    emissor_bruto = ""
    ctx_bruto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_bruto.check_hostname = False
    ctx_bruto.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, porta), timeout=20) as sock:
            with ctx_bruto.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                import subprocess, tempfile
                fh = tempfile.NamedTemporaryFile("wb", suffix=".der", delete=False)
                fh.write(der); fh.close()
                out = subprocess.run(
                    ["openssl", "x509", "-inform", "DER", "-in", fh.name,
                     "-noout", "-subject", "-issuer"],
                    capture_output=True, text=True, timeout=30)
                txt = (out.stdout or out.stderr).strip()
                print("  " + txt.replace("\n", "\n  "))
                for linha in txt.splitlines():
                    if linha.lower().startswith("issuer"):
                        emissor_bruto = linha
    except OSError as e:
        print(f"  X    nem sem verificar a conexao completou: {e}")
    except Exception as e:
        print(f"  (nao consegui decodificar a cadeia: {e})")

    # ---- veredito ----
    prog = os.path.basename(__file__)
    print("\n" + "=" * 70)
    padrao_ok = res.get("padrao", ("", ""))[0] == "ok"
    key_ok = res.get("keychain", ("", ""))[0] == "ok"

    if padrao_ok:
        print("VEREDITO: nao ha problema de TLS. A verificacao padrao passou.")
        print("Se o export falhou, a causa e outra — releia a mensagem de erro dele.")
    elif not tem_store:
        print("VEREDITO: CAUSA A — este Python nao tem conjunto de CAs instalado.")
        print(f"  Evidencia: {detalhe_store}.")
        print("  Um Python sem conjunto de CAs nao consegue verificar cadeia nenhuma,")
        print("  entao esta causa vale independentemente de haver inspecao de TLS na rede.")
        if emissor_bruto:
            print(f"  Emissor apresentado: {emissor_bruto.split('=',1)[-1]}")
            print("  Se esse emissor for uma CA publica conhecida (Google Trust Services,")
            print("  DigiCert, Sectigo, Amazon...), nao ha inspecao — e so a causa A.")
        print("\n  Correcao definitiva, uma vez, e vale para todo script Python da maquina:")
        print("     /Applications/Python\\ <sua-versao>/Install\\ Certificates.command")
        print("     (ex.: /Applications/Python\\ 3.14/Install\\ Certificates.command)")
        if key_ok:
            print("\n  Para coletar AGORA, sem instalar nada, acrescente a toda execucao:")
            print(f"     python3 {prog} --ca-macos-keychain <demais argumentos>")
            print("  O Keychain do macOS ja verificou este host com sucesso acima.")
    elif key_ok:
        print("VEREDITO: CAUSA B — a rede apresenta uma cadeia que so o sistema confia.")
        print(f"  Evidencia: o store deste Python existe ({detalhe_store}) e ainda assim")
        print("  reprovou, enquanto o Keychain do macOS aprovou.")
        if emissor_bruto:
            print(f"  Emissor apresentado: {emissor_bruto.split('=',1)[-1]}")
        print("\n  Rode sempre com:")
        print(f"     python3 {prog} --ca-macos-keychain <demais argumentos>")
    else:
        print("VEREDITO: inconclusivo — nem o store padrao nem o Keychain verificaram o host.")
        print("  Isso costuma ser bloqueio de saida na rede, proxy exigindo autenticacao,")
        print("  ou host errado em TIO_URL. Confira o alvo e a conectividade antes do TLS.")
        if emissor_bruto:
            print(f"  Emissor apresentado: {emissor_bruto.split('=',1)[-1]}")
    print("=" * 70)
    print("\nEm nenhum caso a verificacao de certificado deve ser desligada: sem ela as")
    print("chaves de API do tenant seguem por um canal que pode estar sendo lido.")
    return 0


def chamar(metodo, caminho, corpo=None, tentativas=5, bruto=False):
    """Chama a API com retry em 429 e 5xx. Devolve dict/list, ou bytes se bruto."""
    ak, sk = _chaves()
    url = _base_url() + caminho
    dados = json.dumps(corpo).encode("utf-8") if corpo is not None else None
    espera = 3
    ultimo = None
    for tentativa in range(1, tentativas + 1):
        req = urllib.request.Request(url, data=dados, method=metodo)
        req.add_header("X-ApiKeys", f"accessKey={ak};secretKey={sk}")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", UA)
        if dados is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=180, context=contexto()) as r:
                conteudo = r.read()
                if bruto:
                    return conteudo
                return json.loads(conteudo) if conteudo else {}
        except urllib.error.HTTPError as e:
            texto = e.read().decode("utf-8", "replace")[:500]
            if e.code == 409:
                # job de export ja em andamento: devolve para o chamador tratar
                try:
                    return {"_conflito": json.loads(texto)}
                except Exception:
                    raise ErroApi(f"409 em {caminho}: {texto}")
            if e.code == 401:
                raise ErroApi("401 nao autorizado. Confira TIO_ACCESS_KEY e TIO_SECRET_KEY.")
            if e.code == 403:
                raise ErroApi(
                    "403 sem permissao. A chave precisa do papel Basic [16] ou do "
                    f"privilegio VM.VM_EXPLORE. Resposta: {texto}"
                )
            if e.code in (429, 500, 502, 503, 504) and tentativa < tentativas:
                ultimo = f"HTTP {e.code}: {texto}"
                log(f"  {e.code} em {caminho}; nova tentativa em {espera}s "
                    f"({tentativa}/{tentativas - 1})")
                time.sleep(espera)
                espera = min(espera * 2, 60)
                continue
            raise ErroApi(f"HTTP {e.code} em {caminho}: {texto}")
        except urllib.error.URLError as e:
            if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                from urllib.parse import urlparse
                raise ErroTLS(AJUDA_TLS.format(
                    host=urlparse(_base_url()).hostname or "cloud.tenable.com",
                    prog=os.path.basename(__file__)) + f"\nDetalhe: {e.reason}")
            if tentativa < tentativas:
                ultimo = str(e)
                log(f"  falha de rede em {caminho}; nova tentativa em {espera}s")
                time.sleep(espera)
                espera = min(espera * 2, 60)
                continue
            raise ErroApi(f"Falha de rede em {caminho}: {e}")
        except TimeoutError as e:
            if tentativa < tentativas:
                ultimo = str(e)
                log(f"  timeout em {caminho}; nova tentativa em {espera}s")
                time.sleep(espera)
                espera = min(espera * 2, 60)
                continue
            raise ErroApi(f"Timeout em {caminho}: {e}")
    raise ErroApi(f"Esgotadas as tentativas em {caminho}. Ultimo erro: {ultimo}")


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------------

def abrir_export(dias, severidades, estados, num_assets, tags):
    filtros = {"state": estados}
    if severidades:
        filtros["severity"] = severidades
    if dias:
        # `since` com state=FIXED devolve o que foi corrigido a partir da data;
        # com OPEN/REOPENED devolve o que foi visto a partir da data.
        # A spec proibe combinar `since` com first_found/last_found/last_fixed.
        filtros["since"] = int(time.time()) - dias * 86400
    for chave, valores in tags.items():
        filtros[f"tag.{chave}"] = valores

    corpo = {
        "num_assets": num_assets,
        "include_unlicensed": False,
        "include_plugin_output": False,  # reduz o volume drasticamente
        "filters": filtros,
    }
    log(f"Abrindo export com filtros: {json.dumps(filtros, ensure_ascii=False)}")
    resp = chamar("POST", "/vulns/export", corpo)

    if "_conflito" in resp:
        conflito = resp["_conflito"]
        uuid_ativo = conflito.get("active_job_id")
        motivo = conflito.get("failure_reason", "")
        if not uuid_ativo:
            raise ErroApi(f"409 sem active_job_id: {conflito}")
        log(f"Ja existe um export em andamento para esta chave ({motivo}).")
        log(f"Reaproveitando o job {uuid_ativo}. ATENCAO: os filtros dele podem")
        log("diferir dos que voce pediu; o resumo registra os filtros reais.")
        return uuid_ativo, filtros, True

    uuid = resp.get("export_uuid")
    if not uuid:
        raise ErroApi(f"Resposta sem export_uuid: {resp}")
    log(f"Job aberto: {uuid}")
    return uuid, filtros, False


def aguardar(uuid, timeout_min):
    """Baixa chunks conforme ficam prontos. Devolve (findings, status_final)."""
    limite = time.time() + timeout_min * 60
    baixados = set()
    findings = []
    status = {}
    intervalo = 5
    while True:
        status = chamar("GET", f"/vulns/export/{uuid}/status")
        estado = status.get("status", "?")
        disponiveis = [c for c in (status.get("chunks_available") or [])]
        for cid in disponiveis:
            if cid in baixados:
                continue
            log(f"  baixando chunk {cid}")
            bruto = chamar("GET", f"/vulns/export/{uuid}/chunks/{cid}", bruto=True)
            try:
                lote = json.loads(bruto)
            except json.JSONDecodeError as e:
                raise ErroApi(f"chunk {cid} nao e JSON valido: {e}")
            if isinstance(lote, list):
                findings.extend(lote)
            baixados.add(cid)

        falhos = status.get("chunks_failed") or []
        if falhos:
            log(f"  AVISO: chunks com falha: {falhos}. Reabra o export para recuperar.")

        if estado == "FINISHED":
            total = status.get("total_chunks")
            if total is None or len(baixados) >= len([c for c in disponiveis]):
                log(f"Export concluido. {len(baixados)} chunk(s), "
                    f"{len(findings)} finding(s).")
                return findings, status
        if estado == "ERROR":
            raise ErroApi(f"Export terminou em ERROR. Motivo: {status.get('reason')}")
        if estado == "CANCELLED":
            raise ErroApi("Export foi cancelado.")
        if time.time() > limite:
            log(f"Timeout de {timeout_min} min com status {estado}. "
                f"Baixados {len(findings)} finding(s) de chunks parciais.")
            log(f"Para retomar depois:  --retomar {uuid}")
            return findings, status

        log(f"  status {estado}; prontos {status.get('finished_chunks', 0)}"
            f"/{status.get('total_chunks', '?')}; aguardando {intervalo}s")
        time.sleep(intervalo)
        intervalo = min(intervalo + 5, 30)


# ----------------------------------------------------------------------------
# Normalizacao
# ----------------------------------------------------------------------------

def iso_para_epoch(valor):
    """Aceita ISO 8601 ou epoch (int/str). Devolve int epoch ou None."""
    if valor in (None, "", 0):
        return None
    if isinstance(valor, (int, float)):
        return int(valor)
    texto = str(valor).strip()
    if texto.isdigit():
        return int(texto)
    texto = texto.replace("Z", "+00:00")
    # trunca fracao de segundo com mais de 6 digitos
    if "." in texto:
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


def epoch_para_iso(epoch):
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def normalizar(f, agora):
    asset = f.get("asset") or {}
    plugin = f.get("plugin") or {}
    cves = plugin.get("cve") or []
    if isinstance(cves, str):
        cves = [cves]

    primeiro = iso_para_epoch(f.get("first_found"))
    ultimo = iso_para_epoch(f.get("last_found"))
    corrigido = iso_para_epoch(f.get("last_fixed"))
    nativo = f.get("time_taken_to_fix")

    dias = None
    fonte = ""
    if isinstance(nativo, (int, float)) and nativo > 0:
        dias = round(nativo / 86400.0, 2)
        fonte = "nativo"
    elif corrigido and primeiro and corrigido >= primeiro:
        dias = round((corrigido - primeiro) / 86400.0, 2)
        fonte = "derivado"

    idade_aberta = None
    estado = (f.get("state") or "").upper()
    if estado in ("OPEN", "REOPENED") and primeiro:
        idade_aberta = round((agora - primeiro) / 86400.0, 2)

    return {
        "finding_id": f.get("finding_id", ""),
        "asset_uuid": asset.get("uuid") or asset.get("id") or "",
        "asset_nome": asset.get("hostname") or asset.get("name")
                      or (asset.get("fqdn") or "")
                      or ((asset.get("ipv4") or [""])[0]
                          if isinstance(asset.get("ipv4"), list) else asset.get("ipv4") or ""),
        "plugin_id": plugin.get("id", ""),
        "plugin_nome": plugin.get("name", ""),
        "cve": ";".join(cves),
        "severidade": f.get("severity", ""),
        "severidade_modificada": f.get("severity_modification_type", ""),
        "vpr": (plugin.get("vpr") or {}).get("score", "")
               if isinstance(plugin.get("vpr"), dict) else "",
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


def comparar_filtros(pedidos, aplicados):
    """Compara filtros pedidos com os que o job realmente aplicou.

    A API NAO devolve o que foi enviado: ela normaliza (severidade volta em
    maiuscula e em outra ordem) e acrescenta todos os filtros de data com valor
    zero. Comparacao literal de dicionario acusaria divergencia em TODA execucao.
    Aqui a comparacao e semantica: so conta divergencia real."""
    if not isinstance(pedidos, dict) or not isinstance(aplicados, dict):
        return True, {"erro": "filtros ausentes ou em formato inesperado"}

    def norm(v):
        if isinstance(v, (list, tuple)):
            return {str(x).strip().lower() for x in v}
        if isinstance(v, str):
            return v.strip().lower()
        return v

    div = {}
    for k, pedido in pedidos.items():
        if k not in aplicados:
            div[k] = {"pedido": pedido, "aplicado": "<ausente>"}
            continue
        if norm(pedido) != norm(aplicados[k]):
            div[k] = {"pedido": pedido, "aplicado": aplicados[k]}
    # chaves que o job trouxe e nao foram pedidas: so contam se tiverem valor.
    # As de data vem sempre com 0 e sao default da API, nao filtro aplicado.
    for k, v in aplicados.items():
        if k in pedidos:
            continue
        if v in (0, "", None, [], {}, False):
            continue
        div[k] = {"pedido": "<nao pedido>", "aplicado": v}
    return bool(div), div


def detectar_lotes(linhas, corte=2):
    """Acha findings fechados em lote: mesmo ativo, mesma first_found, mesma
    last_fixed. Todos compartilham o MESMO dias_para_corrigir por construcao, e
    esse valor e o INTERVALO ENTRE DOIS SCANS, nao o tempo de acao da equipe.

    Um ativo escaneado em 09/06, nao escaneado de novo, e visto limpo em 02/09
    produz 85 dias para tudo que estava nele — inclusive o que foi corrigido no
    primeiro dia. Sem esta deteccao o relatorio confunde cadencia com MTTR.

    `corte` e o numero minimo de findings na mesma janela para o grupo contar
    como lote. Default 2: dois findings do mesmo ativo vistos fechados no mesmo
    scan ja compartilham um valor que nenhum dos dois mediu sozinho. O corte
    entra no resumo (`lote_minimo_por_janela`) porque muda o percentual: na
    coleta de referencia de 2026-09-03 o mesmo CSV deu 93,5% com corte 2, 74,2%
    com 3, 64,5% com 4 e 38,7% com 5 — e o limiar de alerta e 40%. Quem le o
    numero precisa saber com que corte ele foi feito."""
    grupos = {}
    for l in linhas:
        if l["estado"] != "FIXED" or not l["dias_para_corrigir"]:
            continue
        chave = (l["asset_nome"], l["first_found"], l["last_fixed"])
        grupos.setdefault(chave, []).append(l)

    total = sum(1 for l in linhas if l["estado"] == "FIXED" and l["dias_para_corrigir"])

    def _pct(c):
        n = sum(len(v) for v in grupos.values() if len(v) >= c)
        return round(n / total * 100, 1) if total else 0.0

    lotes = {k: v for k, v in grupos.items() if len(v) >= corte}
    em_lote = sum(len(v) for v in lotes.values())
    detalhe = sorted(
        ({"ativo": k[0], "first_found": k[1], "last_fixed": k[2],
          "findings": len(v), "dias_para_corrigir": float(v[0]["dias_para_corrigir"])}
         for k, v in lotes.items()),
        key=lambda d: -d["findings"])

    # Datas distintas que formam as janelas. Se um punhado de datas explica
    # todas as janelas, essas datas sao as datas de scan e o MTTR e o intervalo
    # entre elas — o consumidor do resumo checa isso contra o historico de scan.
    datas = set()
    for k in grupos:
        datas.add(str(k[1])[:10])
        datas.add(str(k[2])[:10])

    return {
        "findings_em_lote": em_lote,
        "findings_com_mttr": total,
        "pct_em_lote": round(em_lote / total * 100, 1) if total else 0.0,
        "lote_minimo_por_janela": corte,
        "sensibilidade_ao_corte": {str(c): _pct(c) for c in (2, 3, 4, 5)},
        "janelas_distintas": len(grupos),
        "datas_que_formam_as_janelas": sorted(datas),
        "lotes": detalhe,
    }


def percentil(ordenados, p):
    """Percentil INTERPOLADO: interpolacao linear entre as duas posicoes
    vizinhas (equivalente ao tipo 7 do R, ao default do numpy e ao
    PERCENTIL.INC do Excel). Com n pequeno a escolha muda o numero: na coleta
    de referencia de 2026-09-03, o p90 de critical com n=10 deu 101,43
    interpolado e 92,91 por posicao mais proxima — 9% de diferenca. O metodo
    vai declarado no resumo em `metodo_percentil`."""
    if not ordenados:
        return None
    if len(ordenados) == 1:
        return round(ordenados[0], 2)
    pos = (len(ordenados) - 1) * (p / 100.0)
    baixo = int(pos)
    alto = min(baixo + 1, len(ordenados) - 1)
    peso = pos - baixo
    return round(ordenados[baixo] * (1 - peso) + ordenados[alto] * peso, 2)


def resumir(linhas, filtros, uuid, status, corte_lote=2):
    por_sev = {}
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
            "mttr_dias_media": round(sum(ordenados) / len(ordenados), 2) if ordenados else None,
            "mttr_dias_p50": percentil(ordenados, 50),
            "mttr_dias_p90": percentil(ordenados, 90),
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
    lotes = detectar_lotes(linhas, corte_lote)
    return {
        "ferramenta": f"tenable_mttr_export.py {VERSAO}",
        "coletado_em_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base_url": _base_url(),
        "export_uuid": uuid,
        "filtros_pedidos": filtros,
        "filtros_aplicados_pelo_job": status.get("filters"),
        "filtros_divergiram": divergiu,
        "filtros_divergencias": divergencias,
        "nota_comparacao_filtros": ("A API normaliza os filtros e devolve todos os de data com "
                                    "valor 0. Use `filtros_divergiram`, que ja compara de forma "
                                    "semantica; comparar os dois dicionarios literalmente acusa "
                                    "divergencia em toda execucao."),
        "cadencia_de_scan": lotes,
        "metodo_percentil": ("interpolado — interpolacao linear entre as duas posicoes "
                             "vizinhas (tipo 7 do R, default do numpy, PERCENTIL.INC do "
                             "Excel). Com n pequeno o resultado difere do metodo por "
                             "posicao mais proxima; declare o metodo ao publicar o numero."),
        "estados_incluidos_no_mttr": ["FIXED"],
        "nota_estados": ("O MTTR e calculado SO sobre findings FIXED. Findings REOPENED "
                         "sao contados por severidade em `reabertos_no_recorte` e ficam "
                         "FORA da media: um finding reaberto nao foi corrigido. O campo "
                         "`mttr_dias_media_se_incluir_reabertos` existe para o leitor "
                         "medir o efeito da exclusao — na coleta de referencia de "
                         "2026-09-03 a media de high ia de 60,39 para 49,66 dias."),
        "nota_cadencia": ("`time_taken_to_fix` mede deteccao a deteccao, nao tempo de acao. "
                          "Findings do mesmo ativo com a mesma first_found e a mesma last_fixed "
                          "foram todos vistos corrigidos no MESMO scan: o valor deles e o "
                          "intervalo entre dois scans. Se `pct_em_lote` for alto, o MTTR e "
                          "LIMITE SUPERIOR determinado pela cadencia, e nao mede a equipe. "
                          "Leia junto `lote_minimo_por_janela` (o corte usado), "
                          "`sensibilidade_ao_corte` (o percentual com cortes 2 a 5) e "
                          "`datas_que_formam_as_janelas`: se poucas datas explicam todas as "
                          "janelas, essas datas sao as datas de scan e o MTTR e o intervalo "
                          "entre elas — confirme contra o historico de scan do tenant."),
        "status_final_do_job": status.get("status"),
        "total_chunks": status.get("total_chunks"),
        "chunks_com_falha": status.get("chunks_failed") or [],
        "registros_analisados": len(linhas),
        "endpoint": "POST /vulns/export (Tenable Vulnerability Management API)",
        "definicao_mttr": ("dias_para_corrigir = time_taken_to_fix/86400 quando a API "
                           "devolve o campo (mttr_fonte=nativo); senao "
                           "(last_fixed - first_found)/86400 (mttr_fonte=derivado). "
                           "Findings FIXED sem nenhuma das duas datas entram como "
                           "corrigidos_sem_data e NAO entram na media."),
        "mttr_por_severidade": saida,
    }


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

CAMPOS = ["finding_id", "asset_uuid", "asset_nome", "plugin_id", "plugin_nome", "cve",
          "severidade", "severidade_modificada", "vpr", "cvss3_base", "estado",
          "first_found", "last_found", "last_fixed", "resurfaced_date",
          "time_taken_to_fix_seg", "dias_para_corrigir", "mttr_fonte",
          "dias_em_aberto", "fonte_scan"]


def main():
    ap = argparse.ArgumentParser(
        description="Coleta MTTR real da Tenable VM via export de vulnerabilidades.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=180,
                    help="janela em dias (filtro `since`). 0 desativa o filtro. Padrao 180.")
    ap.add_argument("--severity", default="critical,high",
                    help="lista separada por virgula: info,low,medium,high,critical. "
                         "Vazio = todas. Padrao critical,high.")
    ap.add_argument("--state", default="FIXED",
                    help="OPEN, REOPENED, FIXED ou combinacao separada por virgula. "
                         "Padrao FIXED. Use FIXED,OPEN,REOPENED para MTTR e aging juntos.")
    ap.add_argument("--tag", action="append", default=[],
                    help="filtro de tag no formato Categoria=valor1,valor2. Repetivel.")
    ap.add_argument("--num-assets", type=int, default=500,
                    help="ativos por chunk. Padrao 500. Reduza se houver timeout.")
    ap.add_argument("--timeout-min", type=int, default=40,
                    help="minutos de espera pelo job. Padrao 40.")
    ap.add_argument("--retomar", default="",
                    help="UUID de um export ja aberto: pula o POST e so baixa.")
    ap.add_argument("--lote-minimo", type=int, default=2,
                    help="findings na mesma janela (ativo + first_found + last_fixed) "
                         "para o grupo contar como lote de cadencia. Padrao 2. O valor "
                         "usado e o percentual com cortes 2 a 5 vao no resumo.")
    ap.add_argument("--outdir", default=".", help="diretorio de saida. Padrao o atual.")
    ap.add_argument("--ca-bundle", default="",
                    help="caminho de um bundle PEM de CAs a usar na verificacao TLS. "
                         "Tambem pode vir de TIO_CA_BUNDLE.")
    ap.add_argument("--ca-macos-keychain", action="store_true",
                    help="usa os Keychains do macOS como fonte de confianca TLS. "
                         "Necessario quando a rede corporativa inspeciona TLS.")
    ap.add_argument("--diagnostico-tls", action="store_true",
                    help="descobre por que a verificacao de certificado falhou e sai. "
                         "Nao envia chave de API nem dado nenhum.")
    ap.add_argument("--autoteste", action="store_true",
                    help="roda a normalizacao contra um payload de exemplo, sem rede, "
                         "e sai. Serve para validar a instalacao.")
    args = ap.parse_args()

    if args.autoteste:
        return autoteste()

    if args.diagnostico_tls:
        return diagnostico_tls()

    severidades = [s.strip().lower() for s in args.severity.split(",") if s.strip()]
    for s in severidades:
        if s not in SEVERIDADES_VALIDAS:
            log(f"Severidade invalida: {s}. Validas: {', '.join(SEVERIDADES_VALIDAS)}")
            return 2
    estados = [e.strip().upper() for e in args.state.split(",") if e.strip()]
    for e in estados:
        if e not in ESTADOS_VALIDOS:
            log(f"Estado invalido: {e}. Validos: {', '.join(ESTADOS_VALIDOS)}")
            return 2

    tags = {}
    for t in args.tag:
        if "=" not in t:
            log(f"--tag precisa do formato Categoria=valor: {t}")
            return 2
        cat, vals = t.split("=", 1)
        tags[cat.strip()] = [v.strip() for v in vals.split(",") if v.strip()]

    try:
        configurar_tls(ca_bundle=args.ca_bundle,
                       usar_keychain=args.ca_macos_keychain)
        log(f"Confianca TLS: {_CTX['origem']}")
    except ErroTLS as e:
        log(f"\nERRO: {e}")
        return 1

    try:
        if args.retomar:
            uuid, filtros, reaproveitado = args.retomar, {"_retomado": True}, True
            log(f"Retomando export {uuid}")
        else:
            uuid, filtros, reaproveitado = abrir_export(
                args.days, severidades, estados, args.num_assets, tags)
        findings, status = aguardar(uuid, args.timeout_min)
    except ErroTLS as e:
        log(str(e))
        return 3
    except ErroApi as e:
        log(f"\nERRO: {e}")
        return 1

    agora = int(time.time())
    linhas = [normalizar(f, agora) for f in findings]

    if not linhas:
        log("\nNenhum finding no recorte pedido. Isto NAO e erro: pode significar que")
        log("nao houve correcao na janela, ou que os filtros ficaram estreitos demais.")
        log("Registre isso como lacuna no relatorio, nao preencha com estimativa.")

    os.makedirs(args.outdir, exist_ok=True)
    marca = datetime.now(timezone.utc).strftime("%Y%m%d")
    csv_path = os.path.join(args.outdir, f"tenable_mttr_findings_{marca}.csv")
    json_path = os.path.join(args.outdir, f"tenable_mttr_resumo_{marca}.json")

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CAMPOS)
        w.writeheader()
        for l in linhas:
            w.writerow(l)

    resumo = resumir(linhas, filtros, uuid, status, args.lote_minimo)
    if reaproveitado:
        resumo["aviso"] = ("Job de export reaproveitado ou retomado. Confira "
                           "filtros_aplicados_pelo_job antes de citar os numeros.")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(resumo, fh, indent=2, ensure_ascii=False)

    print()
    print(f"CSV:    {csv_path}   ({len(linhas)} linha(s))")
    print(f"Resumo: {json_path}")
    print()
    def _d(v):
        return "sem dado" if v is None else f"{v} d"
    for sev, m in resumo["mttr_por_severidade"].items():
        print(f"  {sev:9s} corrigidos com data: {m['corrigidos_com_data']:6d} | "
              f"p50 {_d(m['mttr_dias_p50'])} | p90 {_d(m['mttr_dias_p90'])} | "
              f"sem data: {m['corrigidos_sem_data']} | "
              f"abertos: {m['abertos_no_recorte']} (idade p50 "
              f"{_d(m['idade_dias_p50_abertos'])})")

    cad = resumo["cadencia_de_scan"]
    if cad["pct_em_lote"] > 0:
        print()
        print(f"  ATENCAO — CADENCIA DE SCAN: {cad['findings_em_lote']} de "
              f"{cad['findings_com_mttr']} findings ({cad['pct_em_lote']}%) foram vistos")
        print("  corrigidos no mesmo scan que os vizinhos do mesmo ativo. Para eles o")
        print("  numero e o INTERVALO ENTRE SCANS, nao o tempo que a equipe levou.")
        print(f"  Corte de lote usado: {cad['lote_minimo_por_janela']} finding(s) por janela. "
              f"Sensibilidade: " +
              ", ".join(f"corte {c}={v}%" for c, v in cad["sensibilidade_ao_corte"].items()))
        print(f"  Datas que formam as {cad['janelas_distintas']} janela(s): "
              + ", ".join(cad["datas_que_formam_as_janelas"]))
        if len(cad["datas_que_formam_as_janelas"]) <= 8 and cad["janelas_distintas"] >= 3:
            print("  Poucas datas explicam todas as janelas: confira o historico de scan.")
            print("  Se sao as datas de scan, o MTTR aqui e o intervalo entre scans.")
        for lote in cad["lotes"][:5]:
            print(f"    {lote['ativo']}: {lote['findings']} findings, todos com "
                  f"{lote['dias_para_corrigir']:.1f} d "
                  f"({lote['first_found']} -> {lote['last_fixed']})")
        if cad["pct_em_lote"] >= 40:
            print("  Com esse percentual, trate o MTTR como LIMITE SUPERIOR e nao o")
            print("  apresente como velocidade de remediacao da equipe.")

    if resumo.get("filtros_divergiram"):
        print()
        print("  ATENCAO — os filtros aplicados divergem dos pedidos:")
        for k, v in resumo["filtros_divergencias"].items():
            print(f"    {k}: pedido {v['pedido']!r}, aplicado {v['aplicado']!r}")
    return 0


def autoteste():
    exemplo = [
        {"finding_id": "f1", "state": "FIXED", "severity": "critical",
         "asset": {"uuid": "a1", "hostname": "srv-01"},
         "plugin": {"id": 12345, "name": "Exemplo", "cve": ["CVE-2024-0001"],
                    "vpr": {"score": 9.1}},
         "first_found": "2026-01-01T00:00:00Z", "last_found": "2026-02-01T00:00:00Z",
         "last_fixed": "2026-02-11T00:00:00Z", "time_taken_to_fix": 3628800},
        {"finding_id": "f2", "state": "FIXED", "severity": "critical",
         "asset": {"uuid": "a2", "hostname": "srv-02"},
         "plugin": {"id": 12345, "name": "Exemplo", "cve": ["CVE-2024-0001"]},
         "first_found": "2026-01-01T00:00:00Z", "last_fixed": "2026-01-21T00:00:00Z"},
        {"finding_id": "f3", "state": "FIXED", "severity": "high",
         "asset": {"uuid": "a3", "hostname": "srv-03"},
         "plugin": {"id": 999, "name": "Sem data"},
         "first_found": "2026-01-01T00:00:00Z"},
        {"finding_id": "f4", "state": "OPEN", "severity": "high",
         "asset": {"uuid": "a4", "ipv4": ["10.0.0.4"]},
         "plugin": {"id": 777, "name": "Aberto"},
         "first_found": "2026-06-01T00:00:00Z", "last_found": "2026-09-01T00:00:00Z"},
    ]
    agora = int(datetime(2026, 9, 3, tzinfo=timezone.utc).timestamp())
    linhas = [normalizar(f, agora) for f in exemplo]
    esperado = [
        ("f1", 42.0, "nativo"),   # 3628800 s = 42 d
        ("f2", 20.0, "derivado"), # 01-01 -> 01-21
        ("f3", "", ""),
        ("f4", "", ""),
    ]
    falhas = []
    for l, (fid, dias, fonte) in zip(linhas, esperado):
        if l["finding_id"] != fid:
            falhas.append(f"ordem trocada em {fid}")
        if l["dias_para_corrigir"] != dias:
            falhas.append(f"{fid}: dias_para_corrigir={l['dias_para_corrigir']} "
                          f"esperado {dias}")
        if l["mttr_fonte"] != fonte:
            falhas.append(f"{fid}: mttr_fonte={l['mttr_fonte']} esperado {fonte}")
    if linhas[3]["dias_em_aberto"] != 94.0:
        falhas.append(f"f4: dias_em_aberto={linhas[3]['dias_em_aberto']} esperado 94.0")
    if linhas[3]["asset_nome"] != "10.0.0.4":
        falhas.append(f"f4: asset_nome={linhas[3]['asset_nome']} esperado 10.0.0.4")

    r = resumir(linhas, {"_autoteste": True}, "uuid-de-teste", {"status": "FINISHED"})
    crit = r["mttr_por_severidade"]["critical"]
    if crit["mttr_dias_media"] != 31.0:
        falhas.append(f"critical media={crit['mttr_dias_media']} esperado 31.0")
    if crit["mttr_dias_p50"] != 31.0:
        falhas.append(f"critical p50={crit['mttr_dias_p50']} esperado 31.0")
    alta = r["mttr_por_severidade"]["high"]
    if alta["corrigidos_sem_data"] != 1:
        falhas.append(f"high sem_data={alta['corrigidos_sem_data']} esperado 1")
    if alta["idade_dias_p50_abertos"] != 94.0:
        falhas.append(f"high idade p50={alta['idade_dias_p50_abertos']} esperado 94.0")

    # --- declaracoes de metodo (1.1.0): o resumo tem de dizer COMO contou
    for campo in ("metodo_percentil", "estados_incluidos_no_mttr", "nota_estados"):
        if campo not in r:
            falhas.append(f"resumo sem o campo declarativo {campo}")
    if r.get("estados_incluidos_no_mttr") != ["FIXED"]:
        falhas.append("estados_incluidos_no_mttr deveria ser ['FIXED']")
    cad = r["cadencia_de_scan"]
    for campo in ("lote_minimo_por_janela", "sensibilidade_ao_corte",
                  "janelas_distintas", "datas_que_formam_as_janelas"):
        if campo not in cad:
            falhas.append(f"cadencia_de_scan sem o campo {campo}")
    if cad.get("lote_minimo_por_janela") != 2:
        falhas.append("corte de lote default deveria ser 2")

    # --- corte de lote: dois findings do mesmo ativo na mesma janela viram lote
    #     com corte 2 e nao viram com corte 3
    par = [
        {"finding_id": "g1", "state": "FIXED", "severity": "high",
         "asset": {"uuid": "b1", "hostname": "srv-lote"},
         "plugin": {"id": 1, "name": "A"},
         "first_found": "2026-01-01T00:00:00Z", "last_fixed": "2026-04-01T00:00:00Z"},
        {"finding_id": "g2", "state": "FIXED", "severity": "high",
         "asset": {"uuid": "b1", "hostname": "srv-lote"},
         "plugin": {"id": 2, "name": "B"},
         "first_found": "2026-01-01T00:00:00Z", "last_fixed": "2026-04-01T00:00:00Z"},
        {"finding_id": "g3", "state": "REOPENED", "severity": "high",
         "asset": {"uuid": "b2", "hostname": "srv-reab"},
         "plugin": {"id": 3, "name": "C"},
         "first_found": "2026-01-01T00:00:00Z", "last_found": "2026-09-01T00:00:00Z"},
    ]
    lp = [normalizar(f, agora) for f in par]
    c2 = detectar_lotes(lp, 2)
    c3 = detectar_lotes(lp, 3)
    if c2["pct_em_lote"] != 100.0:
        falhas.append(f"corte 2: pct_em_lote={c2['pct_em_lote']} esperado 100.0")
    if c3["pct_em_lote"] != 0.0:
        falhas.append(f"corte 3: pct_em_lote={c3['pct_em_lote']} esperado 0.0")
    if c2["sensibilidade_ao_corte"]["3"] != 0.0:
        falhas.append("sensibilidade ao corte 3 deveria ser 0.0")
    if c2["datas_que_formam_as_janelas"] != ["2026-01-01", "2026-04-01"]:
        falhas.append(f"datas das janelas={c2['datas_que_formam_as_janelas']}")

    # --- REOPENED contado por severidade e fora da media
    rp = resumir(lp, {"_autoteste": True}, "uuid-de-teste", {"status": "FINISHED"})
    alta2 = rp["mttr_por_severidade"]["high"]
    if alta2["reabertos_no_recorte"] != 1:
        falhas.append(f"high reabertos={alta2['reabertos_no_recorte']} esperado 1")
    if alta2["corrigidos_com_data"] != 2:
        falhas.append(f"high corrigidos={alta2['corrigidos_com_data']} esperado 2")

    if falhas:
        print("AUTOTESTE FALHOU:")
        for f in falhas:
            print("  -", f)
        return 1
    print("Autoteste OK. Normalizacao, fallback de MTTR, idade de abertos,")
    print("percentis, corte de lote, contagem de REOPENED e as declaracoes de")
    print("metodo no resumo conferem. O script esta pronto para rodar no tenant.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
