"""Cliente HTTP para a API Tenable: auth, TLS, backoff, paginacao, cache.

PORTADO de _ferramentas/mttr-export/tenable_mttr_export.py 1.1.0 (linhas 98-430).
Nao foi reescrito do zero: a camada de TLS corporativo, o tratamento de 401/403/409
e o backoff ja estavam resolvidos e testados em campo.

Tres acrescimos que o servidor exige e o coletor nao tinha:
  1. honrar o header `retry-after` no 429 - o limite da Tenable e DINAMICO,
     calculado por minuto conforme a carga da plataforma, e a resposta traz o
     numero de segundos. Ler o header e o unico jeito de respeitar o limite sem
     inventar numero.  https://developer.tenable.com/docs/rate-limiting
  2. paginacao interna, nunca exposta ao chamador;
  3. cache em memoria por processo, TTL curto, chaveado pelo filtro literal.

Credencial: SOMENTE via TIO_ACCESS_KEY, TIO_SECRET_KEY, TIO_URL no ambiente.
Nunca como parametro de tool, nunca em log.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

VERSAO = "0.1.0"
UA = f"tenable-ctem-mcp/{VERSAO} (community tooling, nao suportado pela Tenable)"

# TTL curto do cache em memoria. Curto de proposito: o cache existe para evitar
# a MESMA consulta quatro vezes dentro de uma coleta, nao para servir dado velho.
TTL_PADRAO_S = 300


# ----------------------------------------------------------------------------
# Erros - estruturados, nunca numero parcial silencioso
# ----------------------------------------------------------------------------

class ErroApi(Exception):
    """Falha na conversa com a API. Vira lacuna declarada, com causa."""

    def __init__(self, mensagem: str, causa: str = "erro_api"):
        super().__init__(mensagem)
        self.causa = causa


class ErroCredencial(ErroApi):
    """Chave ausente, invalida ou sem permissao."""


class ErroTLS(ErroApi):
    """Falha de verificacao de certificado. NAO e transitorio: nao tentar de novo."""


AJUDA_TLS = r"""Falha ao verificar o certificado TLS de {host}.

Isto NAO e problema de rede e nao melhora tentando de novo. O Python nao esta
achando a cadeia de certificados. Duas causas possiveis:

  A) Python instalado do python.org sem os certificados. Rode uma vez:
       /Applications/Python\ 3.12/Install\ Certificates.command

  B) A rede corporativa inspeciona TLS e apresenta um certificado assinado por
     uma CA interna, que esta no Keychain do macOS mas nao no bundle do Python.
     Este e o caso mais comum em rede de cliente: e o proxy dele, nao o MCP.
     Aponte o bundle da empresa:
       export TIO_CA_BUNDLE=/caminho/para/ca.pem
     ou deixe o servidor usar o Keychain do macOS:
       export TIO_CA_KEYCHAIN=1

Nao existe opcao para desligar a verificacao, e nao deve existir: sem
verificacao as chaves de API do tenant seguem por um canal que pode estar
sendo lido por terceiro.

Detalhe: {detalhe}"""


def log(msg: str) -> None:
    """Log vai para stderr. Em stdio, stdout e do protocolo MCP."""
    print(msg, file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------
# Credenciais e base URL  (portado: _chaves 102, _base_url 113)
# ----------------------------------------------------------------------------

def _chaves() -> tuple[str, str]:
    # O .strip() nao e cosmetico: espaco no fim da variavel de ambiente e uma
    # das duas causas classicas de 401. Ver docs/troubleshooting.md.
    ak = os.environ.get("TIO_ACCESS_KEY", "").strip()
    sk = os.environ.get("TIO_SECRET_KEY", "").strip()
    if not ak or not sk:
        raise ErroCredencial(
            "TIO_ACCESS_KEY e TIO_SECRET_KEY nao estao definidas no ambiente do "
            "servidor. A chave e gerada no tenant em Settings > My Account > API Keys "
            "e so entra por variavel de ambiente - nunca como parametro de tool.",
            causa="credencial_ausente",
        )
    return ak, sk


def base_url() -> str:
    return os.environ.get("TIO_URL", "https://cloud.tenable.com").rstrip("/")


# ----------------------------------------------------------------------------
# TLS  (portado: ErroTLS/AJUDA_TLS/estado_store_padrao/_pem_do_keychain/
#       configurar_tls/contexto, linhas 117-248)
# ----------------------------------------------------------------------------

_CTX: dict[str, Any] = {"ctx": None, "origem": ""}


def estado_store_padrao() -> tuple[bool, str]:
    """Diz se este Python tem, de fato, um conjunto de CAs utilizavel.
    Distinguir 'store ausente' de 'store presente mas nao confia nesta cadeia'
    e o que separa a causa A da causa B."""
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
    return False, ("nenhum arquivo de CAs encontrado - certifi nao instalado e "
                   f"openssl_cafile ({vp.openssl_cafile}) nao existe")


def _pem_do_keychain() -> str:
    """Monta um bundle PEM a partir dos Keychains do macOS (inclui CAs corporativas
    instaladas por MDM). Usa o binario `security`, presente em todo macOS."""
    import subprocess
    import tempfile
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
            raise ErroTLS(f"Nao consegui ler o Keychain {k}: {e}", causa="tls")
        if out.returncode == 0 and "BEGIN CERTIFICATE" in out.stdout:
            pedacos.append(out.stdout)
    if not pedacos:
        raise ErroTLS("Nenhum certificado encontrado nos Keychains do macOS. "
                      "TIO_CA_KEYCHAIN so funciona em macOS.", causa="tls")
    fh = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8")
    fh.write("\n".join(pedacos))
    fh.close()
    n = "\n".join(pedacos).count("BEGIN CERTIFICATE")
    log(f"  {n} certificados lidos do Keychain do macOS")
    return fh.name


def configurar_tls() -> None:
    """Monta o contexto SSL uma unica vez. A verificacao NUNCA e desligada.

    O servidor nao oferece, e nao deve oferecer, opcao de desabilitar a
    verificacao de certificado. E regra do projeto, nao preferencia.
    """
    if os.environ.get("TIO_CA_KEYCHAIN", "").strip() in ("1", "true", "True"):
        caminho = _pem_do_keychain()
        _CTX["ctx"] = ssl.create_default_context(cafile=caminho)
        _CTX["origem"] = f"Keychain do macOS ({caminho})"
        return

    caminho = os.environ.get("TIO_CA_BUNDLE", "").strip()
    if caminho:
        if not os.path.exists(caminho):
            raise ErroTLS(f"Bundle de CA nao encontrado: {caminho}", causa="tls")
        _CTX["ctx"] = ssl.create_default_context(cafile=caminho)
        _CTX["origem"] = f"bundle informado em TIO_CA_BUNDLE ({caminho})"
        return

    tem, detalhe = estado_store_padrao()
    if not tem and sys.platform == "darwin":
        # Este Python nao tem CAs proprias. Em vez de falhar, cair no Keychain do
        # macOS - a mesma raiz de confianca que o Safari usa e que o proprio
        # usuario administra. A verificacao segue LIGADA; so muda a fonte das CAs.
        log(f"AVISO: este Python nao tem conjunto de CAs proprio ({detalhe}).")
        log("       Usando o Keychain do macOS. A verificacao continua ativa.")
        try:
            caminho = _pem_do_keychain()
            _CTX["ctx"] = ssl.create_default_context(cafile=caminho)
            _CTX["origem"] = f"Keychain do macOS, por ausencia de store proprio ({caminho})"
            return
        except ErroTLS as e:
            log(f"       Nao consegui usar o Keychain: {e}")

    _CTX["ctx"] = ssl.create_default_context()
    _CTX["origem"] = f"padrao do Python ({detalhe})"


def contexto() -> ssl.SSLContext:
    if _CTX["ctx"] is None:
        configurar_tls()
    return _CTX["ctx"]


def origem_tls() -> str:
    contexto()
    return _CTX["origem"]


# ----------------------------------------------------------------------------
# Chamada HTTP  (portado: chamar 361)
# ----------------------------------------------------------------------------

def _espera_do_header(headers, padrao: int) -> int:
    """Le `retry-after`. O limite da Tenable e dinamico: a plataforma calcula
    quantas requisicoes aceita por minuto conforme a carga, e diz no header
    quantos segundos esperar. Nao ha numero fixo para fixar aqui."""
    bruto = headers.get("retry-after") if headers else None
    if bruto:
        try:
            return max(1, min(int(float(bruto)), 300))
        except (TypeError, ValueError):
            pass
    return padrao


def chamar(metodo: str, caminho: str, corpo: Any = None,
           params: dict[str, Any] | None = None,
           tentativas: int = 5, bruto: bool = False) -> Any:
    """Chama a API com retry em 429 e 5xx. Devolve dict/list, ou bytes se bruto.

    O 409 e devolvido ao chamador em {"_conflito": ...} em vez de virar excecao:
    e assim que mttr_collect retoma um export ja aberto em vez de pedir outro.
    """
    ak, sk = _chaves()
    url = base_url() + caminho
    if params:
        limpos = {k: v for k, v in params.items() if v is not None}
        if limpos:
            url += "?" + urllib.parse.urlencode(limpos, doseq=True)
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
                except (ValueError, TypeError):
                    raise ErroApi(f"409 em {caminho}: {texto}", causa="conflito")
            if e.code == 401:
                raise ErroCredencial(
                    "401 nao autorizado. Confira TIO_ACCESS_KEY e TIO_SECRET_KEY - "
                    "as duas causas classicas sao chave de outro container e espaco "
                    "no fim da variavel de ambiente.",
                    causa="credencial_invalida")
            if e.code == 403:
                raise ErroCredencial(
                    "403 sem permissao. A chave precisa do papel Basic [16] ou do "
                    f"privilegio VM.VM_EXPLORE. Resposta: {texto}",
                    causa="sem_permissao")
            if e.code in (429, 500, 502, 503, 504) and tentativa < tentativas:
                ultimo = f"HTTP {e.code}: {texto}"
                pausa = _espera_do_header(getattr(e, "headers", None), espera)
                log(f"  {e.code} em {caminho}; nova tentativa em {pausa}s "
                    f"({tentativa}/{tentativas - 1})")
                time.sleep(pausa)
                espera = min(espera * 2, 60)
                continue
            raise ErroApi(f"HTTP {e.code} em {caminho}: {texto}", causa=f"http_{e.code}")

        except urllib.error.URLError as e:
            if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                host = urllib.parse.urlparse(base_url()).hostname or "cloud.tenable.com"
                raise ErroTLS(
                    AJUDA_TLS.format(host=host, detalhe=e.reason),
                    causa="tls_proxy_corporativo")
            if tentativa < tentativas:
                ultimo = str(e)
                log(f"  falha de rede em {caminho}; nova tentativa em {espera}s")
                time.sleep(espera)
                espera = min(espera * 2, 60)
                continue
            raise ErroApi(f"Falha de rede em {caminho}: {e}", causa="rede")

        except TimeoutError as e:
            if tentativa < tentativas:
                ultimo = str(e)
                log(f"  timeout em {caminho}; nova tentativa em {espera}s")
                time.sleep(espera)
                espera = min(espera * 2, 60)
                continue
            raise ErroApi(f"Timeout em {caminho}: {e}", causa="timeout")

    raise ErroApi(f"Esgotadas as tentativas em {caminho}. Ultimo erro: {ultimo}",
                  causa="tentativas_esgotadas")


# ----------------------------------------------------------------------------
# Paginacao - interna, invisivel para o chamador.
# Nenhum tool expoe offset. Decisao fechada no CLAUDE.md.
# ----------------------------------------------------------------------------

def paginar(metodo: str, caminho: str, corpo: dict | None = None,
            params: dict | None = None, campo: str = "data",
            limite_pagina: int = 200, teto: int = 100_000) -> list[dict]:
    """Percorre todas as paginas e devolve a lista completa de itens."""
    itens: list[dict] = []
    offset = 0
    while len(itens) < teto:
        if metodo.upper() == "GET":
            p = dict(params or {}, limit=limite_pagina, offset=offset)
            resp = chamar("GET", caminho, params=p)
        else:
            c = dict(corpo or {})
            c.update({"limit": limite_pagina, "offset": offset})
            resp = chamar(metodo, caminho, corpo=c, params=params)

        lote = _extrair_lista(resp, campo)
        if not lote:
            break
        itens.extend(lote)
        if len(lote) < limite_pagina:
            break
        offset += limite_pagina
    return itens


def _extrair_lista(resp: Any, campo: str) -> list[dict]:
    if isinstance(resp, list):
        return resp
    if not isinstance(resp, dict):
        return []
    for chave in (campo, "data", "items", "results", "values"):
        v = resp.get(chave)
        if isinstance(v, list):
            return v
        if isinstance(v, dict):
            for k2 in ("items", "results", "values", "assets", "findings"):
                if isinstance(v.get(k2), list):
                    return v[k2]
    return []


def total_de(resp: Any) -> int | None:
    """Le so o campo de total. E o que o pre-voo precisa: uma consulta com
    limit=1 onde so o total importa."""
    if not isinstance(resp, dict):
        return None
    for chave in ("total", "total_count", "totalCount", "count"):
        if isinstance(resp.get(chave), int):
            return resp[chave]
    for pai in ("pagination", "meta", "data"):
        sub = resp.get(pai)
        if isinstance(sub, dict):
            t = total_de(sub)
            if t is not None:
                return t
    return None


# ----------------------------------------------------------------------------
# Cache em memoria, por processo, TTL curto, chaveado por filtro literal.
# Obrigatorio em ctem_discover_tenant e plugin_census (CLAUDE.md).
# ----------------------------------------------------------------------------

class Cache:
    def __init__(self, ttl_s: int = TTL_PADRAO_S):
        self.ttl_s = ttl_s
        self._itens: dict[str, tuple[float, Any]] = {}
        self._trava = threading.Lock()

    def get(self, chave: str) -> tuple[bool, Any]:
        with self._trava:
            item = self._itens.get(chave)
            if item is None:
                return False, None
            gravado_em, valor = item
            if time.monotonic() - gravado_em > self.ttl_s:
                del self._itens[chave]
                return False, None
            return True, valor

    def set(self, chave: str, valor: Any) -> None:
        with self._trava:
            self._itens[chave] = (time.monotonic(), valor)

    def limpar(self) -> None:
        with self._trava:
            self._itens.clear()


CACHE = Cache()
