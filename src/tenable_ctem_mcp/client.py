"""HTTP client for the Tenable API: auth, TLS, backoff, pagination, cache.

PORTED from _ferramentas/mttr-export/tenable_mttr_export.py 1.1.0 (lines 98-430).
It was not rewritten from scratch: the corporate TLS layer, the 401/403/409
handling and the backoff were already solved and field-tested.

Three additions the server requires and the collector did not have:
  1. honour the `retry-after` header on 429 - the Tenable limit is DYNAMIC,
     computed per minute according to platform load, and the response carries
     the number of seconds. Reading the header is the only way to respect the
     limit without inventing a number.  https://developer.tenable.com/docs/rate-limiting
  2. internal pagination, never exposed to the caller;
  3. in-memory per-process cache, short TTL, keyed by the literal filter.

Credentials: ONLY via TIO_ACCESS_KEY, TIO_SECRET_KEY, TIO_URL in the environment.
Never as a tool parameter, never in a log.
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

VERSION = "0.1.0"
UA = f"tenable-ctem-mcp/{VERSION} (community tooling, not supported by Tenable)"

# Short TTL for the in-memory cache. Short on purpose: the cache exists to avoid
# the SAME query four times within one collection, not to serve stale data.
DEFAULT_TTL_S = 300


# ----------------------------------------------------------------------------
# Errors - structured, never a silent partial number
# ----------------------------------------------------------------------------

class ApiError(Exception):
    """Failure talking to the API. Becomes a declared gap, with a cause."""

    def __init__(self, message: str, cause: str = "api_error"):
        super().__init__(message)
        self.cause = cause


class CredentialError(ApiError):
    """Key missing, invalid, or lacking permission."""


class TlsError(ApiError):
    """Certificate verification failure. NOT transient: do not retry."""


TLS_HELP = r"""Failed to verify the TLS certificate of {host}.

This is NOT a network problem and it does not improve by retrying. Python cannot
find the certificate chain. Two possible causes:

  A) Python installed from python.org without the certificates. Run once:
       /Applications/Python\ 3.12/Install\ Certificates.command

  B) The corporate network inspects TLS and presents a certificate signed by an
     internal CA, which is in the macOS Keychain but not in Python's bundle.
     This is the most common case on a customer network: it is their proxy, not
     the MCP. Point at the company bundle:
       export TIO_CA_BUNDLE=/path/to/ca.pem
     or let the server use the macOS Keychain:
       export TIO_CA_KEYCHAIN=1

There is no option to turn verification off, and there should not be: without
verification the tenant's API keys travel over a channel that may be being read
by a third party.

Detail: {detail}"""


def log(msg: str) -> None:
    """Logs go to stderr. Under stdio, stdout belongs to the MCP protocol."""
    print(msg, file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------
# Credentials and base URL  (ported: _chaves 102, _base_url 113)
# ----------------------------------------------------------------------------

def _keys() -> tuple[str, str]:
    # The .strip() is not cosmetic: a trailing space in the environment variable
    # is one of the two classic causes of a 401. See docs/troubleshooting.md.
    ak = os.environ.get("TIO_ACCESS_KEY", "").strip()
    sk = os.environ.get("TIO_SECRET_KEY", "").strip()
    if not ak or not sk:
        raise CredentialError(
            "TIO_ACCESS_KEY and TIO_SECRET_KEY are not set in the server's "
            "environment. The key is generated in the tenant under Settings > My "
            "Account > API Keys and is only accepted through an environment "
            "variable - never as a tool parameter.",
            cause="credential_missing",
        )
    return ak, sk


def base_url() -> str:
    return os.environ.get("TIO_URL", "https://cloud.tenable.com").rstrip("/")


# ----------------------------------------------------------------------------
# TLS  (ported: ErroTLS/AJUDA_TLS/estado_store_padrao/_pem_do_keychain/
#       configurar_tls/contexto, lines 117-248)
# ----------------------------------------------------------------------------

_CTX: dict[str, Any] = {"ctx": None, "origin": ""}


def default_store_state() -> tuple[bool, str]:
    """Says whether this Python actually has a usable set of CAs.
    Telling 'store absent' from 'store present but does not trust this chain'
    is what separates cause A from cause B."""
    try:
        import certifi
        return True, f"certifi at {certifi.where()}"
    except ImportError:
        pass
    vp = ssl.get_default_verify_paths()
    for attr in ("cafile", "openssl_cafile"):
        c = getattr(vp, attr, None)
        if c and os.path.exists(c) and os.path.getsize(c) > 0:
            return True, f"{attr}={c}"
    for attr in ("capath", "openssl_capath"):
        d = getattr(vp, attr, None)
        if d and os.path.isdir(d):
            try:
                if any(os.scandir(d)):
                    return True, f"{attr}={d}"
            except OSError:
                pass
    return False, ("no CA file found - certifi not installed and "
                   f"openssl_cafile ({vp.openssl_cafile}) does not exist")


def _pem_from_keychain() -> str:
    """Builds a PEM bundle from the macOS Keychains (includes corporate CAs
    installed by MDM). Uses the `security` binary, present on every macOS."""
    import subprocess
    import tempfile
    keychains = ["/System/Library/Keychains/SystemRootCertificates.keychain",
                 "/Library/Keychains/System.keychain"]
    pieces = []
    for k in keychains:
        if not os.path.exists(k):
            continue
        try:
            out = subprocess.run(["security", "find-certificate", "-a", "-p", k],
                                 capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            raise TlsError(f"Could not read the Keychain {k}: {e}", cause="tls")
        if out.returncode == 0 and "BEGIN CERTIFICATE" in out.stdout:
            pieces.append(out.stdout)
    if not pieces:
        raise TlsError("No certificate found in the macOS Keychains. "
                       "TIO_CA_KEYCHAIN only works on macOS.", cause="tls")
    fh = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8")
    fh.write("\n".join(pieces))
    fh.close()
    n = "\n".join(pieces).count("BEGIN CERTIFICATE")
    log(f"  {n} certificates read from the macOS Keychain")
    return fh.name


def configure_tls() -> None:
    """Builds the SSL context exactly once. Verification is NEVER turned off.

    The server does not offer, and must not offer, an option to disable
    certificate verification. That is a project rule, not a preference.
    """
    if os.environ.get("TIO_CA_KEYCHAIN", "").strip() in ("1", "true", "True"):
        path = _pem_from_keychain()
        _CTX["ctx"] = ssl.create_default_context(cafile=path)
        _CTX["origin"] = f"macOS Keychain ({path})"
        return

    path = os.environ.get("TIO_CA_BUNDLE", "").strip()
    if path:
        if not os.path.exists(path):
            raise TlsError(f"CA bundle not found: {path}", cause="tls")
        _CTX["ctx"] = ssl.create_default_context(cafile=path)
        _CTX["origin"] = f"bundle given in TIO_CA_BUNDLE ({path})"
        return

    has_store, detail = default_store_state()
    if not has_store and sys.platform == "darwin":
        # This Python has no CAs of its own. Rather than fail, fall back to the
        # macOS Keychain - the same trust root Safari uses and the user already
        # administers. Verification stays ON; only the source of the CAs changes.
        log(f"WARNING: this Python has no CA store of its own ({detail}).")
        log("         Using the macOS Keychain. Verification remains active.")
        try:
            path = _pem_from_keychain()
            _CTX["ctx"] = ssl.create_default_context(cafile=path)
            _CTX["origin"] = f"macOS Keychain, for lack of an own store ({path})"
            return
        except TlsError as e:
            log(f"         Could not use the Keychain: {e}")

    _CTX["ctx"] = ssl.create_default_context()
    _CTX["origin"] = f"Python default ({detail})"


def context() -> ssl.SSLContext:
    if _CTX["ctx"] is None:
        configure_tls()
    return _CTX["ctx"]


def tls_origin() -> str:
    context()
    return _CTX["origin"]


# ----------------------------------------------------------------------------
# HTTP call  (ported: chamar 361)
# ----------------------------------------------------------------------------

def _wait_from_header(headers, default: int) -> int:
    """Reads `retry-after`. The Tenable limit is dynamic: the platform computes
    how many requests it accepts per minute according to load, and says in the
    header how many seconds to wait. There is no fixed number to hard-code."""
    raw = headers.get("retry-after") if headers else None
    if raw:
        try:
            return max(1, min(int(float(raw)), 300))
        except (TypeError, ValueError):
            pass
    return default


def call(method: str, path: str, body: Any = None,
         params: dict[str, Any] | None = None,
         attempts: int = 5, raw: bool = False) -> Any:
    """Calls the API retrying on 429 and 5xx. Returns dict/list, or bytes if raw.

    A 409 is handed back to the caller in {"_conflict": ...} instead of raising:
    that is how mttr_collect resumes an export already open rather than asking
    for another one.
    """
    ak, sk = _keys()
    url = base_url() + path
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url += "?" + urllib.parse.urlencode(clean, doseq=True)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    wait = 3
    last = None

    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("X-ApiKeys", f"accessKey={ak};secretKey={sk}")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", UA)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=180, context=context()) as r:
                content = r.read()
                if raw:
                    return content
                return json.loads(content) if content else {}

        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")[:500]
            if e.code == 409:
                # export job already running: hand back for the caller to handle
                try:
                    return {"_conflict": json.loads(text)}
                except (ValueError, TypeError):
                    raise ApiError(f"409 on {path}: {text}", cause="conflict")
            if e.code == 401:
                raise CredentialError(
                    "401 unauthorized. Check TIO_ACCESS_KEY and TIO_SECRET_KEY - "
                    "the two classic causes are a key from another container and "
                    "a trailing space in the environment variable.",
                    cause="credential_invalid")
            if e.code == 403:
                raise CredentialError(
                    "403 forbidden. The key needs the Basic [16] role or the "
                    f"VM.VM_EXPLORE privilege. Response: {text}",
                    cause="no_permission")
            if e.code in (429, 500, 502, 503, 504) and attempt < attempts:
                last = f"HTTP {e.code}: {text}"
                pause = _wait_from_header(getattr(e, "headers", None), wait)
                log(f"  {e.code} on {path}; retrying in {pause}s "
                    f"({attempt}/{attempts - 1})")
                time.sleep(pause)
                wait = min(wait * 2, 60)
                continue
            raise ApiError(f"HTTP {e.code} on {path}: {text}", cause=f"http_{e.code}")

        except urllib.error.URLError as e:
            if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                host = urllib.parse.urlparse(base_url()).hostname or "cloud.tenable.com"
                raise TlsError(
                    TLS_HELP.format(host=host, detail=e.reason),
                    cause="tls_corporate_proxy")
            if attempt < attempts:
                last = str(e)
                log(f"  network failure on {path}; retrying in {wait}s")
                time.sleep(wait)
                wait = min(wait * 2, 60)
                continue
            raise ApiError(f"Network failure on {path}: {e}", cause="network")

        except TimeoutError as e:
            if attempt < attempts:
                last = str(e)
                log(f"  timeout on {path}; retrying in {wait}s")
                time.sleep(wait)
                wait = min(wait * 2, 60)
                continue
            raise ApiError(f"Timeout on {path}: {e}", cause="timeout")

    raise ApiError(f"Attempts exhausted on {path}. Last error: {last}",
                   cause="attempts_exhausted")


# ----------------------------------------------------------------------------
# Pagination - internal, invisible to the caller.
# No tool exposes offset. Decision closed in CLAUDE.md.
# ----------------------------------------------------------------------------

def paginate(method: str, path: str, body: dict | None = None,
             params: dict | None = None, field: str = "data",
             page_size: int = 200, ceiling: int = 100_000) -> list[dict]:
    """Walks every page and returns the complete list of items."""
    items: list[dict] = []
    offset = 0
    while len(items) < ceiling:
        if method.upper() == "GET":
            p = dict(params or {}, limit=page_size, offset=offset)
            resp = call("GET", path, params=p)
        else:
            c = dict(body or {})
            c.update({"limit": page_size, "offset": offset})
            resp = call(method, path, body=c, params=params)

        batch = _extract_list(resp, field)
        if not batch:
            break
        items.extend(batch)
        if len(batch) < page_size:
            break
        offset += page_size
    return items


def _extract_list(resp: Any, field: str) -> list[dict]:
    if isinstance(resp, list):
        return resp
    if not isinstance(resp, dict):
        return []
    for key in (field, "data", "items", "results", "values"):
        v = resp.get(key)
        if isinstance(v, list):
            return v
        if isinstance(v, dict):
            for k2 in ("items", "results", "values", "assets", "findings"):
                if isinstance(v.get(k2), list):
                    return v[k2]
    return []


def total_of(resp: Any) -> int | None:
    """Reads only the total field. That is what preflight needs: a query with
    limit=1 where only the total matters."""
    if not isinstance(resp, dict):
        return None
    for key in ("total", "total_count", "totalCount", "count"):
        if isinstance(resp.get(key), int):
            return resp[key]
    for parent in ("pagination", "meta", "data"):
        sub = resp.get(parent)
        if isinstance(sub, dict):
            t = total_of(sub)
            if t is not None:
                return t
    return None


# ----------------------------------------------------------------------------
# In-memory cache, per process, short TTL, keyed by literal filter.
# Mandatory in ctem_discover_tenant and plugin_census (CLAUDE.md).
# ----------------------------------------------------------------------------

class Cache:
    def __init__(self, ttl_s: int = DEFAULT_TTL_S):
        self.ttl_s = ttl_s
        self._items: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> tuple[bool, Any]:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return False, None
            written_at, value = item
            if time.monotonic() - written_at > self.ttl_s:
                del self._items[key]
                return False, None
            return True, value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._items[key] = (time.monotonic(), value)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


CACHE = Cache()
