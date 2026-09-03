"""tenable-ctem-mcp - servidor MCP local (stdio) para o assessment de CTEM.

Aqui vive o ENVELOPE, porque todo indicador de todo estagio passa por ele e nao
existe lugar mais neutro para colocar. Contrato do CLAUDE.md, e nao se desvia:

    {"indicador": "M1", "valor": 21.0, "n": 12,
     "filtro_literal": "...", "coletado_em_utc": "...", "veredito_preflight": "ok"}

Consulta que falhou nao vira numero: vira `valor: null` com `lacuna: true` e
`causa` preenchida. Numero parcial silencioso e proibido - e a regra central do
projeto, porque numero errado com aparencia de certo nao tem sinal de que
aconteceu.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__version__ = "0.1.0"


def agora_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Indicador:
    """Envelope unico de retorno. Use `ok()` ou `lacuna()` para construir."""

    indicador: str
    valor: Any = None
    n: int | None = None
    filtro_literal: str = ""
    coletado_em_utc: str = field(default_factory=agora_utc)
    veredito_preflight: str = "nao_aplicavel"
    lacuna: bool = False
    causa: str | None = None
    contexto: dict[str, Any] | None = None

    @classmethod
    def ok(cls, indicador: str, valor: Any, n: int | None = None,
           filtro_literal: str = "", veredito_preflight: str = "ok",
           contexto: dict[str, Any] | None = None) -> "Indicador":
        return cls(indicador=indicador, valor=valor, n=n,
                   filtro_literal=filtro_literal,
                   veredito_preflight=veredito_preflight, contexto=contexto)

    @classmethod
    def lacuna_declarada(cls, indicador: str, causa: str,
                         filtro_literal: str = "",
                         veredito_preflight: str = "nao_aplicavel",
                         n: int | None = None) -> "Indicador":
        return cls(indicador=indicador, valor=None, n=n,
                   filtro_literal=filtro_literal,
                   veredito_preflight=veredito_preflight,
                   lacuna=True, causa=causa)

    def para_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "indicador": self.indicador,
            "valor": self.valor,
            "n": self.n,
            "filtro_literal": self.filtro_literal,
            "coletado_em_utc": self.coletado_em_utc,
            "veredito_preflight": self.veredito_preflight,
        }
        if self.lacuna:
            d["lacuna"] = True
            d["causa"] = self.causa
        if self.contexto:
            d["contexto"] = self.contexto
        return d


__all__ = ["Indicador", "agora_utc", "__version__"]
