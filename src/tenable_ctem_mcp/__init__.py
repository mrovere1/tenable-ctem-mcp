"""tenable-ctem-mcp - local MCP server (stdio) for the CTEM assessment.

The ENVELOPE lives here, because every indicator of every stage goes through it
and there is no more neutral place to put it. Contract from CLAUDE.md, and it is
not deviated from:

    {"indicator": "M1", "value": 21.0, "n": 12,
     "literal_filter": "...", "collected_at_utc": "...", "preflight_verdict": "ok"}

A query that failed does not become a number: it becomes `value: null` with
`gap: true` and `cause` filled in. A silent partial number is forbidden - that is
the central rule of the project, because a wrong number that looks right carries
no signal that it happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__version__ = "0.1.0"


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Indicator:
    """Single return envelope. Build with `ok()` or `declared_gap()`."""

    indicator: str
    value: Any = None
    n: int | None = None
    literal_filter: str = ""
    collected_at_utc: str = field(default_factory=now_utc)
    preflight_verdict: str = "not_applicable"
    gap: bool = False
    cause: str | None = None
    context: dict[str, Any] | None = None

    @classmethod
    def ok(cls, indicator: str, value: Any, n: int | None = None,
           literal_filter: str = "", preflight_verdict: str = "ok",
           context: dict[str, Any] | None = None) -> "Indicator":
        return cls(indicator=indicator, value=value, n=n,
                   literal_filter=literal_filter,
                   preflight_verdict=preflight_verdict, context=context)

    @classmethod
    def declared_gap(cls, indicator: str, cause: str,
                     literal_filter: str = "",
                     preflight_verdict: str = "not_applicable",
                     n: int | None = None) -> "Indicator":
        return cls(indicator=indicator, value=None, n=n,
                   literal_filter=literal_filter,
                   preflight_verdict=preflight_verdict,
                   gap=True, cause=cause)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "indicator": self.indicator,
            "value": self.value,
            "n": self.n,
            "literal_filter": self.literal_filter,
            "collected_at_utc": self.collected_at_utc,
            "preflight_verdict": self.preflight_verdict,
        }
        if self.gap:
            d["gap"] = True
            d["cause"] = self.cause
        if self.context:
            d["context"] = self.context
        return d


__all__ = ["Indicator", "now_utc", "__version__"]
