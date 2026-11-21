"""Shared data structures used by every analyzer and the scoring engine."""
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class ParsedURL:
    """A safely parsed URL. Nothing here ever touches the network."""
    raw: str
    normalized: str
    scheme: str
    host: str                 # lower-cased hostname, no port / userinfo
    port: Optional[int]
    path: str
    query: str
    userinfo: str             # text before '@' in the authority, if any
    subdomain: str            # e.g. "login.secure"
    domain: str               # e.g. "g00gle-login"
    suffix: str               # e.g. "com" / "co.in"
    is_ip: bool

    @property
    def registered_domain(self) -> str:
        return f"{self.domain}.{self.suffix}" if self.suffix else self.domain

    @property
    def subdomain_labels(self) -> List[str]:
        return [s for s in self.subdomain.split(".") if s]


@dataclass
class Finding:
    """One explainable red flag. `points` feeds the risk-scoring engine."""
    module: str               # "heuristics" | "typosquat" | "domain" | "ssl"
    check: str                # machine-friendly id, e.g. "ip_address"
    title: str                # short human title
    detail: str               # plain-English explanation for the report
    points: int               # contribution to the 0-100 risk score
    severity: str = "medium"  # "low" | "medium" | "high"

    def to_dict(self) -> dict:
        return asdict(self)
