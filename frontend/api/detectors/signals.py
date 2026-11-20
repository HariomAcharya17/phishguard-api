"""A Signal is one piece of evidence about a URL, with a weight in [0, 1]."""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class Signal:
    id: str          # stable machine id, e.g. "brand_in_subdomain"
    layer: str       # "reputation" | "url" | "domain" | "ml"
    title: str       # short human-readable label
    detail: str      # one sentence explaining what was found
    weight: float    # contribution to risk, 0..1 (0 = informational)
    confirmed: bool = False  # a reputation feed lists this URL as malicious

    @property
    def severity(self) -> str:
        if self.confirmed or self.weight >= 0.7:
            return "critical"
        if self.weight >= 0.45:
            return "high"
        if self.weight >= 0.2:
            return "medium"
        if self.weight > 0:
            return "low"
        return "info"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["weight"] = round(self.weight, 3)
        d["severity"] = self.severity
        return d


def combine(weights: list[float]) -> float:
    """
    Noisy-OR: treat each signal as independent evidence. Two medium signals
    add up to more than either alone, but the result never exceeds 1 and a
    pile of weak signals cannot outweigh one strong one by simple addition.
    """
    p_clean = 1.0
    for w in weights:
        p_clean *= 1.0 - max(0.0, min(w, 1.0))
    return 1.0 - p_clean
