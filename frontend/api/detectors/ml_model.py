"""
Domain classifier: gradient-boosted trees over hostname features.

The model is stored as plain JSON (see ml/train_domain_model.py) and scored
in pure Python, so the API needs no scikit-learn, pandas or numpy at runtime
and is immune to pickle version mismatches.
"""
from __future__ import annotations

import json
import math
import os

from .features import FEATURE_NAMES, host_features
from .signals import Signal
from .urlparts import ParsedURL

_MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "model", "domain_model.json")

try:
    with open(_MODEL_PATH, encoding="utf-8") as f:
        _MODEL = json.load(f)
    if _MODEL.get("features") != FEATURE_NAMES:
        raise ValueError("feature list in model file does not match features.py")
    MODEL_LOADED = True
except Exception as e:  # pragma: no cover - logged, API keeps working without ML
    _MODEL = None
    MODEL_LOADED = False
    print(f"[ml_model] model not loaded: {e}")


def _tree_value(tree: dict, x: list[float]) -> float:
    left, right, feat, thr, val = tree["l"], tree["r"], tree["f"], tree["t"], tree["v"]
    node = 0
    while left[node] != -1:
        node = left[node] if x[feat[node]] <= thr[node] else right[node]
    return val[node]


def probability(p: ParsedURL) -> float | None:
    """Probability that the hostname belongs to a phishing site, or None."""
    if not MODEL_LOADED or not p.host:
        return None
    x = host_features(p.host, p.domain, p.suffix, p.subdomain, p.is_ip)
    raw = _MODEL["init"] + _MODEL["learning_rate"] * sum(_tree_value(t, x) for t in _MODEL["trees"])
    return 1.0 / (1.0 + math.exp(-raw))


def analyze(p: ParsedURL, well_known: bool) -> tuple[list[Signal], float | None]:
    prob = probability(p)
    if prob is None:
        return [], None
    signals: list[Signal] = []
    # Only confident predictions contribute; a well-known domain is never
    # penalized for its shape (short brand names look "random" to the model).
    if not well_known and prob >= 0.6:
        # Capped below the strongest rules: the model also sees the domain
        # ending, so a suspicious TLD is partly counted here already.
        weight = min(0.45, (prob - 0.5) * 1.0)
        signals.append(Signal(
            id="ml_suspicious_host",
            layer="ml",
            title="Hostname resembles known phishing domains",
            detail=f"The domain classifier rates this hostname {round(prob * 100)}% similar to phishing domains it was trained on.",
            weight=weight,
        ))
    return signals, prob
