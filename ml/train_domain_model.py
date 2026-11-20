"""
Train the PhishGuard hostname classifier and export it as JSON.

Dataset: PhiUSIIL Phishing URL Dataset (UCI ML Repository, id 967).
  https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
  Prasad, A., & Chandra, S. (2023). PhiUSIIL: A diverse security profile
  empowered phishing URL detection framework. Computers & Security.

Usage:
  python ml/train_domain_model.py path/to/PhiUSIIL_Phishing_URL_Dataset.csv

Notes on dataset bias:
  * Every legitimate URL in PhiUSIIL is a bare "https://www.<domain>" homepage,
    while many phishing URLs include paths. The model therefore sees ONLY the
    hostname, never the path, scheme or query.
  * Legitimate hosts have no subdomains besides "www". To stop the model from
    learning "any subdomain = phishing", a share of legitimate rows get a
    common subdomain (docs., mail., app., ...) added during training.
  * Rows are split by registrable domain so the test set never contains a
    domain seen in training.

Requires (training only): pandas, scikit-learn, tldextract.
"""
from __future__ import annotations

import json
import os
import random
import sys
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import average_precision_score, classification_report, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "frontend", "api"))

from detectors.features import FEATURE_NAMES, host_features  # noqa: E402
from detectors.urlparts import InvalidURL, parse  # noqa: E402

OUT = os.path.join(ROOT, "frontend", "api", "model", "domain_model.json")
COMMON_SUBS = ["docs", "mail", "app", "api", "blog", "shop", "m", "support", "help", "news",
               "en", "store", "my", "portal", "login", "accounts", "secure", "dev", "status", "cdn"]


def row_features(url: str, rng: random.Random, augment: bool):
    try:
        p = parse(url)
    except InvalidURL:
        return None
    host, sub = p.host, p.subdomain
    if augment and p.registrable and rng.random() < 0.35:
        extra = rng.choice(COMMON_SUBS)
        host = f"{extra}.{p.registrable}"
        sub = extra
    return host_features(host, p.domain, p.suffix, sub, p.is_ip), (p.registrable or p.host)


def main(csv_path: str) -> None:
    df = pd.read_csv(csv_path, usecols=["URL", "label"])
    df = df.dropna()
    # PhiUSIIL: label 1 = legitimate, 0 = phishing. We predict phishing.
    df["phish"] = (df["label"] == 0).astype(int)
    df["host"] = df["URL"].map(lambda u: (urlsplit(u if "://" in u else "http://" + u).hostname or "").lower().removeprefix("www."))
    # One row per (host, label): repeated phishing URLs on the same host would
    # otherwise dominate training.
    df = df.drop_duplicates(subset=["host", "phish"])

    rng = random.Random(42)
    X, y, groups = [], [], []
    for url, phish in zip(df["URL"], df["phish"]):
        r = row_features(url, rng, augment=(phish == 0))
        if r is None:
            continue
        X.append(r[0]); y.append(phish); groups.append(r[1])
    X, y = np.array(X), np.array(y)
    print(f"rows: {len(y)}  phishing: {y.sum()}  legitimate: {len(y) - y.sum()}")

    split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(split.split(X, y, groups))

    model = GradientBoostingClassifier(
        n_estimators=250, max_depth=4, learning_rate=0.1, subsample=0.8,
        min_samples_leaf=40, random_state=42,
    )
    model.fit(X[train_idx], y[train_idx])

    proba = model.predict_proba(X[test_idx])[:, 1]
    pred = (proba >= 0.5).astype(int)
    auc = roc_auc_score(y[test_idx], proba)
    ap = average_precision_score(y[test_idx], proba)
    print(f"ROC AUC: {auc:.4f}  PR AUC: {ap:.4f}")
    print(classification_report(y[test_idx], pred, target_names=["legitimate", "phishing"], digits=4))

    init_p = float(np.clip(y[train_idx].mean(), 1e-6, 1 - 1e-6))
    trees = []
    for est in model.estimators_[:, 0]:
        t = est.tree_
        trees.append({
            "l": t.children_left.tolist(),
            "r": t.children_right.tolist(),
            "f": [int(f) if f >= 0 else 0 for f in t.feature],
            "t": [round(float(v), 6) for v in t.threshold],
            "v": [round(float(v), 6) for v in t.value[:, 0, 0]],
        })
    exported = {
        "format": "gbdt-logloss-v1",
        "features": FEATURE_NAMES,
        "init": float(np.log(init_p / (1 - init_p))),
        "learning_rate": model.learning_rate,
        "trees": trees,
        "metrics": {"roc_auc": round(auc, 4), "pr_auc": round(ap, 4), "test_rows": int(len(test_idx))},
        "dataset": "PhiUSIIL Phishing URL Dataset (UCI 967), hostname only",
    }

    # Verify the exported trees reproduce scikit-learn's probabilities.
    sys.modules.pop("detectors.ml_model", None)
    from detectors import ml_model
    ml_model._MODEL = exported
    ml_model.MODEL_LOADED = True
    sample = X[test_idx][:500]
    ours = []
    for x in sample:
        raw = exported["init"] + exported["learning_rate"] * sum(ml_model._tree_value(t, list(x)) for t in trees)
        ours.append(1 / (1 + np.exp(-raw)))
    diff = np.max(np.abs(np.array(ours) - model.predict_proba(sample)[:, 1]))
    print(f"max |exported - sklearn| on 500 rows: {diff:.2e}")
    assert diff < 1e-4, "exported model does not match scikit-learn output"

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(exported, f, separators=(",", ":"))
    print(f"wrote {OUT} ({os.path.getsize(OUT) / 1024:.0f} KB)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
