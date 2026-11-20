"""
Hostname features for the domain classifier.

Used both at inference time (ml_model.py) and by the training script
(ml/train_domain_model.py), so the two can never drift apart.

The features describe only the *shape* of the hostname (lengths, character
mix, randomness, domain ending). Brand names, hosting platforms and
credential words are deliberately left out: lexical.py scores those as
explicit rules, and feeding them to the model as well would count the same
evidence twice.
"""
from __future__ import annotations

import math
import re
from collections import Counter

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "in", "uk", "de", "fr", "jp",
    "au", "ca", "us", "nl", "it", "es", "br", "ch", "se", "no", "dk", "fi", "be", "at", "nz",
    "sg", "ie", "kr", "pl", "ru", "cn", "za", "mx", "ai", "dev", "app",
}
ABUSED_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site", "fun", "click", "work",
    "loan", "live", "icu", "buzz", "rest", "cyou", "monster", "cfd", "sbs", "quest", "bond", "lol",
    "mom", "support", "help", "pw", "cc", "ws", "su", "zip", "mov", "shop", "store", "win", "vip",
}
VOWELS = set("aeiou")

FEATURE_NAMES = [
    "host_len", "domain_len", "suffix_parts", "sub_count", "longest_label",
    "hyphens", "digits_host", "digit_ratio_domain", "max_digit_run", "max_consonant_run",
    "vowel_ratio_domain", "entropy_domain", "entropy_host", "unique_ratio_domain",
    "tld_common", "tld_abused", "tld_len", "is_ip", "punycode", "label_has_digits_letters",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _max_run(s: str, pred) -> int:
    best = cur = 0
    for ch in s:
        cur = cur + 1 if pred(ch) else 0
        best = max(best, cur)
    return best


def host_features(host: str, domain: str, suffix: str, subdomain: str, is_ip: bool) -> list[float]:
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    sub_labels = [l for l in subdomain.lower().split(".") if l and l != "www"]
    domain = domain.lower()
    letters = [c for c in domain if c.isalpha()]
    tld = suffix.split(".")[-1] if suffix else ""
    labels = [l for l in host.split(".") if l]

    return [
        float(len(host)),
        float(len(domain)),
        float(suffix.count(".") + 1 if suffix else 0),
        float(len(sub_labels)),
        float(max((len(l) for l in labels), default=0)),
        float(host.count("-")),
        float(sum(c.isdigit() for c in host)),
        (sum(c.isdigit() for c in domain) / len(domain)) if domain else 0.0,
        float(_max_run(domain, str.isdigit)),
        float(_max_run(domain, lambda c: c.isalpha() and c not in VOWELS)),
        (sum(c in VOWELS for c in letters) / len(letters)) if letters else 0.0,
        _entropy(domain),
        _entropy(host.replace(".", "")),
        (len(set(domain)) / len(domain)) if domain else 0.0,
        1.0 if tld in COMMON_TLDS else 0.0,
        1.0 if tld in ABUSED_TLDS else 0.0,
        float(len(tld)),
        1.0 if is_ip else 0.0,
        1.0 if "xn--" in host else 0.0,
        1.0 if any(re.search(r"[a-z]", l) and re.search(r"\d", l) for l in labels) else 0.0,
    ]
