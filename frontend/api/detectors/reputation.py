"""
Reputation feeds: VirusTotal, Google Safe Browsing and OpenPhish.

Each source is optional. A missing key or an outage is reported as
"not checked" and never raises the risk score on its own.
"""
from __future__ import annotations

import base64
import os
import threading
import time

import requests

from .signals import Signal
from .urlparts import ParsedURL

_cache: dict[str, tuple[float, object]] = {}
_lock = threading.Lock()


def _cached(key: str, ttl: float, fn):
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    value = fn()
    with _lock:
        if len(_cache) > 2000:
            _cache.clear()
        _cache[key] = (now, value)
    return value


# ── VirusTotal ──────────────────────────────────────────────────────

def _vt_stats(path: str, key: str) -> tuple[int, dict | None]:
    r = requests.get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key}, timeout=6)
    if r.status_code != 200:
        return r.status_code, None
    return 200, r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})


def virustotal(p: ParsedURL, domain_fallback: bool = True) -> tuple[list[Signal], dict]:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return [], {"status": "not_configured"}
    try:
        url_id = base64.urlsafe_b64encode(p.url.encode()).decode().strip("=")
        status, stats = _cached(f"vt:url:{p.url}", 900, lambda: _vt_stats(f"urls/{url_id}", key))
        scope = "url"
        if status == 404 and p.registrable and domain_fallback:
            # URL never scanned: fall back to the domain's reputation.
            status, stats = _cached(f"vt:dom:{p.registrable}", 3600, lambda: _vt_stats(f"domains/{p.registrable}", key))
            scope = "domain"
        if status == 429:
            return [], {"status": "rate_limited"}
        if status in (401, 403):
            return [], {"status": "auth_error"}
        if stats is None:
            return [], {"status": "unknown" if status == 404 else "error"}
    except requests.RequestException:
        return [], {"status": "error"}

    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(v for v in stats.values() if isinstance(v, int))
    info = {"status": "ok", "scope": scope, "malicious": mal, "suspicious": sus, "engines": total}
    what = "this exact link" if scope == "url" else f"the domain {p.registrable}"
    sigs: list[Signal] = []
    if mal >= 3:
        sigs.append(Signal("vt_malicious", "reputation", "Flagged by security vendors",
                           f"{mal} of {total} VirusTotal engines flag {what} as malicious or phishing.",
                           0.95 if scope == "url" else 0.8, confirmed=scope == "url"))
    elif mal >= 1:
        sigs.append(Signal("vt_low_confidence", "reputation", "Flagged by a few security vendors",
                           f"{mal} of {total} VirusTotal engines flag {what}. Low agreement, so treat as a warning.",
                           0.3 if scope == "url" else 0.2))
    if sus >= 3:
        sigs.append(Signal("vt_suspicious", "reputation", "Marked suspicious by security vendors",
                           f"{sus} VirusTotal engines mark {what} as suspicious.", 0.35))
    return sigs, info


# ── Google Safe Browsing ────────────────────────────────────────────

def safe_browsing(p: ParsedURL) -> tuple[list[Signal], dict]:
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return [], {"status": "not_configured"}

    def call():
        body = {
            "client": {"clientId": "phishguard", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": p.url}],
            },
        }
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body, timeout=5)
        r.raise_for_status()
        return [m.get("threatType") for m in r.json().get("matches", [])]

    try:
        matches = _cached(f"gsb:{p.url}", 900, call)
    except requests.RequestException:
        return [], {"status": "error"}
    if not matches:
        return [], {"status": "ok", "matches": []}
    kinds = ", ".join(sorted({m.replace("_", " ").lower() for m in matches}))
    return [Signal("safe_browsing_match", "reputation", "Listed by Google Safe Browsing",
                   f"Google Safe Browsing lists this link as {kinds}.", 0.97, confirmed=True)], {"status": "ok", "matches": matches}


# ── OpenPhish community feed ────────────────────────────────────────

OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"


def _openphish_feed() -> tuple[set[str], set[str]]:
    r = requests.get(OPENPHISH_URL, timeout=5)
    r.raise_for_status()
    urls, hosts = set(), set()
    for line in r.text.splitlines():
        line = line.strip().lower().rstrip("/")
        if line.startswith("http"):
            urls.add(line)
            host = line.split("//", 1)[1].split("/", 1)[0].split(":")[0]
            hosts.add(host)
    return urls, hosts


def openphish(p: ParsedURL) -> tuple[list[Signal], dict]:
    if os.getenv("OPENPHISH_DISABLED") == "1":
        return [], {"status": "not_configured"}
    try:
        urls, hosts = _cached("openphish", 1800, _openphish_feed)
    except requests.RequestException:
        return [], {"status": "error"}
    u = p.url.lower().rstrip("/")
    if u in urls:
        return [Signal("openphish_url", "reputation", "Listed in the OpenPhish feed",
                       "This exact link appears in OpenPhish's list of active phishing URLs.", 0.97, confirmed=True)], {"status": "ok", "listed": "url"}
    if p.host in hosts:
        return [Signal("openphish_host", "reputation", "Host listed in the OpenPhish feed",
                       f"Other phishing pages on {p.host} appear in OpenPhish's active feed.", 0.8)], {"status": "ok", "listed": "host"}
    return [], {"status": "ok", "listed": None, "feed_size": len(urls)}
