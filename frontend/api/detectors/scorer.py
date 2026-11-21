"""
Runs every detector and turns their signals into one verdict.

Scoring:
  * Each detector emits Signals with a weight in [0, 1].
  * Weights are combined with noisy-OR (see signals.combine), so each piece of
    evidence counts once and independent evidence reinforces itself.
  * A confirmed listing in a reputation feed sets a floor of 0.95.
  * On well-known domains, URL-shape heuristics and the ML model are damped
    (a bank's own login page legitimately says "login"), but reputation
    feeds still apply in full.
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, wait

from . import domain, lexical, ml_model, reputation
from .brands import is_official
from .signals import Signal, combine
from .urlparts import InvalidURL, ParsedURL, parse

_pool = ThreadPoolExecutor(max_workers=16)
NETWORK_BUDGET_S = 8.0

BRAND_SIGNALS = {"lookalike_domain", "brand_in_domain", "brand_other_tld", "brand_in_subdomain", "brand_with_account_words"}

LEVELS = [(0.2, "safe"), (0.4, "low"), (0.6, "medium"), (0.8, "high"), (1.01, "critical")]

VERDICTS = {
    "safe": "No signs of phishing found.",
    "low": "Mostly fine, with minor warning signs.",
    "medium": "Suspicious. Several phishing traits found.",
    "high": "Likely phishing.",
    "critical": "Phishing or malicious. Do not open.",
}
ADVICE = {
    "safe": "No warning signs were found. Still check the address bar before entering a password.",
    "low": "Probably legitimate, but confirm the address is the one you expect before signing in or paying.",
    "medium": "Do not enter passwords, card numbers or OTPs here. Reach the service by typing its address yourself.",
    "high": "Avoid this link. If it came by email or SMS, report it and delete the message.",
    "critical": "Do not open this link. If you already entered details, change your password and contact your bank or the service immediately.",
}

LAYER_DESCRIPTIONS = {
    "reputation": "VirusTotal and OpenPhish lookups for this link and domain.",
    "url": "Rules for brand impersonation, look-alike domains, hosting platforms and obfuscation tricks.",
    "domain": "Registration age, DNS, HTTPS and where the link redirects.",
    "ml": "Gradient-boosted tree model scoring the hostname's structure, trained on the PhiUSIIL dataset.",
}


def level_for(score: float) -> str:
    return next(name for limit, name in LEVELS if score < limit)


def _safe_call(fn, *args):
    try:
        return fn(*args)
    except Exception as e:  # a failing source must never fail the scan
        print(f"[scorer] {getattr(fn, '__name__', fn)} failed: {type(e).__name__}: {e}")
        return [], {"status": "error"}


def analyze(raw_url: str, network: bool | None = None) -> dict:
    if network is None:
        network = os.getenv("PHISHGUARD_OFFLINE") != "1"
    started = time.perf_counter()
    p = parse(raw_url)  # raises InvalidURL

    url_signals, facts = lexical.analyze(p)
    well_known = facts.get("well_known", False) and not facts.get("content_hosted", False)
    ml_signals, ml_prob = ml_model.analyze(p, well_known)

    checks: dict[str, dict] = {}
    rep_signals: list[Signal] = []
    dom_signals: list[Signal] = []

    if network and p.host:
        jobs = {
            # Shared services (shorteners, hosting platforms, big sites) get
            # flagged at domain level because of their users; only use the
            # domain fallback for ordinary domains.
            "virustotal": _pool.submit(
                _safe_call, reputation.virustotal, p,
                not (well_known or facts.get("shortener") or facts.get("hosting_platform")),
            ),
            "openphish": _pool.submit(_safe_call, reputation.openphish, p),
            "whois": _pool.submit(_safe_call, domain.domain_age, p),
            "dns": _pool.submit(_safe_call, domain.dns_and_redirects, p),
        }
        wait(jobs.values(), timeout=NETWORK_BUDGET_S)
        for name, fut in jobs.items():
            if not fut.done():
                checks[name] = {"status": "timeout"}
                continue
            sigs, info = fut.result()
            checks[name] = info
            (rep_signals if name in ("virustotal", "openphish") else dom_signals).extend(sigs)
    else:
        for name in ("virustotal", "openphish", "whois", "dns"):
            checks[name] = {"status": "skipped"}

    # If the link redirects elsewhere (shorteners, tracking links), judge the
    # destination's URL too and keep whichever evidence is stronger.
    final_url = checks.get("dns", {}).get("final_url")
    if final_url and final_url != p.url:
        try:
            fp = parse(final_url)
            if fp.registrable != p.registrable:
                dest_signals, dest_facts = lexical.analyze(fp)
                dest_known = dest_facts.get("well_known") and not dest_facts.get("content_hosted")
                for sg in dest_signals:
                    if sg.id in ("http_only",):
                        continue
                    sg.id = "destination_" + sg.id
                    sg.detail = f"After redirecting to {fp.host}: {sg.detail}"
                    url_signals.append(sg)
                # Brands often register look-alikes of their own name and
                # redirect them home (paypa1.com -> paypal.com).
                owner = [b for b in facts.get("brands", []) if is_official(b, fp.registrable, fp.host)]
                if owner:
                    for sg in url_signals:
                        if sg.id in BRAND_SIGNALS:
                            sg.weight *= 0.2
                    url_signals.append(Signal(
                        "redirects_to_official", "url", f"Redirects to the official {owner[0]} site",
                        f"The link forwards to {fp.host}, which belongs to {owner[0]}. This is likely a domain the company registered to protect its name.",
                        0.0))
                if facts.get("shortener") and dest_known:
                    # A shortener pointing at a well-known site is ordinary.
                    for sg in url_signals:
                        if sg.id == "url_shortener":
                            sg.weight = 0.05
        except InvalidURL:
            pass

    if well_known:
        for sg in url_signals + ml_signals + dom_signals:
            sg.weight *= 0.25
        rep_signals = [sg for sg in rep_signals if sg.id != "openphish_host"]

    signals = rep_signals + url_signals + dom_signals + ml_signals
    score = combine([sg.weight for sg in signals])
    confirmed = any(sg.confirmed for sg in signals)
    if confirmed:
        score = max(score, 0.95)
    score = round(min(score, 1.0), 4)
    level = level_for(score)

    def layer(name: str, sigs: list[Signal]) -> dict:
        return {
            "score": round(combine([sg.weight for sg in sigs]), 4),
            "threats": [sg.id for sg in sigs],
            "description": LAYER_DESCRIPTIONS[name],
        }

    ordered = sorted(signals, key=lambda sg: (not sg.confirmed, -sg.weight))
    whois = checks.get("whois", {})

    return {
        "url": p.url,
        "input": p.original,
        "host": p.host_unicode or p.host,
        "registrable_domain": p.registrable or None,
        "is_safe": level == "safe",
        "risk_score": score,
        "risk_level": level,
        "verdict": VERDICTS[level],
        "recommendation": ADVICE[level],
        "confirmed_malicious": confirmed,
        "signals": [sg.to_dict() for sg in ordered if sg.weight > 0.0 or sg.id == "redirects_to_official"],
        "threats_detected": [sg.id for sg in ordered if sg.weight >= 0.1],
        "ml_score": round(ml_prob, 4) if ml_prob is not None else None,
        "domain_age_days": whois.get("age_days"),
        "domain_created": whois.get("created"),
        "final_url": final_url,
        "well_known_domain": well_known,
        "brands_detected": sorted(set(facts.get("brands", []))),
        "checks": checks,
        "breakdown": {
            "blacklist": layer("reputation", rep_signals),
            "pattern": layer("url", url_signals),
            "domain": layer("domain", dom_signals),
            "ml": layer("ml", ml_signals),
        },
        "analysis_ms": round((time.perf_counter() - started) * 1000),
    }
