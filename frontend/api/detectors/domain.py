"""
Domain intelligence: registration age (WHOIS), DNS, and where the link
really ends up after redirects (followed safely, see netsafe.py).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import requests

from . import netsafe
from .reputation import _cached
from .signals import Signal
from .urlparts import ParsedURL, parse, InvalidURL


def _whois_created(domain: str, key: str) -> str | None:
    r = requests.get("https://api.ip2whois.com/v2", params={"key": key, "domain": domain, "format": "json"}, timeout=5)
    if r.status_code != 200:
        raise requests.RequestException(f"status {r.status_code}")
    return r.json().get("create_date")


def domain_age(p: ParsedURL) -> tuple[list[Signal], dict]:
    key = os.getenv("WHOIS_API_KEY")
    if not p.registrable:
        return [], {"status": "not_applicable"}
    if not key:
        return [], {"status": "not_configured"}
    try:
        created = _cached(f"whois:{p.registrable}", 86400, lambda: _whois_created(p.registrable, key))
    except requests.RequestException:
        return [], {"status": "error"}
    if not created:
        return [], {"status": "redacted"}
    try:
        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00")[:19]).replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            created_dt = datetime.strptime(created[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return [], {"status": "unparsed"}
    days = max(0, (datetime.now(timezone.utc) - created_dt).days)
    info = {"status": "ok", "created": created_dt.date().isoformat(), "age_days": days}
    if days < 30:
        return [Signal("new_domain", "domain", "Registered in the last 30 days",
                       f"{p.registrable} was registered {days} day{'s' if days != 1 else ''} ago. Most phishing domains are used within weeks of registration.", 0.5)], info
    if days < 180:
        return [Signal("young_domain", "domain", "Registered recently",
                       f"{p.registrable} is about {days // 30} months old.", 0.2)], info
    if days < 365:
        return [Signal("under_a_year", "domain", "Less than a year old", f"{p.registrable} is {days} days old.", 0.06)], info
    return [], info


def dns_and_redirects(p: ParsedURL, follow: bool = True) -> tuple[list[Signal], dict]:
    signals: list[Signal] = []
    info: dict = {}
    if p.is_ip:
        info["resolves"] = True
    else:
        try:
            ips = netsafe.resolve(p.host)
        except netsafe.BlockedDestination:
            info.update(resolves=True, public=False)
            signals.append(Signal("non_public_host", "domain", "Resolves to a private address",
                                  f"{p.host} points to an internal network address, not a public website.", 0.35))
            return signals, info
        info["resolves"] = bool(ips)
        if not ips:
            signals.append(Signal("no_dns", "domain", "Domain does not resolve",
                                  f"{p.host} has no DNS record. It may have been taken down, or never existed.", 0.25))
            return signals, info

    if not follow:
        return signals, info

    res = netsafe.follow_redirects(p.url)
    info.update(final_url=res.final_url, redirects=len(res.hops) - 1, http_status=res.status, fetch_error=res.error)
    try:
        final = parse(res.final_url)
    except InvalidURL:
        final = None
    if final and final.registrable and p.registrable and final.registrable != p.registrable and len(res.hops) > 1:
        info["redirects_to"] = final.registrable
        signals.append(Signal("cross_domain_redirect", "domain", "Redirects to a different site",
                              f"Opening the link sends you to {final.host}.", 0.1))
    if res.error is None and final and final.scheme == "http":
        signals.append(Signal("no_https", "domain", "No HTTPS",
                              "The page is served without encryption, so anything entered on it can be intercepted.", 0.15))
    info["final_https"] = bool(final and final.scheme == "https" and res.error is None)
    return signals, info
