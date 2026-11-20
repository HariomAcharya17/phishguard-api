"""
Rule-based checks on the URL text itself. No network access.

Covers brand impersonation (in the domain, a subdomain or the path),
look-alike domains, IDN homoglyphs, hosting platforms, obfuscation tricks
and credential-harvesting vocabulary.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import parse_qsl, unquote

from .brands import (
    BRANDS, CONTENT_HOSTING_PREFIXES, CREDENTIAL_WORDS, FREE_HOSTING, RISKY_EXTENSIONS,
    SUSPICIOUS_TLDS, TYPOSQUAT_TARGETS, URL_SHORTENERS, WELL_KNOWN, WHOLE_WORD_ONLY,
    deconfuse, deconfuse_multi, is_official,
)
from .signals import Signal
from .urlparts import ParsedURL


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def damerau(a: str, b: str) -> int:
    """Levenshtein plus adjacent transposition (gogole -> google is 1)."""
    if abs(len(a) - len(b)) > 2:
        return 3
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _brand_tokens_in(text: str) -> set[str]:
    """Brands that appear in text. Short/common brands must be a whole token."""
    low = text.lower()
    toks = set(_tokens(low))
    found = set()
    for brand in BRANDS:
        if brand in WHOLE_WORD_ONLY or len(brand) < 5:
            if brand in toks:
                found.add(brand)
        elif brand in low:
            found.add(brand)
    return found


def _lookalike(label: str) -> tuple[str, str] | None:
    """
    Return (brand, how) if label imitates a brand without being it.
    Checks homoglyph substitution first, then edit distance.
    """
    if not label or len(label) < 4:
        return None
    plain = deconfuse(label)
    # "i" and "l" (and "I"/"l" in many fonts) are the classic swap: robiox, paypai
    for variant in {plain, deconfuse_multi(plain), plain.replace("i", "l"), plain.replace("l", "i")}:
        for brand in TYPOSQUAT_TARGETS:
            if variant == brand and label != brand:
                return brand, "uses look-alike characters"
    # One typo (swap, extra letter, wrong letter) on a distinctive brand name.
    # Deletions that produce a shorter word are ignored (cloud vs icloud).
    for brand in TYPOSQUAT_TARGETS:
        if len(brand) < 6 or label == brand or len(plain) < len(brand) or len(plain) - len(brand) > 1:
            continue
        if damerau(plain, brand) == 1:
            return brand, f"is one character away from \"{brand}\""
    # brand plus 1-2 junk characters glued on: paypall, gooogle1
    for brand in TYPOSQUAT_TARGETS:
        if plain.startswith(brand) and 0 < len(plain) - len(brand) <= 2 and plain != brand:
            return brand, f"adds characters to \"{brand}\""
    return None


def analyze(p: ParsedURL) -> tuple[list[Signal], dict]:
    s: list[Signal] = []
    facts: dict = {}

    def add(id, title, detail, weight):
        s.append(Signal(id=id, layer="url", title=title, detail=detail, weight=weight))

    # ── Non-web schemes ─────────────────────────────────────────────
    if p.scheme in ("javascript", "data", "vbscript", "file"):
        add("dangerous_scheme", "Script or data URL",
            f"The link uses the {p.scheme}: scheme, which can run code or embed a fake page directly in the browser.", 0.9)
        return s, facts

    host, reg = p.host, p.registrable
    path_q = unquote(p.path + ("?" + p.query if p.query else "")).lower()
    full_lower = unquote(p.url).lower()
    well_known = reg in WELL_KNOWN and not p.suffix_is_private
    hp = host + p.path
    content_hosted = any(
        hp.startswith(x) if "/" in x else (host == x or host.endswith("." + x))
        for x in CONTENT_HOSTING_PREFIXES
    )
    facts.update(well_known=well_known, content_hosted=content_hosted)

    # ── Host is an IP address ──────────────────────────────────────
    if p.is_ip:
        if p.ip.is_private or p.ip.is_loopback or p.ip.is_link_local:
            add("private_ip_host", "Points to a private network address",
                f"The host {p.host} is a local or private network address, not a public website.", 0.35)
        else:
            add("ip_host", "IP address instead of a domain name",
                f"The link goes to the raw IP address {p.host}. Legitimate services almost always use a domain name.", 0.5)
        typed_host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", p.original.lower()).split("/")[0].split("@")[-1]
        typed_host = typed_host.rsplit(":", 1)[0] if typed_host.count(":") == 1 else typed_host.strip("[]")
        if typed_host != p.host and p.ip.version == 4:
            add("obfuscated_ip", "Disguised IP address",
                "The IP address is written in decimal, hex or octal form to hide what it is.", 0.4)

    # ── Credentials in the authority: https://paypal.com@evil.tld ───
    if p.userinfo:
        add("userinfo_trick", "Text before \"@\" in the address",
            f"Everything before \"@\" (\"{p.userinfo[:40]}\") is ignored by the browser. The real destination is {host}.", 0.65)

    # ── IDN / punycode ─────────────────────────────────────────────
    if "xn--" in host:
        non_ascii = any(ord(c) > 127 for c in p.host_unicode)
        scripts = {("latin" if c.isascii() else "cyrillic" if "Ѐ" <= c <= "ӿ" else "greek" if "Ͱ" <= c <= "Ͽ" else "other") for c in p.host_unicode if c.isalpha()}
        add("punycode", "Internationalized domain name",
            f"The domain is displayed as \"{p.host_unicode}\" but is registered as {host}.",
            0.3 if any(c.isascii() and c.isalpha() for c in p.host_unicode.split(".")[0]) and non_ascii else 0.08)
        if len(scripts - {"other"}) > 1:
            add("mixed_scripts", "Mixed alphabets in the domain",
                "The domain mixes Latin letters with Cyrillic or Greek ones, a common way to imitate a known name.", 0.5)

    # ── Brand impersonation ────────────────────────────────────────
    # Brand tokens written plainly. Look-alike spellings (paypa1, аpple) are
    # handled separately below so the same evidence is not counted twice.
    try:
        domain_u = p.domain.encode("ascii").decode("idna") if p.domain else ""
    except UnicodeError:
        domain_u = p.domain
    sub_u = p.host_unicode[: -len(domain_u + "." + p.suffix) - 1] if p.subdomain and domain_u else ""
    brands_in_domain = {b for b in _brand_tokens_in(domain_u) if not is_official(b, reg, host)}
    brands_in_sub = {b for b in _brand_tokens_in(sub_u) if not is_official(b, reg, host)} - brands_in_domain
    brands_in_host = brands_in_domain | brands_in_sub
    facts["brands"] = sorted(brands_in_host)

    official_any = any(is_official(b, reg, host) for b in BRANDS)
    facts["official_brand_domain"] = official_any

    if brands_in_sub and not official_any:
        b = sorted(brands_in_sub)[0]
        add("brand_in_subdomain", f"\"{b}\" placed in a subdomain",
            f"The address starts with \"{b}\" but the site actually belongs to {reg or host}. This makes a fake site look official at a glance.", 0.75)
    if brands_in_domain and not official_any:
        b = sorted(brands_in_domain)[0]
        if domain_u == b:
            # brand.<other ending>: could be a regional site (ebay.com.sg) or
            # a copy (roblox.com.bz). Domain age and reputation decide.
            add("brand_other_tld", f"\"{b}\" on an unofficial domain ending",
                f"{reg} uses the {b} name but is not on its list of known official domains. Check that it is a genuine regional site.", 0.35)
        else:
            add("brand_in_domain", f"Uses the \"{b}\" name on an unrelated domain",
                f"{reg} contains \"{b}\" but is not one of {b}'s official domains.", 0.45)
    if brands_in_host and not official_any:
        host_words = sorted({w for w in CREDENTIAL_WORDS if w in host})
        if host_words:
            b = sorted(brands_in_host)[0]
            add("brand_with_account_words", "Brand name combined with account wording",
                f"The hostname pairs \"{b}\" with \"{host_words[0]}\", the pattern of fake sign-in and verification sites.", 0.35)
            facts["brand_words_flagged"] = True

    # Look-alike of a brand in the registrable label or any subdomain label
    if not official_any and not p.is_ip:
        candidates = [domain_u] + [l for l in sub_u.split(".") if l and l != "www"]
        for part in candidates:
            for piece in [part] + part.split("-"):
                hit = _lookalike(piece)
                if hit and not is_official(hit[0], reg, host) and hit[0] not in brands_in_host:
                    brand, how = hit
                    add("lookalike_domain", f"Look-alike of \"{brand}\"",
                        f"\"{piece}\" {how}. Attackers register near-identical names to fool readers.", 0.75)
                    facts.setdefault("brands", []).append(brand)
                    break
            else:
                continue
            break

    # Brand mentioned in the path of an unrelated site: evil.com/paypal/login
    if not official_any and not well_known:
        path_brands = {b for b in _brand_tokens_in(path_q) if not is_official(b, reg, host)} - brands_in_host
        if path_brands:
            b = sorted(path_brands)[0]
            add("brand_in_path", f"\"{b}\" mentioned in the page path",
                f"The path refers to {b}, but the site is {reg or host}.", 0.3)

    # ── Domain shape ───────────────────────────────────────────────
    tld = p.suffix.split(".")[-1] if p.suffix else ""
    if tld in SUSPICIOUS_TLDS and not p.suffix_is_private:
        add("suspicious_tld", f"High-risk domain ending (.{tld})",
            f".{tld} domains are cheap or free and are heavily used for phishing and spam.", 0.2)

    hosting = reg if p.suffix_is_private else None
    hosting_suffix = p.suffix if p.suffix in FREE_HOSTING else (reg if reg in FREE_HOSTING else None)
    if hosting_suffix and not p.is_ip:
        add("free_hosting", "Hosted on a free hosting or tunneling service",
            f"The site is a user-created page on {hosting_suffix}. Anyone can publish there in minutes, which makes it popular for throwaway phishing pages.", 0.15)
    facts["hosting_platform"] = hosting_suffix or hosting

    if reg in URL_SHORTENERS or host in URL_SHORTENERS:
        add("url_shortener", "Shortened link",
            f"{host} is a link shortener, so the real destination is hidden until you open it.", 0.25)
        facts["shortener"] = True

    if content_hosted:
        add("shared_content_host", "User-generated page on a trusted service",
            f"This is a form, document or page that any user can create on {host}. The service is legitimate, but the content may not be.", 0.15)

    sub_count = len(p.subdomain_labels)
    if sub_count >= 4:
        add("deep_subdomains", "Unusually many subdomains",
            f"The host has {sub_count} subdomain levels, often used to push the real domain out of view on mobile screens.", 0.3)
    elif sub_count == 3 and not well_known:
        add("deep_subdomains", "Many subdomains", f"The host has {sub_count} subdomain levels.", 0.12)

    if len(host) > 50:
        add("long_host", "Very long hostname", f"The hostname is {len(host)} characters long.", 0.15)

    hyphens = p.host_unicode.count("-") if "xn--" in host else host.count("-")
    if hyphens >= 4:
        add("many_hyphens", "Many hyphens in the hostname", f"The hostname contains {hyphens} hyphens, typical of keyword-stuffed fake domains.", 0.3)
    elif hyphens >= 2 and not well_known:
        add("many_hyphens", "Several hyphens in the hostname", f"The hostname contains {hyphens} hyphens.", 0.1)

    main = p.domain
    if main and not p.is_ip:
        digits = sum(c.isdigit() for c in main)
        if len(main) >= 8 and digits / len(main) > 0.3:
            add("digit_heavy_domain", "Domain name is mostly numbers",
                f"\"{main}\" contains {digits} digits, which looks machine-generated.", 0.2)
        if len(main) >= 12 and "-" not in main and entropy(main) > 3.6 and not well_known:
            add("random_domain", "Random-looking domain name",
                f"\"{main}\" looks randomly generated rather than chosen by a person.", 0.2)
        # brand-free host stuffed with credential words: secure-login-verify.com
        host_words = [w for w in CREDENTIAL_WORDS if w in host.replace(reg, "") + main]
        if len(host_words) >= 2 and not well_known and not facts.get("brand_words_flagged"):
            add("credential_words_in_host", "Account-related words in the hostname",
                f"The hostname uses words like {', '.join(sorted(host_words)[:3])}, a hallmark of fake login sites.", 0.35)

    if p.port and p.port not in (80, 443):
        add("unusual_port", "Non-standard port", f"The link uses port {p.port}; public websites normally use 80 or 443.", 0.2)

    # ── Path and query ─────────────────────────────────────────────
    words = sorted({w for w in CREDENTIAL_WORDS if w in path_q})
    facts["credential_words"] = words
    if not well_known or content_hosted:
        if len(words) >= 3:
            add("credential_words_in_path", "Login or payment wording in the link",
                f"The link contains {', '.join(words[:4])}. Phishing pages use this wording to look like an account page.", 0.3)
        elif len(words) >= 1:
            add("credential_words_in_path", "Account-related word in the link",
                f"The link contains \"{words[0]}\".", 0.1 if len(words) == 1 else 0.18)

    ext = re.search(r"(\.[a-z0-9]{1,5})$", p.path.lower())
    if ext and ext.group(1) in RISKY_EXTENSIONS:
        add("risky_download", f"Direct download of a {ext.group(1)} file",
            f"The link downloads a {ext.group(1)} file, a format that can install software or hide malware.", 0.4)
    if re.search(r"\.(pdf|doc|docx|xls|jpg|png)\.(exe|scr|js|zip|html?)$", p.path.lower()):
        add("double_extension", "Disguised file type", "The file name has two extensions to disguise what it really is.", 0.5)

    embedded = [v for _, v in parse_qsl(p.query, keep_blank_values=True) if re.match(r"^(https?:)?//", unquote(v).strip(), re.I)]
    if embedded or re.search(r"[?&](url|redirect|redir|next|goto|target|dest|destination|return|continue)=https?", p.query, re.I):
        add("embedded_redirect", "Contains a redirect to another site",
            "A parameter in the link points to a different web address, a trick used to bounce visitors through a trusted site.", 0.2)

    if "//" in p.path:
        add("double_slash", "Double slash in the path", "The path contains \"//\", sometimes used to confuse link parsers.", 0.08)

    pct = len(re.findall(r"%[0-9a-f]{2}", p.url.lower()))
    if pct >= 10 or re.search(r"%(2e|2f|40)", p.path.lower()):
        add("encoded_url", "Heavily encoded characters",
            f"The link contains {pct} percent-encoded characters, which can hide the real text.", 0.2)

    if len(p.url) > 200:
        add("long_url", "Very long link", f"The link is {len(p.url)} characters long.", 0.1)

    if p.scheme == "http" and not p.scheme_was_added:
        add("http_only", "Not encrypted (http)", "The link uses http, so anything typed on the page is sent unencrypted.", 0.1)

    if re.search(r"(^|/)(wp-admin|wp-includes|wp-content)/.*\.(php|html?)", p.path.lower()) and words:
        add("compromised_cms_path", "Login page inside a website's internal folders",
            "The page sits inside WordPress system folders, a common sign of a hacked site hosting a phishing kit.", 0.35)

    return s, facts
