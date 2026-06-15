import re
from urllib.parse import urlparse

# These keywords are suspicious ONLY when found on a domain that isn't the brand itself
BRAND_KEYWORDS = [
    'paypal', 'facebook', 'instagram', 'amazon', 'apple',
    'microsoft', 'netflix', 'google', 'twitter', 'linkedin',
    'ebay', 'paytm', 'binance', 'coinbase', 'steam',
    'dropbox', 'chase', 'wellsfargo', 'citibank'
]

# These keywords are suspicious regardless of domain (phishing action words)
PHISHING_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'signin', 'password',
    'credit', 'wallet', 'crypto', 'bitcoin', 'urgent',
    'validate', 'recover', 'reset', 'credential', 'auth'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
    '.top', '.club', '.online', '.site', '.fun',
    '.click', '.work', '.loan', '.live', '.icu'
]

TRUSTED_DOMAINS = {
    'google.com', 'facebook.com', 'amazon.com', 'apple.com',
    'microsoft.com', 'paypal.com', 'netflix.com', 'instagram.com',
    'twitter.com', 'x.com', 'linkedin.com', 'github.com',
    'youtube.com', 'paytm.com', 'binance.com', 'coinbase.com',
    'wikipedia.org', 'reddit.com', 'whatsapp.com', 'zoom.us',
    'slack.com', 'notion.so', 'figma.com', 'dropbox.com'
}


def _get_root_domain(url: str) -> str:
    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lower().replace("www.", "")
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    except Exception:
        return ""


def _normalize(s: str) -> str:
    """Collapse repeated characters: 'payytm' → 'paytm'"""
    if not s:
        return s
    res = [s[0]]
    for c in s[1:]:
        if c != res[-1]:
            res.append(c)
    return "".join(res)


def analyze(url: str) -> dict:
    threats = []
    score = 0.0

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        root_domain = _get_root_domain(url)
    except Exception:
        hostname = url.lower()
        root_domain = ""

    url_lower = url.lower()

    # Fast-path: trusted domains skip pattern scoring entirely
    if root_domain in TRUSTED_DOMAINS:
        return {
            "threats": [],
            "pattern_score": 0.0
        }

    # Has IP instead of domain
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        threats.append("ip_in_url")
        score += 0.3

    # Has @ symbol
    if '@' in url:
        threats.append("at_symbol")
        score += 0.3

    # Too many subdomains
    try:
        parts = hostname.split('.')
        if len(parts) > 4:
            threats.append("too_many_subdomains")
            score += 0.2
    except Exception:
        pass

    # Suspicious TLD
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        threats.append("suspicious_tld")
        score += 0.25

    # FIX: Brand keywords only suspicious on FOREIGN domains
    # e.g. "facebook" in "login-facebook.net" is suspicious
    # but "facebook" in "facebook.com" is fine
    for brand in BRAND_KEYWORDS:
        if brand in url_lower and not root_domain.startswith(brand + "."):
            threats.append("suspicious_keywords")
            score += 0.2
            break  # One flag is enough

    # Phishing action keywords — suspicious on any domain
    phishing_hits = sum(kw in url_lower for kw in PHISHING_KEYWORDS)
    if phishing_hits >= 2:
        threats.append("phishing_keywords")
        score += 0.2
    elif phishing_hits == 1:
        threats.append("phishing_keywords")
        score += 0.1

    # URL too long
    if len(url) > 100:
        threats.append("long_url")
        score += 0.1

    # Has double slash redirect (after stripping protocol)
    stripped = url.replace('https://', '').replace('http://', '')
    if '//' in stripped:
        threats.append("double_slash_redirect")
        score += 0.2

    # Typosquatting check — only on the domain part, not full URL
    try:
        domain_part = hostname.replace("www.", "").split(".")[0]
        norm_domain = _normalize(domain_part)

        for brand in BRAND_KEYWORDS:
            brand_name = brand.split(".")[0]
            norm_brand = _normalize(brand_name)

            # Repetition typo: payytm → paytm
            if norm_brand == norm_domain and brand_name != domain_part:
                threats.append(f"typosquatting_{brand_name}")
                score += 0.5
                break

            # Brand name embedded with extra chars: paypal-login, secure-paypal
            if brand_name in domain_part and not domain_part == brand_name:
                threats.append(f"brand_impersonation_{brand_name}")
                score += 0.4
                break
    except Exception:
        pass

    # No HTTPS (only penalize once — domain.py handles the real SSL check)
    if not url.startswith('https'):
        threats.append("no_https")
        score += 0.1  # Reduced from 0.15; domain.py does the real check

    # Excessive special characters
    special_count = sum(
        1 for c in url
        if not c.isalnum() and c not in ['.', '/', ':', '-', '_', '?', '=', '&']
    )
    if special_count > 10:
        threats.append("excessive_special_chars")
        score += 0.15

    return {
        "threats": threats,
        "pattern_score": round(min(score, 1.0), 4)
    }