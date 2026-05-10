from . import blacklist, pattern, domain, ml_model
import re
from urllib.parse import urlparse


def calculate_risk_level(score: float) -> str:
    if score >= 0.85:
        return "critical"
    elif score >= 0.65:
        return "high"
    elif score >= 0.45:
        return "medium"
    elif score >= 0.25:
        return "low"
    else:
        return "safe"


def get_recommendation(score: float) -> str:
    if score >= 0.85:
        return "dangerous — phishing likely"
    elif score >= 0.65:
        return "high risk — avoid visiting"
    elif score >= 0.45:
        return "suspicious — proceed carefully"
    elif score >= 0.25:
        return "low risk — stay alert"
    else:
        return "appears safe"


def _is_typo(hostname: str, brand: str) -> bool:
    """Detect common typosquatting patterns like character repetition."""
    hostname = hostname.lower()
    # Normalize by removing repeating characters for comparison
    def normalize(s):
        if not s: return s
        res = [s[0]]
        for c in s[1:]:
            if c != res[-1]:
                res.append(c)
        return "".join(res)
    
    norm_host = normalize(hostname)
    norm_brand = normalize(brand)
    
    # If normalized versions match but originals don't, it's a repetition typo (e.g., payytm vs paytm)
    if norm_brand in norm_host and brand not in hostname:
        return True
    
    # Check for character substitution or missing characters if they are very similar length
    if abs(len(hostname) - len(brand)) <= 2:
        # Simple distance check for common brands
        from difflib import SequenceMatcher
        ratio = SequenceMatcher(None, hostname, brand).ratio()
        if ratio > 0.8 and ratio < 1.0:
            return True

    return False

def _brand_in_domain(hostname: str, brands: list) -> bool:
    """Check brands against hostname only, skip if it's the legitimate domain."""
    hostname = hostname.replace("www.", "").lower()
    # Extract the main domain part (e.g., 'payypal' from 'payypal.com' or 'payypal.co.uk')
    parts = hostname.split('.')
    if not parts:
        return False
    domain_part = parts[0]
    
    for brand in brands:
        # Check for typosquatting on the main domain part (e.g., payytm)
        if _is_typo(domain_part, brand):
            return True
        # Check for direct inclusion in the full hostname if it's not the legitimate domain
        if brand in hostname:
            # If it's something like paypal-security.com or login-paypal.com
            if not hostname.startswith(f"{brand}."):
                return True
    return False


def analyze(url: str) -> dict:

    all_threats = []

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        hostname = url.lower()

    url_lower = url.lower()

    # Layer 1 — Blacklist
    blacklist_result = blacklist.analyze(url)
    
    # Layer 2 — Pattern Analysis
    pattern_result = pattern.analyze(url)
    
    # Layer 3 — Domain Intelligence
    domain_result = domain.analyze(url)
    
    # Layer 4 — ML Detection
    ml_result = ml_model.predict(url)

    # Base weighted score
    final_score = (
        blacklist_result["blacklist_score"] * 0.35 +
        ml_result["ml_score"]              * 0.35 +
        pattern_result["pattern_score"]    * 0.20 +
        domain_result["domain_score"]      * 0.10
    )

    # ==================================================
    # RISK ESCALATION RULES
    # ==================================================

    suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".xyz", ".top", ".click", ".work",
        ".loan", ".online", ".site", ".live", ".icu"
    ]
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        final_score += 0.25
        all_threats.append("Suspicious TLD")

    brands = [
        "paypal", "facebook", "instagram", "amazon",
        "apple", "microsoft", "netflix", "bank",
        "steam", "google", "twitter", "linkedin",
        "paytm", "binance", "coinbase", "kraken",
        "dropbox", "chase", "wellsfargo", "citibank"
    ]
    
    if _brand_in_domain(hostname, brands):
        final_score += 0.35 # Increased from 0.20
        all_threats.append("Brand Impersonation / Typosquatting")

    danger_keywords = [
        "login", "verify", "secure", "update", "password",
        "signin", "confirm", "billing", "session", "account",
        "banking", "alert", "credential", "auth",
        "validation", "reset", "recover"
    ]
    keyword_matches = sum(kw in url_lower for kw in danger_keywords)

    if keyword_matches >= 2:
        final_score += 0.15
        all_threats.append("Suspicious Security Keywords")

    if keyword_matches >= 3:
        final_score += 0.10
        all_threats.append("Multiple Phishing Keywords")

    if url.count("-") >= 3:
        final_score += 0.10
        all_threats.append("Excessive Hyphens")

    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        final_score += 0.25
        all_threats.append("IP Address URL")

    if len(url) > 100:
        final_score += 0.10
        all_threats.append("Long Suspicious URL")

    domain_age = domain_result.get("domain_age_days")
    if domain_age is not None:
        if domain_age < 30:
            final_score += 0.25
            all_threats.append("Newly Registered Domain")
        elif domain_age < 90:
            final_score += 0.15
            all_threats.append("Recently Registered Domain")
    else:
        final_score += 0.15
        all_threats.append("Unknown Domain Age")

    # ==================================================
    # FINAL CLEANUP
    # ==================================================

    final_score = min(final_score, 1.0)
    final_score = round(final_score, 4)

    is_safe = final_score < 0.25

    # Aggregate threats from all layers
    all_threats.extend(blacklist_result["threats"])
    all_threats.extend(pattern_result["threats"])
    all_threats.extend(domain_result["threats"])
    
    # Return detailed breakdown
    return {
        "url": url,
        "is_safe": is_safe,
        "risk_score": final_score,
        "risk_level": calculate_risk_level(final_score),
        "threats_detected": list(set(all_threats)),
        "ml_score": ml_result["ml_score"],
        "domain_age_days": domain_result["domain_age_days"],
        "recommendation": get_recommendation(final_score),
        "breakdown": {
            "blacklist": {
                "score": blacklist_result["blacklist_score"],
                "threats": blacklist_result["threats"],
                "description": "Cross-references global databases for known malicious signatures."
            },
            "pattern": {
                "score": pattern_result["pattern_score"],
                "threats": pattern_result["threats"],
                "description": "Examines URL structure and character distribution for obfuscation."
            },
            "domain": {
                "score": domain_result["domain_score"],
                "threats": domain_result["threats"],
                "description": "Evaluates domain age, SSL status, and historical reputation."
            },
            "ml": {
                "score": ml_result["ml_score"],
                "threats": ["Deep learning inference complete"],
                "description": "Neural classifier trained on millions of samples for zero-day detection."
            }
        }
    }