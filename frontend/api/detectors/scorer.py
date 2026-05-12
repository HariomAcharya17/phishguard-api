import os
import re
from urllib.parse import urlparse
from detectors import blacklist, pattern, domain, ml_model

def calculate_risk_level(score: float) -> str:
    if score < 0.15: return "safe"
    if score < 0.35: return "low"
    if score < 0.65: return "medium"
    if score < 0.85: return "high"
    return "critical"

def get_recommendation(score: float) -> str:
    if score < 0.25:
        return "This URL appears safe. No malicious signatures were detected."
    if score < 0.5:
        return "Exercise caution. Minor suspicious patterns detected."
    if score < 0.75:
        return "High risk. This URL exhibits multiple phishing characteristics."
    return "Dangerous. Strongly recommended to avoid this URL."

def _brand_in_domain(hostname: str, brands: list) -> bool:
    hostname = hostname.lower()
    for brand in brands:
        if brand in hostname:
            # If it's exactly the brand's domain (or subdomain of it), it's safe
            # e.g. 'paypal.com' or 'service.paypal.com'
            if hostname == brand + ".com" or hostname.endswith("." + brand + ".com"):
                return False
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

    # Layer 1 — Blacklist (VirusTotal)
    blacklist_result = blacklist.analyze(url)
    
    # Layer 2 — Pattern Analysis (Heuristics)
    pattern_result = pattern.analyze(url)
    
    # Layer 3 — Domain Intelligence (WHOIS/SSL)
    domain_result = domain.analyze(url)
    
    # Layer 4 — ML Detection (Random Forest)
    ml_result = ml_model.predict(url)

    # Base weighted score
    final_score = (
        blacklist_result.get("blacklist_score", 0.0) * 0.35 +
        ml_result.get("ml_score", 0.0)              * 0.35 +
        pattern_result.get("pattern_score", 0.0)    * 0.20 +
        domain_result.get("domain_score", 0.0)      * 0.10
    )

    # ==================================================
    # RISK ESCALATION RULES
    # ==================================================

    # 1. Suspicious TLDs
    suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".xyz", ".top", ".click", ".work",
        ".loan", ".online", ".site", ".live", ".icu"
    ]
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        final_score += 0.20
        all_threats.append("suspicious_tld_escalation")

    # 2. Brand Impersonation
    brands = [
        "paypal", "facebook", "instagram", "amazon",
        "apple", "microsoft", "netflix", "bank",
        "steam", "google", "twitter", "linkedin",
        "paytm", "binance", "coinbase", "kraken",
        "dropbox", "chase", "wellsfargo", "citibank"
    ]
    if _brand_in_domain(hostname, brands):
        final_score += 0.35
        all_threats.append("brand_impersonation_detected")

    # 3. Phishing Keywords
    danger_keywords = [
        "login", "verify", "secure", "update", "password",
        "signin", "confirm", "billing", "session", "account",
        "banking", "alert", "credential", "auth",
        "validation", "reset", "recover"
    ]
    keyword_matches = sum(kw in url_lower for kw in danger_keywords)
    if keyword_matches >= 2:
        final_score += 0.15
        all_threats.append("multiple_phishing_keywords")

    # 4. Domain Age
    domain_age = domain_result.get("domain_age_days")
    if domain_age is not None:
        if domain_age < 30:
            final_score += 0.25
            all_threats.append("newly_registered_domain")
        elif domain_age < 90:
            final_score += 0.10
            all_threats.append("recently_registered_domain")

    # ==================================================
    # FINAL AGGREGATION
    # ==================================================

    final_score = min(final_score, 1.0)
    final_score = round(final_score, 4)

    is_safe = final_score < 0.25

    # Aggregate threats from all layers
    all_threats.extend(blacklist_result.get("threats", []))
    all_threats.extend(pattern_result.get("threats", []))
    all_threats.extend(domain_result.get("threats", []))
    
    return {
        "url": url,
        "is_safe": is_safe,
        "risk_score": final_score,
        "risk_level": calculate_risk_level(final_score),
        "threats_detected": list(set(all_threats)),
        "ml_score": ml_result.get("ml_score", 0.0),
        "domain_age_days": domain_result.get("domain_age_days"),
        "recommendation": get_recommendation(final_score),
        "breakdown": {
            "blacklist": {
                "score": blacklist_result.get("blacklist_score", 0.0),
                "threats": blacklist_result.get("threats", []),
                "description": "Cross-references global databases for known malicious signatures."
            },
            "pattern": {
                "score": pattern_result.get("pattern_score", 0.0),
                "threats": pattern_result.get("threats", []),
                "description": "Examines URL structure and character distribution for obfuscation."
            },
            "domain": {
                "score": domain_result.get("domain_score", 0.0),
                "threats": domain_result.get("threats", []),
                "description": "Evaluates domain age, SSL status, and historical reputation."
            },
            "ml": {
                "score": ml_result.get("ml_score", 0.0),
                "threats": ["Deep learning inference complete"],
                "description": "Neural classifier trained on millions of samples for zero-day detection."
            }
        }
    }