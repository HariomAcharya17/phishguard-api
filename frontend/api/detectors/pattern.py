import re

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'paypal', 'signin', 'password',
    'ebay', 'amazon', 'apple', 'microsoft', 'google',
    'netflix', 'instagram', 'facebook', 'twitter', 'bank',
    'credit', 'wallet', 'crypto', 'bitcoin', 'urgent'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
    '.top', '.club', '.online', '.site', '.fun'
]

TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'apple.com',
    'microsoft.com', 'paypal.com', 'netflix.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'github.com', 'youtube.com',
    'paytm.com', 'binance.com'
]


def analyze(url: str) -> dict:
    threats = []
    score = 0.0

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
        domain = url.split('/')[2] if '/' in url else url
        parts = domain.split('.')
        if len(parts) > 4:
            threats.append("too_many_subdomains")
            score += 0.2
    except:
        pass

    # Suspicious TLD
    try:
        domain = url.split('/')[2] if '/' in url else url
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            threats.append("suspicious_tld")
            score += 0.25
    except:
        pass

    # Suspicious keywords
    if any(word in url.lower() for word in SUSPICIOUS_KEYWORDS):
        threats.append("suspicious_keywords")
        score += 0.2

    # URL too long
    if len(url) > 100:
        threats.append("long_url")
        score += 0.1

    # Has double slash redirect
    if '//' in url.replace('https://', '').replace('http://', ''):
        threats.append("double_slash_redirect")
        score += 0.2

    # Typosquatting check
    try:
        domain = domain.replace('www.', '').lower()
        
        def normalize(s):
            if not s: return s
            res = [s[0]]
            for c in s[1:]:
                if c != res[-1]: res.append(c)
            return "".join(res)
        
        norm_domain = normalize(domain)

        for trusted in TRUSTED_DOMAINS:
            trusted_name = trusted.split('.')[0]
            trusted_full = trusted.lower()
            
            # Exact match — skip
            if domain == trusted_full or domain.endswith("." + trusted_full):
                continue

            # Brand name in domain (e.g., login-paypal.com or facebook.comn)
            if trusted_name in domain:
                threats.append(f"brand_impersonation_{trusted_name}")
                score += 0.4
                break
                
            # Repetition typo (e.g., payytm.com)
            norm_trusted = normalize(trusted_name)
            if norm_trusted in norm_domain and trusted_name not in domain:
                threats.append(f"typosquatting_{trusted_name}")
                score += 0.5
                break
    except:
        pass

    # No HTTPS
    if not url.startswith('https'):
        threats.append("no_https")
        score += 0.15

    # Excessive special characters
    special_count = sum(
        1 for c in url if not c.isalnum() and c not in ['.', '/', ':', '-', '_', '?', '=', '&']
    )
    if special_count > 10:
        threats.append("excessive_special_chars")
        score += 0.15

    return {
        "threats": threats,
        "pattern_score": round(min(score, 1.0), 4)
    }