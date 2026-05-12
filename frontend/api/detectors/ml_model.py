import pickle
import pandas as pd
import re
from math import log2
import os
import gzip
from urllib.parse import urlparse

# =====================================================
# LOAD MODEL
# =====================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

try:
    with gzip.open(os.path.join(BASE_DIR, 'phishing_model.pkl.gz'), 'rb') as f:
        model = pickle.load(f)
    MODEL_LOADED = True
except Exception as e:
    model = None
    MODEL_LOADED = False
    print(f"[ml_model] WARNING: Could not load model: {e}")


# =====================================================
# TRUSTED DOMAINS — ML skips heuristic boosts for these
# =====================================================

TRUSTED_DOMAINS = {
    "facebook.com", "google.com", "youtube.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "paypal.com", "wikipedia.org", "reddit.com", "whatsapp.com",
    "paytm.com", "binance.com", "coinbase.com", "dropbox.com",
    "zoom.us", "slack.com", "notion.so", "figma.com"
}

# Brand names that are suspicious ONLY on foreign domains
BRAND_NAMES = [
    'paypal', 'facebook', 'instagram', 'amazon', 'apple',
    'microsoft', 'netflix', 'steam', 'google', 'twitter',
    'linkedin', 'paytm', 'binance', 'coinbase', 'ebay'
]

# Pure phishing action words — suspicious on ANY domain
PHISHING_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'signin', 'password',
    'billing', 'session', 'credential', 'auth',
    'validate', 'recover', 'reset', 'urgent'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
    '.top', '.click', '.work', '.support',
    '.loan', '.online', '.site', '.live', '.icu'
]


def _get_root_domain(url: str) -> str:
    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lower().replace("www.", "")
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    except Exception:
        return ""


def _get_hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _check_brand_on_foreign_domain(url_lower: str, root_domain: str) -> bool:
    """
    Returns True only if a brand keyword appears in a URL
    that does NOT belong to that brand.
    e.g. 'paypal-login.net' → True, 'paypal.com' → False
    """
    for brand in BRAND_NAMES:
        if brand in url_lower:
            # If root domain IS the brand's legitimate domain (exactly), skip
            # e.g. root_domain is 'paypal.com' or 'google.com'
            if root_domain == brand + ".com" or root_domain == brand + ".org" or root_domain == brand + ".net":
                continue
            return True
    return False


# =====================================================
# FEATURE EXTRACTION
# =====================================================

def extract_features(url: str) -> dict:
    features = {}
    url_lower = url.lower()
    root_domain = _get_root_domain(url)
    hostname = _get_hostname(url)
    is_trusted = root_domain in TRUSTED_DOMAINS

    # ── Basic URL Structure ──
    features['url_length']     = len(url)
    features['num_dots']       = url.count('.')
    features['num_hyphens']    = url.count('-')
    features['num_slashes']    = url.count('/')
    features['num_at']         = url.count('@')
    features['num_question']   = url.count('?')
    features['num_equal']      = url.count('=')
    features['num_underscore'] = url.count('_')
    features['num_percent']    = url.count('%')

    # ── IP Address Detection ──
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0

    # ── HTTPS ──
    # FIX: Use resolved hostname SSL check instead of raw URL scheme.
    # If user typed http:// but site redirects to https, don't penalize.
    # We approximate this by trusting known-safe domains have SSL.
    if is_trusted:
        features['has_https'] = 1  # Trusted domains always have SSL
    else:
        features['has_https'] = 1 if url.startswith('https') else 0

    # ── URL Entropy ──
    if len(url) > 0:
        prob = [float(url.count(c)) / len(url) for c in set(url)]
        features['entropy'] = -sum(p * log2(p) for p in prob if p > 0)
    else:
        features['entropy'] = 0.0

    # ── Phishing Action Keywords (safe on any domain) ──
    phishing_hits = sum(word in url_lower for word in PHISHING_KEYWORDS)
    features['has_suspicious_keyword'] = 1 if phishing_hits > 0 else 0
    features['danger_keyword_count']   = phishing_hits

    # ── Suspicious TLDs ──
    features['suspicious_tld'] = 1 if any(
        hostname.endswith(tld) for tld in SUSPICIOUS_TLDS
    ) else 0

    # ── Brand Impersonation ──
    # FIX: Only flag if brand appears on a FOREIGN domain, not the brand's own domain
    features['brand_impersonation'] = (
        0 if is_trusted
        else (1 if _check_brand_on_foreign_domain(url_lower, root_domain) else 0)
    )

    # ── Excessive Hyphens ──
    features['many_hyphens'] = 1 if url.count('-') >= 3 else 0

    # ── Domain Length ──
    try:
        domain = url.split('/')[2] if '/' in url else url
        features['domain_length'] = len(domain)
    except Exception:
        features['domain_length'] = 0

    # ── Subdomains ──
    try:
        domain = url.split('/')[2] if '/' in url else url
        parts = domain.split('.')
        features['num_subdomains'] = len(parts) - 2 if len(parts) > 2 else 0
    except Exception:
        features['num_subdomains'] = 0

    # ── Digits ──
    features['num_digits'] = sum(c.isdigit() for c in url)

    # ── Special Characters ──
    features['num_special'] = sum(
        1 for c in url
        if not c.isalnum() and c not in ['.', '/', ':', '-', '_']
    )

    # ── Long URL ──
    features['long_url'] = 1 if len(url) > 100 else 0

    return features


# =====================================================
# PREDICTION
# =====================================================

def predict(url: str) -> dict:
    root_domain = _get_root_domain(url)
    is_trusted = root_domain in TRUSTED_DOMAINS



    # Model not loaded — return neutral 0.0, not 0.5
    # scorer will rely more on other layers
    if not MODEL_LOADED or model is None:
        return {
            "ml_score": 0.0,
            "is_phishing": False,
            "error": "Model not loaded"
        }

    try:
        features = extract_features(url)
        X = pd.DataFrame([features])

        proba = model.predict_proba(X)[0]
        classes = list(model.classes_)

        # FIX: Explicitly get phishing class (1) probability
        if 1 in classes:
            phishing_idx = classes.index(1)
        else:
            phishing_idx = 1  # fallback

        phishing_probability = float(proba[phishing_idx])
        predicted_class = model.predict(X)[0]
        is_phishing = bool(predicted_class == 1)

        # FIX: Removed heuristic boosts here — scorer.py already applies
        # escalation rules for suspicious_tld, brand_impersonation, hyphens.
        # Double-counting inflated scores significantly.
        final_score = min(phishing_probability, 1.0)

        return {
            "ml_score": round(final_score, 4),
            "is_phishing": is_phishing,
            "features": features
        }

    except Exception as e:
        # FIX: Return 0.0 on failure, not 0.5
        # A broken model should not push scores up
        return {
            "ml_score": 0.0,
            "is_phishing": False,
            "error": str(e)
        }