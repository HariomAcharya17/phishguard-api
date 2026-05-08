import pickle
import pandas as pd
import re
from math import log2
import os
import gzip


# =====================================================
# LOAD MODEL
# =====================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

with gzip.open(os.path.join(BASE_DIR, 'phishing_model.pkl.gz'), 'rb') as f:
    model = pickle.load(f)


# =====================================================
# FEATURE EXTRACTION
# =====================================================

def extract_features(url: str) -> dict:

    features = {}

    url_lower = url.lower()

    # ---------------------------------
    # Basic URL Structure
    # ---------------------------------

    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')
    features['num_question'] = url.count('?')
    features['num_equal'] = url.count('=')
    features['num_underscore'] = url.count('_')
    features['num_percent'] = url.count('%')

    # ---------------------------------
    # IP Address Detection
    # ---------------------------------

    features['has_ip'] = 1 if re.search(
        r'\d+\.\d+\.\d+\.\d+',
        url
    ) else 0

    # ---------------------------------
    # HTTPS
    # ---------------------------------

    features['has_https'] = 1 if url.startswith('https') else 0

    # ---------------------------------
    # URL Entropy
    # ---------------------------------

    prob = [float(url.count(c)) / len(url) for c in set(url)]

    features['entropy'] = -sum(
        p * log2(p) for p in prob
    )

    # ---------------------------------
    # Suspicious Keywords
    # ---------------------------------

    suspicious_keywords = [
        'login',
        'verify',
        'secure',
        'account',
        'update',
        'banking',
        'confirm',
        'paypal',
        'signin',
        'password',
        'ebay',
        'amazon',
        'facebook',
        'instagram',
        'microsoft',
        'netflix',
        'billing',
        'session'
    ]

    keyword_matches = sum(
        word in url_lower for word in suspicious_keywords
    )

    features['has_suspicious_keyword'] = (
        1 if keyword_matches > 0 else 0
    )

    features['danger_keyword_count'] = keyword_matches

    # ---------------------------------
    # Suspicious TLDs
    # ---------------------------------

    suspicious_tlds = [
        '.tk',
        '.ml',
        '.ga',
        '.cf',
        '.gq',
        '.xyz',
        '.top',
        '.click',
        '.work',
        '.support'
    ]

    features['suspicious_tld'] = 1 if any(
        url_lower.endswith(tld)
        for tld in suspicious_tlds
    ) else 0

    # ---------------------------------
    # Brand Impersonation
    # ---------------------------------

    brands = [
        'paypal',
        'facebook',
        'instagram',
        'amazon',
        'apple',
        'microsoft',
        'netflix',
        'bank',
        'steam'
    ]

    features['brand_impersonation'] = 1 if any(
        brand in url_lower
        for brand in brands
    ) else 0

    # ---------------------------------
    # Excessive Hyphens
    # ---------------------------------

    features['many_hyphens'] = (
        1 if url.count('-') >= 3 else 0
    )

    # ---------------------------------
    # Domain Length
    # ---------------------------------

    try:
        domain = url.split('/')[2] if '/' in url else url
        features['domain_length'] = len(domain)
    except:
        features['domain_length'] = 0

    # ---------------------------------
    # Subdomains
    # ---------------------------------

    try:
        domain = url.split('/')[2] if '/' in url else url
        parts = domain.split('.')

        features['num_subdomains'] = (
            len(parts) - 2 if len(parts) > 2 else 0
        )

    except:
        features['num_subdomains'] = 0

    # ---------------------------------
    # Digits
    # ---------------------------------

    features['num_digits'] = sum(
        c.isdigit() for c in url
    )

    # ---------------------------------
    # Special Characters
    # ---------------------------------

    features['num_special'] = sum(
        1 for c in url
        if not c.isalnum()
        and c not in ['.', '/', ':', '-', '_']
    )

    # ---------------------------------
    # Long URL
    # ---------------------------------

    features['long_url'] = (
        1 if len(url) > 100 else 0
    )

    return features


# =====================================================
# PREDICTION
# =====================================================
def predict(url: str) -> dict:
    try:
        features = extract_features(url)
        X = pd.DataFrame([features])

        proba = model.predict_proba(X)[0]
        classes = list(model.classes_)

        # FIX: explicitly get phishing class probability
        # not just max() which could be the safe class
        if 1 in classes:
            phishing_idx = classes.index(1)
        else:
            phishing_idx = 1  # fallback assumption

        phishing_probability = float(proba[phishing_idx])

        predicted_class = model.predict(X)[0]
        is_phishing = predicted_class == 1

        heuristic_boost = 0
        if features['suspicious_tld']:
            heuristic_boost += 0.10
        if features['brand_impersonation']:
            heuristic_boost += 0.10
        if features['many_hyphens']:
            heuristic_boost += 0.05
        if features['danger_keyword_count'] >= 2:
            heuristic_boost += 0.10

        final_score = min(phishing_probability + heuristic_boost, 1.0)

        return {
            "ml_score": round(float(final_score), 4),
            "is_phishing": is_phishing,
            "features": features
        }

    except Exception as e:
        # FIX: don't return 0.0 on failure — return neutral 0.5
        # so it doesn't silently drag the final score down
        return {
            "ml_score": 0.5,
            "is_phishing": False,
            "error": str(e)
        }