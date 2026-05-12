import requests
import os
from datetime import datetime
from urllib.parse import urlparse

WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

# Trusted domains — skip WHOIS entirely, treat as established
TRUSTED_DOMAINS = {
    "facebook.com", "google.com", "youtube.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "paypal.com", "wikipedia.org", "reddit.com", "whatsapp.com",
    "paytm.com", "binance.com", "coinbase.com", "dropbox.com",
    "zoom.us", "slack.com", "notion.so", "figma.com"
}


def _get_root_domain(url: str) -> str:
    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lower().replace("www.", "")
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    except Exception:
        return url


def _check_real_ssl(url: str) -> bool:
    """
    Follow redirects and check if the FINAL resolved URL uses HTTPS.
    This avoids penalizing sites where user typed http:// but site redirects to https://.
    """
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url.startswith("https")
    except Exception:
        # Cannot determine — do NOT penalize
        return True


def analyze(url: str) -> dict:
    threats = []
    score = 0.0
    domain_age_days = None

    root_domain = _get_root_domain(url)

    # Fast-path for trusted domains
    if root_domain in TRUSTED_DOMAINS:
        return {
            "threats": [],
            "domain_score": 0.0,
            "domain_age_days": 9999  # Signal to scorer: established domain
        }

    # WHOIS lookup
    try:
        response = requests.get(
            "https://api.ip2whois.com/v2",
            params={
                "key": WHOIS_API_KEY,
                "domain": root_domain,
                "format": "json"
            },
            timeout=5
        )

        data = response.json()
        created_at = data.get("create_date", None)

        if created_at:
            try:
                created_date = datetime.strptime(created_at[:10], "%Y-%m-%d")
                domain_age_days = (datetime.now() - created_date).days

                if domain_age_days < 30:
                    threats.append("very_young_domain")
                    score += 0.4
                elif domain_age_days < 90:
                    threats.append("young_domain")
                    score += 0.2
                # Domain >= 90 days old — no penalty
            except Exception:
                # Date parse failed — treat as unknown, small penalty
                threats.append("unknown_domain_age")
                score += 0.05
        else:
            # No creation date returned — many legitimate domains redact this
            # FIX: was 0.2, reduced to 0.05 to avoid false positives
            threats.append("no_creation_date")
            score += 0.05

    except Exception:
        # FIX: WHOIS API failure ≠ suspicious domain
        # Could be rate limiting, network error, or privacy protection
        # Do NOT penalize — just note it
        threats.append("whois_lookup_failed")
        score += 0.0

    # FIX: Check REAL SSL by following redirects, not just the user-typed URL scheme
    has_ssl = _check_real_ssl(url)
    if not has_ssl:
        threats.append("no_ssl")
        score += 0.2

    return {
        "threats": threats,
        "domain_score": round(min(score, 1.0), 4),
        "domain_age_days": domain_age_days
    }