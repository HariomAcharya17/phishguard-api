import requests
import os
import base64
from urllib.parse import urlparse

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Globally trusted domains — skip VT lookup entirely
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
        # Return last two parts: e.g. "facebook.com"
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    except Exception:
        return ""


def analyze(url: str) -> dict:
    threats = []
    score = 0.0

    # Fast-path: skip VT entirely for well-known trusted domains
    root_domain = _get_root_domain(url)
    if root_domain in TRUSTED_DOMAINS:
        return {
            "threats": [],
            "blacklist_score": 0.0
        }

    if not VIRUSTOTAL_API_KEY:
        return {
            "threats": ["blacklist_check_failed"],
            "blacklist_score": 0.0  # No key = unknown, but don't penalize
        }

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())

            malicious_ratio  = malicious  / total if total > 0 else 0
            suspicious_ratio = suspicious / total if total > 0 else 0

            # FIX: Require at least 3 engines AND >5% ratio to avoid single rogue-engine false flags
            if malicious > 2 and malicious_ratio > 0.05:
                threats.append("virustotal_malicious")
                score = min(0.9, 0.5 + (malicious * 0.04))

            elif malicious > 0:
                # 1–2 engines flagged — mildly suspicious, not a hard flag
                threats.append("virustotal_low_confidence")
                score = max(score, 0.15)

            if suspicious > 2 and suspicious_ratio > 0.05:
                threats.append("virustotal_suspicious")
                score = max(score, min(0.55, 0.25 + (suspicious * 0.04)))

        elif response.status_code == 404:
            # URL not yet in VT — submit for future scan, treat as mildly unknown
            try:
                requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    data={"url": url},
                    timeout=10
                )
            except Exception:
                pass
            score = 0.05  # Not proven safe, but not proven malicious either
            threats.append("not_in_virustotal")

        elif response.status_code == 403:
            # Invalid API key
            threats.append("blacklist_check_failed")
            score = 0.0

    except Exception:
        # Timeout or network error — unknown, do NOT penalize
        threats.append("blacklist_check_failed")
        score = 0.0

    return {
        "threats": threats,
        "blacklist_score": round(min(score, 1.0), 4)
    }