import requests
import os
from datetime import datetime

WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

def get_domain(url: str) -> str:
    try:
        domain = url.split('/')[2] if '/' in url else url
        domain = domain.replace('www.', '')
        return domain
    except:
        return url


def analyze(url: str) -> dict:
    threats = []
    score = 0.0
    domain_age_days = None

    domain = get_domain(url)

    try:
        response = requests.get(
            "https://api.ip2whois.com/v2",
            params={
                "key": WHOIS_API_KEY,
                "domain": domain,
                "format": "json"
            },
            timeout=5
        )

        data = response.json()
        # IP2WHOIS uses 'create_date' directly in the root of the JSON
        created_at = data.get("create_date", None)

        if created_at:
            try:
                # IP2WHOIS usually returns YYYY-MM-DD
                created_date = datetime.strptime(created_at[:10], "%Y-%m-%d")
                domain_age_days = (datetime.now() - created_date).days

                if domain_age_days < 30:
                    threats.append("very_young_domain")
                    score += 0.4
                elif domain_age_days < 90:
                    threats.append("young_domain")
                    score += 0.2
            except:
                threats.append("unknown_domain_age")
                score += 0.2
        else:
            threats.append("no_creation_date")
            score += 0.2

    except Exception:
        # FIX: WHOIS API failed = unknown domain, not safe
        # New phishing domains often have no WHOIS data
        threats.append("whois_lookup_failed")
        score += 0.2  # was 0.0 — silent failure

    if not url.startswith('https'):
        threats.append("no_ssl")
        score += 0.2

    return {
        "threats": threats,
        "domain_score": round(min(score, 1.0), 4),
        "domain_age_days": domain_age_days  # None is fine — scorer handles it
    }