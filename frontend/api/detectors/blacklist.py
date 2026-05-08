import requests
import os
import base64

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def analyze(url: str) -> dict:
    threats = []
    score = 0.0

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

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                threats.append("virustotal_malicious")
                score = min(0.9, 0.5 + (malicious * 0.05))

            if suspicious > 0:
                threats.append("virustotal_suspicious")
                score = max(score, min(0.6, 0.3 + (suspicious * 0.05)))

        elif response.status_code == 404:
            # FIX: URL unknown to VT = not proven safe, treat as mildly suspicious
            # Submit for future scanning but don't give a free 0.0
            try:
                requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    data={"url": url},
                    timeout=10
                )
            except:
                pass
            score = 0.1  # FIX: was 0.0
            threats.append("not_in_virustotal")

    except Exception:
        # FIX: timeout or API error = unknown, not safe
        score = 0.1
        threats.append("blacklist_check_failed")

    return {
        "threats": threats,
        "blacklist_score": round(min(score, 1.0), 4)
    }