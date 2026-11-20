"""Offline detection tests: URL rules + hostname model, no network."""
import pytest

from detectors import scorer
from detectors.urlparts import InvalidURL, parse

LEGIT = [
    "https://www.google.com",
    "google.com",
    "https://github.com/vercel/next.js",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://amazon.in",
    "https://www.amazon.co.uk/gp/css/order-history",
    "https://www.hdfcbank.com",
    "https://www.sbi.co.in/web/personal-banking",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://stackoverflow.com/questions/123/how-to",
    "https://accounts.google.com/signin/v2/identifier",
    "https://www.paypal.com/signin",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://mail.yahoo.com",
    "https://www.flipkart.com/account/login",
    "https://news.ycombinator.com",
    "https://www.irctc.co.in/nget/train-search",
    "https://myblog.github.io/posts/hello",
    "https://www.thehindu.com/news/national/",
    "https://zerodha.com",
    "https://medium.com/@someone/my-post-123",
    "https://www.icicibank.com/personal-banking",
    "https://www.apple.com/in/iphone/",
    "https://steamcommunity.com/id/someone",
    "https://www.bbc.com/news",
    "https://www.nytimes.com/section/technology",
]

PHISHING = [
    "http://paypal-login-verify.xyz/account/update",
    "https://secure-chase-verify.tk/login",
    "https://apple.com-id-verify.support/signin",
    "http://paypa1.com/webscr?cmd=_login",
    "https://www.g00gle.com",
    "https://xn--pple-43d.com",
    "https://microsoft-office365-login.web.app/",
    "https://sbi-kyc-update.online/ekyc",
    "https://hdfcbank-netbanking.com.verify-user.xyz",
    "http://https-www-paypal-com.ngrok-free.app/login",
    "https://amaz0n-refund.com/claim",
    "https://metamask-usa-walet.godaddysites.com/",
    "https://caseid1008934573489573489.firebaseapp.com/",
    "https://www.google.com@evil.example/login",
    "http://3232235777/login",
    "https://faceb00k.com/login",
    "https://netflix-billing-update.com/account",
    "https://exchangeportal-owa-auth-login-aspx-hyttgygh.infura-ipfs.io/ipfs/qm/index1/",
    "http://203.0.113.50/paypal/webscr/login.php",
    "https://instagram-verify-badge.com/form",
    "https://www.paypal.com.secure-login.xyz/",
    "javascript:alert(document.cookie)",
]


@pytest.mark.parametrize("url", LEGIT)
def test_legitimate_urls_are_safe(url):
    r = scorer.analyze(url)
    assert r["risk_level"] in ("safe", "low"), (url, r["risk_score"], [s["id"] for s in r["signals"]])
    assert r["risk_score"] < 0.4


@pytest.mark.parametrize("url", PHISHING)
def test_phishing_urls_score_high(url):
    r = scorer.analyze(url)
    assert r["risk_level"] in ("high", "critical"), (url, r["risk_score"], [s["id"] for s in r["signals"]])
    assert not r["is_safe"]


def test_lookalike_not_double_counted():
    ids = [s["id"] for s in scorer.analyze("http://paypa1.com/")["signals"]]
    assert "lookalike_domain" in ids
    assert "brand_in_domain" not in ids


def test_brand_in_subdomain_points_to_real_owner():
    r = scorer.analyze("https://paypal.com.account-review.top/")
    sig = next(s for s in r["signals"] if s["id"] == "brand_in_subdomain")
    assert "account-review.top" in sig["detail"]


def test_obfuscated_ip_detected():
    ids = [s["id"] for s in scorer.analyze("http://0xC0A80101/")["signals"]]
    assert "obfuscated_ip" in ids


def test_response_shape_is_backwards_compatible():
    r = scorer.analyze("https://example.com")
    for key in ("url", "is_safe", "risk_score", "risk_level", "threats_detected", "ml_score",
                "domain_age_days", "recommendation", "breakdown"):
        assert key in r
    assert set(r["breakdown"]) == {"blacklist", "pattern", "domain", "ml"}
    for layer in r["breakdown"].values():
        assert {"score", "threats", "description"} <= set(layer)


def test_risk_level_matches_is_safe():
    for url in LEGIT[:5] + PHISHING[:5]:
        r = scorer.analyze(url)
        assert r["is_safe"] == (r["risk_level"] == "safe")


@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.com", "http://", "http://exa mple.com", "x" * 3000, "http://example.com:99999"])
def test_invalid_input_rejected(bad):
    with pytest.raises(InvalidURL):
        parse(bad)


def test_parse_handles_idn_and_private_suffix():
    p = parse("https://login.xn--pple-43d.com/a")
    assert p.registrable == "xn--pple-43d.com"
    assert "а" in p.host_unicode  # Cyrillic a
    q = parse("https://evil.firebaseapp.com")
    assert q.registrable == "evil.firebaseapp.com" and q.suffix_is_private


def test_lookalike_redirecting_to_official_site_is_damped(monkeypatch):
    from detectors import domain, reputation
    monkeypatch.setattr(domain, "dns_and_redirects", lambda p: ([], {"resolves": True, "final_url": "https://www.paypal.com/in/home"}))
    monkeypatch.setattr(domain, "domain_age", lambda p: ([], {"status": "ok"}))
    for name in ("virustotal", "safe_browsing", "openphish"):
        monkeypatch.setattr(reputation, name, lambda p, *a: ([], {"status": "ok"}))
    r = scorer.analyze("http://paypa1.com/", network=True)
    ids = {s["id"]: s for s in r["signals"]}
    assert "redirects_to_official" in ids
    assert ids["lookalike_domain"]["weight"] < 0.2
    assert r["risk_level"] in ("safe", "low")
