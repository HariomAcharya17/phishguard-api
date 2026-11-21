"""
Brand and domain reference data.

BRANDS maps a brand token (what attackers put in hostnames) to the
registrable domains the brand actually owns. A token appearing in a host
whose registrable domain is NOT in that set is treated as impersonation.
"""
from __future__ import annotations

BRANDS: dict[str, set[str]] = {
    # Global tech / accounts
    "google": {"google.com", "google.co.in", "google.co.uk", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com", "goo.gl", "g.co", "withgoogle.com", "googleusercontent.com", "blogger.com", "googlesyndication.com", "googleadservices.com", "googletagmanager.com", "google-analytics.com", "googlevideo.com", "doubleclick.net", "google", "googleblog.com", "googlesource.com", "googledomains.com", "google.de", "google.fr", "google.co.jp", "google.com.br", "google.ca", "google.com.au", "googlemail.com"},
    "gmail": {"gmail.com", "google.com"},
    "youtube": {"youtube.com", "youtu.be", "google.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "azure.com", "windows.net", "bing.com", "msn.com", "sharepoint.com", "skype.com", "xbox.com", "aka.ms", "microsoft", "office365.us", "microsoftstore.com", "msftauth.net", "msauth.net", "live.net", "onestore.ms"},
    "office365": {"office.com", "office365.com", "office365.us", "microsoft.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "onedrive": {"onedrive.com", "live.com", "microsoft.com", "sharepoint.com"},
    "sharepoint": {"sharepoint.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com", "apple.co", "itunes.com", "me.com", "apple-cloudkit.com", "apple-dns.net", "applemusic.com", "mzstatic.com", "cdn-apple.com", "apple.news"},
    "icloud": {"icloud.com", "apple.com"},
    "itunes": {"itunes.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amazon.co.jp", "amazon.com.au", "amazon.com.br", "amazon.ae", "amazon.sg", "amazonaws.com", "amazon.jobs", "amzn.to", "aws.amazon.com", "primevideo.com", "ssl-images-amazon.com", "media-amazon.com", "amazon-adsystem.com", "amazontrust.com", "amazonpay.in", "amazon.dev"},
    "aws": {"amazonaws.com", "amazon.com", "aws.com"},
    "netflix": {"netflix.com", "nflxext.com", "nflximg.net"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "facebook.net", "meta.com", "fbcdn.net", "fbsbx.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "meta": {"meta.com", "facebook.com"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "github": {"github.com", "github.io", "githubusercontent.com"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com", "db.tt"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com", "adobelogin.com", "adobe.io"},
    "zoom": {"zoom.us", "zoom.com"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "steamcommunity": {"steamcommunity.com"},
    "discord": {"discord.com", "discord.gg", "discordapp.com"},
    "telegram": {"telegram.org", "t.me"},
    "yahoo": {"yahoo.com", "yahoo.co.jp", "yimg.com"},
    "ebay": {"ebay.com", "ebay.in", "ebay.co.uk", "ebay.de"},
    "spotify": {"spotify.com"},
    # Payments / finance (global)
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "stripe": {"stripe.com", "stripe.network", "stripe.dev"},
    "visa": {"visa.com", "visa.co.in"},
    "mastercard": {"mastercard.com", "mastercard.co.in"},
    "americanexpress": {"americanexpress.com"},
    "amex": {"americanexpress.com", "amex.com"},
    "chase": {"chase.com", "jpmorgan.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citi.com", "citibank.com", "citibank.co.in"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.co.in"},
    "barclays": {"barclays.com", "barclays.co.uk"},
    # Crypto
    "binance": {"binance.com", "binance.us"},
    "coinbase": {"coinbase.com"},
    "kraken": {"kraken.com"},
    "metamask": {"metamask.io"},
    "blockchain": {"blockchain.com"},
    "trustwallet": {"trustwallet.com"},
    "ledger": {"ledger.com"},
    # India
    "paytm": {"paytm.com", "paytm.in", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "gpay": {"google.com"},
    "bhim": {"bhimupi.org.in", "npci.org.in"},
    "npci": {"npci.org.in"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi"},
    "onlinesbi": {"onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcsec.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icici": {"icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com", "axis.bank.in"},
    "kotak": {"kotak.com", "kotaksecurities.com"},
    "pnb": {"pnbindia.in", "netpnb.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "incometax": {"incometax.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "uidai": {"uidai.gov.in"},
    "epfo": {"epfindia.gov.in"},
    # Gaming, shopping and other heavily phished brands
    "roblox": {"roblox.com", "rbxcdn.com", "roblox.qq.com", "rbx.com"},
    "epicgames": {"epicgames.com", "unrealengine.com"},
    "playstation": {"playstation.com", "playstation.net", "sony.com"},
    "nintendo": {"nintendo.com", "nintendo.net", "nintendo.co.jp"},
    "minecraft": {"minecraft.net", "mojang.com"},
    "allegro": {"allegro.pl", "allegrolokalnie.pl", "allegro.cz", "allegro.sk"},
    "mercadolibre": {"mercadolibre.com", "mercadolibre.com.ar", "mercadolibre.com.mx", "mercadolivre.com.br"},
    "booking": {"booking.com", "bstatic.com"},
    "airbnb": {"airbnb.com", "airbnb.co.in", "airbnb.co.uk"},
    "wetransfer": {"wetransfer.com", "we.tl"},
    "tiktok": {"tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com"},
    "snapchat": {"snapchat.com", "snap.com"},
    "verizon": {"verizon.com", "verizonwireless.com"},
    "xfinity": {"xfinity.com", "comcast.com", "comcast.net"},
    "vodafone": {"vodafone.com", "vodafone.in", "vodafone.co.uk", "vodafone.de"},
    "airtel": {"airtel.in", "airtel.com"},
    "santander": {"santander.com", "santander.co.uk", "santander.com.br"},
    "bradesco": {"bradesco.com.br"},
    "nubank": {"nubank.com.br"},
    "itau": {"itau.com.br"},
    "royalmail": {"royalmail.com"},
    "shopify": {"shopify.com", "myshopify.com", "shopifycdn.com", "shopifysvc.com"},
    "outlookweb": {"outlook.com", "office.com"},
    # Shipping (common SMS lures)
    "dhl": {"dhl.com", "dhl.de", "dhl.co.in"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "indiapost": {"indiapost.gov.in"},
}

# Short tokens that are ordinary words or substrings of many unrelated domains.
# They only count when they form a whole hostname label or a hyphen-separated part.
WHOLE_WORD_ONLY = {"sbi", "pnb", "dhl", "aws", "visa", "amex", "meta", "zoom", "chase", "ledger", "steam", "apple", "gpay", "bhim", "kotak", "hsbc", "icici", "hdfc", "npci", "usps", "itau", "booking", "airtel", "outlook", "blockchain", "allegro"}

# Brand names that are also common words: "cloud" vs icloud, "mail" vs gmail.
# Excluded from look-alike matching to avoid flagging ordinary domains.
_LOOKALIKE_EXCLUDE = {"icloud", "gmail", "itunes", "booking", "outlook", "outlookweb", "office365", "blockchain", "onlinesbi", "hdfcbank", "icicibank", "steamcommunity", "incometax", "indiapost", "royalmail", "mastercard", "americanexpress", "bankofamerica", "wellsfargo", "trustwallet", "playstation", "mercadolibre", "sharepoint", "wetransfer"}

# Brands long and distinctive enough for look-alike (typosquat) matching.
TYPOSQUAT_TARGETS = sorted({b for b in BRANDS if len(b) >= 5 and b not in WHOLE_WORD_ONLY and b not in _LOOKALIKE_EXCLUDE} | {"apple", "paypal", "roblox", "google"})

ALL_OFFICIAL = set().union(*BRANDS.values())

# Widely used sites with a long safe history. Matching the registrable domain
# lowers the influence of lexical heuristics and the ML model; reputation
# feeds (VirusTotal, OpenPhish) still apply.
WELL_KNOWN = ALL_OFFICIAL | {
    "wikipedia.org", "wikimedia.org", "reddit.com", "stackoverflow.com", "stackexchange.com",
    "python.org", "mozilla.org", "w3.org", "npmjs.com", "pypi.org", "medium.com", "notion.so",
    "slack.com", "figma.com", "canva.com", "vercel.com", "netlify.com", "cloudflare.com",
    "atlassian.com", "gitlab.com", "bitbucket.org", "salesforce.com", "oracle.com", "ibm.com",
    "nytimes.com", "bbc.co.uk", "bbc.com", "cnn.com", "theguardian.com", "reuters.com",
    "thehindu.com", "ndtv.com", "timesofindia.com", "indiatimes.com", "hindustantimes.com",
    "zomato.com", "swiggy.com", "myntra.com", "naukri.com", "makemytrip.com", "uber.com",
    "airbnb.com", "booking.com", "tripadvisor.com", "quora.com", "pinterest.com", "tiktok.com",
    "snapchat.com", "twitch.tv", "imdb.com", "duckduckgo.com", "bing.com", "openai.com",
    "anthropic.com", "claude.ai", "chatgpt.com", "gov.in", "nic.in",
}

# Services that host user content under their own domain. Phishing pages are
# often hosted here, so being on one of these is NOT a sign of safety.
CONTENT_HOSTING_PREFIXES = (
    "docs.google.com/forms", "forms.gle", "sites.google.com", "drive.google.com",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "forms.office.com",
    "1drv.ms", "onedrive.live.com", "sharepoint.com", "dropbox.com/s/", "dl.dropboxusercontent.com",
    "gitbook.io",
)

# Free hosting, site builders, tunnels and dynamic DNS. Mostly private
# public-suffix entries, so the registrable domain is the customer's site.
FREE_HOSTING = {
    "firebaseapp.com", "web.app", "appspot.com", "pages.dev", "workers.dev", "netlify.app",
    "vercel.app", "herokuapp.com", "onrender.com", "glitch.me", "repl.co", "replit.app",
    "replit.dev", "surge.sh", "github.io", "gitlab.io", "000webhostapp.com", "weebly.com",
    "weeblysite.com", "wixsite.com", "wix.com", "godaddysites.com", "square.site", "webflow.io",
    "blogspot.com", "wordpress.com", "framer.app", "framer.website", "notion.site", "carrd.co",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net",
    "duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net", "myftp.org",
    "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "infura-ipfs.io", "fleek.co", "on.fleek.co",
    "azurewebsites.net", "cloudfront.net", "r2.dev", "backblazeb2.com", "start.page",
    "mystrikingly.com", "jimdosite.com", "yolasite.com", "site123.me", "webnode.page",
    "typedream.app", "teachable.com", "myshopify.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "bit.do", "s.id", "v.gd", "lnkd.in",
    "qrco.de", "short.io", "bl.ink", "shorte.st", "adf.ly", "tiny.one", "urlz.fr", "clck.ru",
    "u.to", "x.co", "trib.al", "soo.gd", "shrtco.de", "2u.pm", "linktr.ee",
}

# Most-abused TLDs by phishing share (Interisle / Spamhaus reports).
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site", "fun", "click",
    "work", "loan", "live", "icu", "buzz", "rest", "cyou", "monster", "cfd", "sbs", "quest",
    "bond", "lol", "mom", "support", "help", "sbs", "autos", "beauty", "hair", "skin", "boats",
    "pw", "cc", "ws", "su", "zip", "mov", "today", "shop", "store", "win", "bid", "vip", "kim",
    "country", "stream", "download", "racing", "review", "date", "faith", "accountant", "cricket",
    "science", "party", "gdn", "men", "webcam", "trade",
}

# Words that show up in credential-harvesting URLs.
CREDENTIAL_WORDS = {
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification", "validate",
    "confirm", "account", "accounts", "update", "secure", "security", "password", "passwd",
    "credential", "auth", "authenticate", "billing", "invoice", "payment", "wallet", "unlock",
    "suspend", "suspended", "locked", "restore", "recover", "recovery", "reset", "kyc",
    "ekyc", "refund", "reward", "bonus", "claim", "prize", "gift", "airdrop", "seed",
    "webscr", "cmd=_login", "otp", "pan-card", "aadhar", "blocked", "expire", "expired",
    "urgent", "alert", "support", "helpdesk", "customer-care", "free",
}

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".apk", ".xapk",
    ".dmg", ".pkg", ".iso", ".img", ".hta", ".lnk", ".wsf", ".zip", ".rar", ".7z",
}

# Characters attackers swap in look-alike domains (after IDN decoding).
CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a",
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ν": "v",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ε": "e", "κ": "k", "ι": "i", "η": "n",
    # Latin look-alikes
    "ı": "i", "ł": "l", "ŀ": "l", "ƚ": "l", "ɑ": "a", "ǝ": "e", "ⅼ": "l", "ｍ": "m",
    "à": "a", "á": "a", "â": "a", "ä": "a", "å": "a", "ã": "a", "è": "e", "é": "e", "ê": "e",
    "ë": "e", "ì": "i", "í": "i", "î": "i", "ï": "i", "ò": "o", "ó": "o", "ô": "o", "ö": "o",
    "õ": "o", "ù": "u", "ú": "u", "û": "u", "ü": "u", "ç": "c", "ñ": "n", "ý": "y", "ÿ": "y",
}
MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))


def deconfuse(text: str) -> str:
    """Map look-alike characters to the ASCII letters they imitate."""
    out = "".join(CONFUSABLES.get(c, c) for c in text.lower())
    return out


def deconfuse_multi(text: str) -> str:
    for a, b in MULTI_CHAR_CONFUSABLES:
        text = text.replace(a, b)
    return text


def is_official(brand: str, registrable: str, host: str) -> bool:
    official = BRANDS.get(brand, set())
    if registrable in official:
        return True
    # Entries like "aws.amazon.com" or a bare TLD-brand like "sbi"
    return any(host == d or host.endswith("." + d) for d in official)
