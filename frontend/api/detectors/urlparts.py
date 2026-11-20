"""
URL parsing shared by every detector.

Everything downstream works on a ParsedURL so that hostname handling
(IDN decoding, IP detection, registrable-domain extraction) happens once
and consistently.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

import tldextract

# Offline extractor: uses the public suffix list snapshot bundled with the
# package (no network fetch, no disk cache). Private suffixes are included so
# that "evil.firebaseapp.com" is treated as its own site, not as firebaseapp.com.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    include_psl_private_domains=True,
)

MAX_URL_LENGTH = 2048


class InvalidURL(ValueError):
    """Raised when input cannot be analyzed as a web URL."""


@dataclass
class ParsedURL:
    original: str           # what the user submitted (trimmed)
    url: str                # normalized, always has a scheme
    scheme: str
    host: str               # lowercase, IDNA (punycode) form
    host_unicode: str       # decoded form for display / homoglyph checks
    port: int | None
    path: str
    query: str
    userinfo: str           # anything before '@' in the authority
    subdomain: str          # e.g. "login.secure" in login.secure.example.com
    domain: str             # e.g. "example"
    suffix: str             # e.g. "com", "co.uk", "github.io"
    registrable: str        # e.g. "example.com" ("" for IPs)
    suffix_is_private: bool # suffix is a hosting platform (github.io, web.app…)
    ip: ipaddress._BaseAddress | None = None
    scheme_was_added: bool = False
    labels: list[str] = field(default_factory=list)

    @property
    def is_ip(self) -> bool:
        return self.ip is not None

    @property
    def subdomain_labels(self) -> list[str]:
        return [p for p in self.subdomain.split(".") if p and p != "www"]


def _parse_ip(host: str) -> ipaddress._BaseAddress | None:
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Obfuscated IPv4 forms browsers still accept: 3232235777, 0xC0A80101
    if re.fullmatch(r"\d{8,10}", h):
        n = int(h)
        if n < 2**32:
            return ipaddress.IPv4Address(n)
    if re.fullmatch(r"0x[0-9a-f]{1,8}", h):
        return ipaddress.IPv4Address(int(h, 16))
    if re.fullmatch(r"(0x[0-9a-f]+|0[0-7]*|\d+)(\.(0x[0-9a-f]+|0[0-7]*|\d+)){3}", h):
        try:
            parts = [int(p, 16) if p.startswith("0x") else int(p, 8) if p.startswith("0") and len(p) > 1 else int(p) for p in h.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return ipaddress.IPv4Address(".".join(map(str, parts)))
        except ValueError:
            pass
    return None


def _to_idna(host: str) -> tuple[str, str]:
    """Return (ascii_host, unicode_host)."""
    host = host.rstrip(".").lower()
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host.encode("ascii", "ignore").decode() or host
    try:
        unicode_host = ascii_host.encode("ascii").decode("idna")
    except UnicodeError:
        unicode_host = host
    return ascii_host, unicode_host


def parse(raw: str) -> ParsedURL:
    if raw is None:
        raise InvalidURL("No URL provided.")
    original = raw.strip()
    if not original:
        raise InvalidURL("No URL provided.")
    if len(original) > MAX_URL_LENGTH:
        raise InvalidURL(f"URL is longer than {MAX_URL_LENGTH} characters.")
    if any(c in original for c in "\r\n\t") or " " in original.split("?")[0]:
        raise InvalidURL("URL contains whitespace.")

    lowered = original.lower()
    if lowered.startswith(("javascript:", "data:", "vbscript:", "file:")):
        scheme = lowered.split(":", 1)[0]
        return ParsedURL(
            original=original, url=original, scheme=scheme, host="", host_unicode="",
            port=None, path="", query="", userinfo="", subdomain="", domain="",
            suffix="", registrable="", suffix_is_private=False,
        )

    added = False
    url = original
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
        added = True

    try:
        parts = urlsplit(url)
    except ValueError as e:
        raise InvalidURL("URL could not be parsed.") from e

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURL("Only http and https URLs can be checked.")

    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, netloc = netloc.rsplit("@", 1)

    try:
        port = parts.port
    except ValueError:
        raise InvalidURL("URL has an invalid port.")

    host_raw = parts.hostname or ""
    if not host_raw:
        raise InvalidURL("URL has no hostname.")
    host_raw = unquote(host_raw)

    ip = _parse_ip(host_raw)
    if ip is not None:
        host = host_unicode = str(ip)
        sub = dom = suf = reg = ""
        private = False
    else:
        host, host_unicode = _to_idna(host_raw)
        if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host:
            raise InvalidURL("URL has an invalid hostname.")
        ext = _extract(host)
        sub, dom, suf = ext.subdomain, ext.domain, ext.suffix
        reg = f"{dom}.{suf}" if dom and suf else ""
        private = bool(getattr(ext, "is_private", False))

    return ParsedURL(
        original=original,
        url=url,
        scheme=scheme,
        host=host,
        host_unicode=host_unicode,
        port=port,
        path=parts.path or "/",
        query=parts.query,
        userinfo=userinfo,
        subdomain=sub,
        domain=dom,
        suffix=suf,
        registrable=reg,
        suffix_is_private=private,
        ip=ip,
        scheme_was_added=added,
        labels=host.split(".") if host else [],
    )
