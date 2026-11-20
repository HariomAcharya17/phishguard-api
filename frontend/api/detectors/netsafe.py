"""
Outbound requests to user-supplied URLs, with SSRF protection.

Every hop of a redirect chain is resolved and rejected if it points at a
private, loopback, link-local, multicast or reserved address (for example
cloud metadata at 169.254.169.254). Only http/https on ports 80/443/8080/8443.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests

ALLOWED_PORTS = {None, 80, 443, 8080, 8443}
USER_AGENT = "Mozilla/5.0 (compatible; PhishGuard/2.0; +https://github.com/HariomAcharya17/phishguard-api)"


class BlockedDestination(Exception):
    pass


def _public_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise BlockedDestination(f"{host} resolves to a non-public address")
        ips.append(str(ip))
    return ips


def resolve(host: str) -> list[str]:
    """Public IPs for host; [] if it does not resolve. Raises if non-public."""
    return _public_ips(host)


@dataclass
class FetchResult:
    final_url: str
    status: int | None
    hops: list[str] = field(default_factory=list)
    error: str | None = None


def follow_redirects(url: str, max_hops: int = 5, timeout: float = 4.0) -> FetchResult:
    hops = [url]
    current = url
    with requests.Session() as session:
        session.headers["User-Agent"] = USER_AGENT
        for _ in range(max_hops + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https"):
                return FetchResult(current, None, hops, "unsupported scheme")
            try:
                port = parts.port
            except ValueError:
                return FetchResult(current, None, hops, "invalid port")
            if port not in ALLOWED_PORTS:
                return FetchResult(current, None, hops, "port not allowed")
            host = parts.hostname or ""
            try:
                ipaddress.ip_address(host)
                if not ipaddress.ip_address(host).is_global:
                    return FetchResult(current, None, hops, "non-public address")
            except ValueError:
                try:
                    if not _public_ips(host):
                        return FetchResult(current, None, hops, "does not resolve")
                except BlockedDestination as e:
                    return FetchResult(current, None, hops, str(e))
            try:
                r = session.get(current, allow_redirects=False, timeout=timeout, stream=True)
                r.close()
            except requests.RequestException as e:
                return FetchResult(current, None, hops, type(e).__name__)
            if r.is_redirect and r.headers.get("location"):
                current = urljoin(current, r.headers["location"])
                hops.append(current)
                continue
            return FetchResult(current, r.status_code, hops)
    return FetchResult(current, None, hops, "too many redirects")
