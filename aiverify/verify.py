"""Verify a claimed crawler request against the list history, and by forward-confirmed reverse DNS."""
import datetime
import ipaddress
import socket

from . import fetch, store as store_mod
from .ranges import RangeSet
from .vendors import CLASS_LIST, RDNS_SUFFIXES, classify

# Tolerance window per list in days, chosen at the knee of the tolerance curve in the historical analysis.
DEFAULT_TOLERANCE = {"oai-searchbot": 30, "chatgpt-user": 90}
CLOUDFLARE_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")


def cloudflare_prefixes():
    text = "\n".join((fetch.get(u) or b"").decode() for u in CLOUDFLARE_URLS)
    prefixes = text.split()
    if not prefixes:
        raise RuntimeError("could not fetch Cloudflare ranges")
    return prefixes


def cloudflare_ranges():
    return RangeSet(cloudflare_prefixes())


def client_ip(peer, cf_header, cloudflare):
    """The real client address. CF-Connecting-IP is trusted only when the peer itself is a Cloudflare IP."""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return None, "bad_ip"
    if addr in cloudflare:
        try:
            return ipaddress.ip_address(cf_header), "via_cloudflare"
        except ValueError:
            return None, "proxy"
    return addr, "direct"


class Verifier:
    def __init__(self, store, tolerance=None):
        self.lists = store_mod.all_versioned(store)
        self.tolerance = dict(DEFAULT_TOLERANCE, **(tolerance or {}))

    def check(self, addr, user_agent, day):
        """Return (crawler class or None, verdict). day is a date ordinal."""
        cls = classify(user_agent)
        if cls is None:
            return None, "not_crawler"
        name = CLASS_LIST.get(cls)
        if name is None or name not in self.lists:
            return cls, "unverifiable"
        return cls, self.lists[name].verdict(addr, day, self.tolerance.get(name, 0))


def today():
    return datetime.datetime.now(datetime.timezone.utc).date().toordinal()


def fcrdns(ip, cls):
    """Forward-confirmed reverse DNS with the vendor's official suffixes.

    Returns (result, provider) where result is pass, wrong_domain, forward_mismatch or no_ptr, and provider is
    the registered domain of the PTR name (two labels) so that no full hostname has to be stored."""
    suffixes = RDNS_SUFFIXES[cls]
    try:
        host = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except OSError:
        return "no_ptr", "-"
    provider = ".".join(host.split(".")[-2:])
    if not host.endswith(suffixes):
        return "wrong_domain", provider
    try:
        forward = {ipaddress.ip_address(info[4][0].split("%")[0]) for info in socket.getaddrinfo(host, None)}
    except OSError:
        return "forward_mismatch", provider
    return ("pass" if ipaddress.ip_address(ip) in forward else "forward_mismatch"), provider
