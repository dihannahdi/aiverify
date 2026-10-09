"""Fetch vendor lists, live or from the Wayback Machine, and parse them into normalized prefixes."""
import datetime
import gzip
import html
import ipaddress
import json
import re
import time
import urllib.request

try:
    import brotli
except ImportError:
    brotli = None

UA = "aiverify/1.0 (academic research; crawler verification)"
GZIP_MAGIC = b"\x1f\x8b"
PREFIX_KEYS = ("ipv4Prefix", "ipv6Prefix", "ip_prefix", "ipv6_prefix")


def get(url, tries=5, timeout=60):
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            return urllib.request.urlopen(req, timeout=timeout).read()
        except Exception:
            if attempt + 1 == tries:
                return None
            time.sleep(8 + 10 * attempt)


def _decode(raw):
    # Wayback's id_ replay returns the original bytes, which may still be gzip- or brotli-encoded.
    if raw[:2] == GZIP_MAGIC:
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    return raw


def _prefixes(data):
    out = set()
    for item in data.get("prefixes", []):
        for key in PREFIX_KEYS:
            if item.get(key):
                try:
                    out.add(str(ipaddress.ip_network(item[key].strip(), strict=False)))
                except ValueError:
                    pass
    return sorted(out) or None


def parse_json(raw):
    if not raw:
        return None
    raw = _decode(raw)
    try:
        return _prefixes(json.loads(raw))
    except Exception:
        if brotli is None:
            return None
        try:
            return _prefixes(json.loads(brotli.decompress(raw)))  # brotli has no magic bytes, so try it last
        except Exception:
            return None


def parse_amazon_html(raw):
    """Amazon publishes the list as a JSON block inside an HTML page."""
    if not raw:
        return None
    text = _decode(raw).decode("utf-8", "replace")
    for block in re.findall(r"<code[^>]*>(.*?)</code>", text, re.S):
        block = html.unescape(re.sub(r"<[^>]+>", "", block))
        if '"prefixes"' in block:
            try:
                return _prefixes(json.loads(block))
            except Exception:
                continue
    return None


PARSERS = {"json": parse_json, "amazon_html": parse_amazon_html}


def live(kind, location):
    if kind == "asn":
        now = datetime.datetime.now(datetime.timezone.utc)
        return asn_prefixes(location, now - datetime.timedelta(days=1), now)
    return PARSERS[kind](get(location))


def wayback(kind, location, sleep=4):
    """Yield (ts14, prefixes) for every distinct archived capture of the list, oldest first."""
    url = location.split("://", 1)[1]
    cdx = get(f"https://web.archive.org/cdx/search/cdx?url={url}&fl=timestamp,digest,statuscode&collapse=digest")
    rows = [line.split() for line in (cdx or b"").decode().splitlines()]
    for ts, digest, status in (r for r in rows if len(r) == 3):
        if status not in ("200", "-"):
            continue
        body = PARSERS[kind](get(f"https://web.archive.org/web/{ts}id_/{location}"))
        time.sleep(sleep)
        if body:
            yield ts, body


def _ripestat(asn, start, end):
    q = (f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
         f"&starttime={start:%Y-%m-%dT%H:%M}&endtime={end:%Y-%m-%dT%H:%M}")
    raw = get(q, timeout=180)
    return json.loads(raw)["data"]["prefixes"] if raw else None


def asn_prefixes(asn, start, end):
    """Prefixes the AS announced at any time in [start, end], as seen by RIPE RIS."""
    rows = _ripestat(asn, start, end)
    return sorted(str(ipaddress.ip_network(r["prefix"])) for r in rows) if rows else None


def asn_daily(asn, start, end):
    """Yield (YYYY-MM-DD, prefixes) for each day in [start, end): prefixes announced at any time that day."""
    rows = _ripestat(asn, start, end) or []
    spans = []
    for r in rows:
        net = str(ipaddress.ip_network(r["prefix"]))
        for tl in r["timelines"]:
            spans.append((tl["starttime"][:10], tl["endtime"][:10], net))
    d = start.date()
    while d < end.date():
        iso = d.isoformat()
        current = sorted({net for s, e, net in spans if s <= iso <= e})
        if current:
            yield iso, current
        d += datetime.timedelta(days=1)
