"""Classify archived captures that did not yield a usable IP list, so exclusions are documented."""
import gzip
import json
import sys
import time
import urllib.request
from collections import Counter

STORE = json.load(open(sys.argv[1]))
URLS = {
    "gptbot": "openai.com/gptbot.json",
    "oai-searchbot": "openai.com/searchbot.json",
    "chatgpt-user": "openai.com/chatgpt-user.json",
    "perplexitybot": "www.perplexity.ai/perplexitybot.json",
    "googlebot": "developers.google.com/static/search/apis/ipranges/googlebot.json",
}
GZIP_MAGIC = b"\x1f\x8b"


def get(url):
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (academic research)"})
            resp = urllib.request.urlopen(req, timeout=60)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            time.sleep(6 + 6 * attempt)
    return None, b""


for name, url in URLS.items():
    usable = {ts for ts, _ in STORE[name]["snapshots"]}
    cdx = get(f"https://web.archive.org/cdx/search/cdx?url={url}&fl=timestamp,statuscode,mimetype&collapse=digest")[1]
    rows = [line.split() for line in cdx.decode().splitlines() if len(line.split()) == 3]
    reasons = Counter()
    for ts, status, mime in rows:
        if ts in usable:
            continue
        if status not in ("200", "-"):
            reasons[f"archived HTTP {status}"] += 1
            continue
        code, body = get(f"https://web.archive.org/web/{ts}id_/https://{url}")
        time.sleep(3)
        if code is None:
            reasons["fetch failed (network)"] += 1
            continue
        if body[:2] == GZIP_MAGIC:
            try:
                body = gzip.decompress(body)
            except Exception:
                reasons["corrupt gzip"] += 1
                continue
        head = body[:200].lower()
        if b"just a moment" in head or b"challenge" in head or b"<html" in head or b"<!doctype" in head:
            reasons["HTML page (not a list)"] += 1
        elif not body.strip():
            reasons["empty body"] += 1
        else:
            try:
                json.loads(body)
                reasons["valid JSON but no prefixes"] += 1
            except Exception:
                reasons["unparseable body"] += 1
    print(f"{name:14} captures={len(rows):3} usable={len(usable):3} unusable_reasons={dict(reasons)}", flush=True)
