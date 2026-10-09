"""Second pass over Wayback: fetch list versions the first pass missed, merge into snapshots.json.

Usage: python retry_snapshots.py snapshots.json [list_name ...]
"""
import gzip
import json
import sys
import time
import urllib.request

PATH = sys.argv[1]
LISTS = {
    "googlebot": "developers.google.com/static/search/apis/ipranges/googlebot.json",
    "gptbot": "openai.com/gptbot.json",
    "oai-searchbot": "openai.com/searchbot.json",
    "chatgpt-user": "openai.com/chatgpt-user.json",
    "perplexitybot": "www.perplexity.ai/perplexitybot.json",
    "perplexity-user": "www.perplexity.ai/perplexity-user.json",
}
GZIP_MAGIC = b"\x1f\x8b"


def get(url):
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (academic research)"})
            return urllib.request.urlopen(req, timeout=60).read()
        except Exception:
            time.sleep(8 + 10 * attempt)
    return None


try:
    import brotli
except ImportError:
    brotli = None


def prefixes(raw):
    # Wayback's id_ replay returns the original bytes, which may still be gzip- or brotli-encoded.
    if raw[:2] == GZIP_MAGIC:
        try:
            raw = gzip.decompress(raw)
        except Exception:
            return None
    try:
        data = json.loads(raw)
    except Exception:
        if brotli is None:
            return None
        try:
            data = json.loads(brotli.decompress(raw))  # brotli has no magic bytes, so try it last
        except Exception:
            return None
    out = {p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in data.get("prefixes", [])}
    out.discard(None)
    return sorted(out) or None


try:
    with open(PATH) as fh:
        store = json.load(fh)
except FileNotFoundError:
    store = {}

ONLY = set(sys.argv[2:])
for name, url in LISTS.items():
    if ONLY and name not in ONLY:
        continue
    entry = store.setdefault(name, {"snapshots": [], "bodies": {}, "live": []})
    cdx = get(f"https://web.archive.org/cdx/search/cdx?url={url}&fl=timestamp,digest,statuscode&collapse=digest")
    rows = [line.split() for line in (cdx or b"").decode().splitlines() if len(line.split()) == 3]
    rows = [(ts, dg) for ts, dg, st in rows if st in ("200", "-")]
    for ts, digest in rows:
        if digest in entry["bodies"]:
            continue
        body = prefixes(get(f"https://web.archive.org/web/{ts}id_/https://{url}") or b"")
        time.sleep(4)
        if body:
            entry["bodies"][digest] = body
    entry["snapshots"] = [[ts, dg] for ts, dg in rows if dg in entry["bodies"]]
    entry["live"] = prefixes(get(f"https://{url}") or b"") or entry["live"]
    snaps = entry["snapshots"]
    print(f"{name:16} captures={len(rows):3} usable={len(snaps):3} unique_digests={len(entry['bodies']):3} "
          f"unique_contents={len({tuple(v) for v in entry['bodies'].values()}):3} "
          f"range={(snaps[0][0][:8] if snaps else '-')}..{(snaps[-1][0][:8] if snaps else '-')}", flush=True)
    with open(PATH, "w") as fh:
        json.dump(store, fh)
