"""Single-pass analysis of historical Apache logs for AI-crawler verification and crawl-to-referral.

Runs on the log server. Reads the IP-range history embedded below, emits ONE JSON line of
aggregates to stdout. No IP address ever leaves the server: IPs are only used in-memory for
range membership and Cloudflare detection.

Env:
  LIMIT  max lines per file (0 = all)
  FILES  comma-separated log file names under /www/wwwlogs/
"""
import base64
import bisect
import ipaddress
import json
import os
import sys
import time
import urllib.request
import zlib
from collections import Counter

SNAPSHOTS_B64 = "__SNAPSHOTS__"

LOGDIR = "/www/wwwlogs/"
LIMIT = int(os.environ.get("LIMIT", "0"))
FILES = os.environ.get("FILES", "").split(",")

MONTHS = {b"Jan": "01", b"Feb": "02", b"Mar": "03", b"Apr": "04", b"May": "05", b"Jun": "06",
          b"Jul": "07", b"Aug": "08", b"Sep": "09", b"Oct": "10", b"Nov": "11", b"Dec": "12"}

# First match wins, so the more specific tokens come first.
UA_CLASSES = [
    (b"oai-searchbot", "oai-searchbot"), (b"chatgpt-user", "chatgpt-user"), (b"gptbot", "gptbot"),
    (b"perplexity-user", "perplexity-user"), (b"perplexitybot", "perplexitybot"),
    (b"claude-searchbot", "claude-searchbot"), (b"claude-user", "claude-user"), (b"claudebot", "claudebot"),
    (b"meta-externalagent", "meta-externalagent"), (b"bytespider", "bytespider"), (b"amazonbot", "amazonbot"),
    (b"ccbot", "ccbot"), (b"googlebot", "googlebot"), (b"bingbot", "bingbot"), (b"applebot", "applebot"),
    (b"aapanel", "internal"),
]
GENERIC_BOT = (b"bot", b"crawler", b"spider", b"curl/", b"python-requests", b"go-http", b"wget", b"headless",
               b"scrapy", b"httpclient", b"okhttp", b"axios", b"node-fetch")
VERIFIABLE = ("googlebot", "gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "perplexity-user")
STATIC_EXT = (b".js", b".css", b".png", b".jpg", b".jpeg", b".gif", b".svg", b".webp", b".ico", b".woff",
              b".woff2", b".ttf", b".map", b".avif", b".mp4", b".webm")


def referral_platform(ref, req):
    if b"chatgpt.com" in ref or b"chat.openai.com" in ref or b"utm_source=chatgpt.com" in req:
        return "openai"
    if b"perplexity.ai" in ref or b"utm_source=perplexity" in req:
        return "perplexity"
    if b"claude.ai" in ref:
        return "anthropic"
    if b"gemini.google.com" in ref:
        return "gemini"
    if b"copilot.microsoft.com" in ref or b"bing.com/chat" in ref:
        return "copilot"
    if b"meta.ai" in ref:
        return "meta_ai"
    if ref.startswith((b"https://www.google.", b"https://google.", b"android-app://com.google")):
        return "google_search"
    if ref.startswith((b"https://www.bing.com", b"https://bing.com")):
        return "bing_search"
    return None


class RangeSet:
    """Sorted, merged integer ranges for fast membership tests."""

    def __init__(self, prefixes):
        spans = {4: [], 6: []}
        for p in prefixes:
            net = ipaddress.ip_network(p, strict=False)
            spans[net.version].append((int(net.network_address), int(net.broadcast_address)))
        self.starts, self.ends = {}, {}
        for v, items in spans.items():
            items.sort()
            merged = []
            for s, e in items:
                if merged and s <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], e))
                else:
                    merged.append((s, e))
            self.starts[v] = [s for s, _ in merged]
            self.ends[v] = [e for _, e in merged]

    def __contains__(self, addr):
        v, n = addr.version, int(addr)
        i = bisect.bisect_right(self.starts[v], n) - 1
        return i >= 0 and n <= self.ends[v][i]


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=30).read().decode()


store = json.loads(zlib.decompress(base64.b64decode(SNAPSHOTS_B64)))
lists = {}
for name, entry in store.items():
    dates, sets, body_cache = [], [], {}
    for ts, digest in entry["snapshots"]:
        if digest not in body_cache:
            body_cache[digest] = RangeSet(entry["bodies"][digest])
        dates.append(int(ts[:8]))
        sets.append(body_cache[digest])
    every = set(entry["live"])
    for body in entry["bodies"].values():
        every.update(body)
    lists[name] = {"dates": dates, "sets": sets, "live": RangeSet(entry["live"]), "union": RangeSet(every)}

cloudflare = RangeSet((fetch("https://www.cloudflare.com/ips-v4") + "\n" + fetch("https://www.cloudflare.com/ips-v6")).split())

A, R, V, VM, S, BNO, PRE = Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
LINES, BAD = Counter(), Counter()
cf_cache, ver_cache = {}, {}
t0 = time.time()

for fname in FILES:
    site = fname.replace("-access_log", "")
    path = LOGDIR + fname
    if not os.path.exists(path):
        continue
    with open(path, "rb") as fh:
        for raw in fh:
            LINES[site] += 1
            if LIMIT and LINES[site] > LIMIT:
                LINES[site] -= 1
                break
            parts = raw.split(b'"')
            if len(parts) < 6:
                BAD[site] += 1
                continue
            head, req, mid, ref, ua = parts[0], parts[1], parts[2], parts[3], parts[5]
            lb = head.find(b"[")
            if lb < 0 or len(head) < lb + 12:
                BAD[site] += 1
                continue
            day, mon, year = head[lb + 1:lb + 3], head[lb + 4:lb + 7], head[lb + 8:lb + 12]
            mm = MONTHS.get(mon)
            if mm is None:
                BAD[site] += 1
                continue
            month = year.decode() + "-" + mm
            date_int = int(year + mm.encode() + day)
            fields = mid.split()
            status = fields[0][:1].decode() + "xx" if fields else "?xx"
            size = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0
            uri = req.split(b" ")[1] if req.count(b" ") >= 2 else b""
            page = 0 if uri.split(b"?")[0].lower().endswith(STATIC_EXT) else 1

            low = ua.lower()
            cls = None
            for token, name in UA_CLASSES:
                if token in low:
                    cls = name
                    break
            if cls is None:
                cls = "other-bot" if any(t in low for t in GENERIC_BOT) else "browser"

            key = f"{site}|{month}|{cls}"
            A[key + "|req"] += 1
            A[key + "|bytes"] += size
            A[key + "|page"] += page
            S[f"{site}|{cls}|{status}"] += 1

            if cls == "browser":
                plat = referral_platform(ref.lower(), req.lower())
                if plat:
                    R[f"{site}|{month}|{plat}"] += 1
                continue

            if cls not in VERIFIABLE:
                continue
            ip_text = head.split(b" ", 1)[0].decode("ascii", "replace")
            try:
                addr = ipaddress.ip_address(ip_text)
            except ValueError:
                for scheme in ("today", "temporal", "union"):
                    V[f"{site}|{cls}|{scheme}|bad"] += 1
                continue
            is_cf = cf_cache.get(ip_text)
            if is_cf is None:
                is_cf = cf_cache[ip_text] = addr in cloudflare
            if is_cf:
                for scheme in ("today", "temporal", "union"):
                    V[f"{site}|{cls}|{scheme}|cf"] += 1
                VM[f"{site}|{month}|{cls}|cf"] += 1
                continue
            info = lists[cls]
            idx = bisect.bisect_right(info["dates"], date_int) - 1
            if idx < 0:
                PRE[f"{site}|{cls}"] += 1
                idx = 0
            ck = (cls, ip_text, idx)
            res = ver_cache.get(ck)
            if res is None:
                res = ver_cache[ck] = (addr in info["live"], addr in info["sets"][idx] if info["sets"] else False,
                                       addr in info["union"])
            for scheme, ok in zip(("today", "temporal", "union"), res):
                V[f"{site}|{cls}|{scheme}|{'ok' if ok else 'no'}"] += 1
            VM[f"{site}|{month}|{cls}|{'ok' if res[1] else 'no'}"] += 1
            if not res[1]:
                BNO[f"{site}|{cls}|req"] += 1
                BNO[f"{site}|{cls}|bytes"] += size

out = {"lines": LINES, "bad": BAD, "A": A, "R": R, "V": V, "VM": VM, "S": S, "BNO": BNO, "PRE": PRE,
       "snapshot_counts": {k: len(v["dates"]) for k, v in lists.items()}, "seconds": round(time.time() - t0, 1)}
sys.stdout.write(json.dumps(out) + "\n")
