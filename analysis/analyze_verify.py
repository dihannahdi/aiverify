"""One-pass, direction-aware verification of claimed crawler requests against the IP-list history.

Outputs (all counts, no IP address leaves the server):
  H       site|cls|bucket   nearest-version distance d_min (days) for tolerance-window curves
                            buckets: 0, 1-7, 8-30, 31-90, 91-180, 181-365, >365, never; plus cf, bad
  CAT     site|cls|cat|bkt  direction of the mismatch:
                              active          IP in the version in force on the request date
                              added_later     only later versions hold the IP (bkt = days until first one)
                              removed_earlier only earlier versions hold it (bkt = days since last one)
                              flapping        earlier and later versions hold it, the one in force does not
                              never           no version holds it, today's list included
  IPS     site|cls|stat     distinct IPs ("ips") and distinct IPs held by no version ("never_ips")
  LAG     cls -> [[proven_or_null, observed], ...] one row per IP held by some version, where
            observed = F - t0  (days from the IP's first observed use t0 to the first version F holding it)
            proven   = Q - t0  (Q = the version just before F, which lacks the IP), counted only when the
                       content of Q never reappears in or after F (no rollback / dual-serving), else null.
          True publication lag >= proven, because the true first use is <= t0 and the list at Q lacked the IP.
"""
import base64
import bisect
import datetime
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
FILES = os.environ.get("FILES", "").split(",")
LIMIT = int(os.environ.get("LIMIT", "0"))
TODAY = datetime.date.today().strftime("%Y%m%d")
MONTHS = {b"Jan": 1, b"Feb": 2, b"Mar": 3, b"Apr": 4, b"May": 5, b"Jun": 6,
          b"Jul": 7, b"Aug": 8, b"Sep": 9, b"Oct": 10, b"Nov": 11, b"Dec": 12}
CLASSES = [(b"oai-searchbot", "oai-searchbot"), (b"chatgpt-user", "chatgpt-user"), (b"gptbot", "gptbot"),
           (b"perplexity-user", "perplexity-user"), (b"perplexitybot", "perplexitybot"), (b"googlebot", "googlebot")]


class RangeSet:
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


def ordinal(yyyymmdd):
    s = str(yyyymmdd)
    return datetime.date(int(s[:4]), int(s[4:6]), int(s[6:8])).toordinal()


def dist_bucket(d):
    if d is None:
        return "never"
    for edge, name in ((0, "0"), (7, "1-7"), (30, "8-30"), (90, "31-90"), (180, "91-180"), (365, "181-365")):
        if d <= edge:
            return name
    return ">365"


store = json.loads(zlib.decompress(base64.b64decode(SNAPSHOTS_B64)))
lists = {}
for name, entry in store.items():
    rows = sorted((int(ts[:8]), tuple(entry["bodies"][dg])) for ts, dg in entry["snapshots"])
    if entry["live"]:
        rows.append((int(TODAY), tuple(sorted(entry["live"]))))
    content_ids, sets_by_content = {}, {}
    ords, sets, cids = [], [], []
    for d, content in rows:
        cid = content_ids.setdefault(content, len(content_ids))
        if cid not in sets_by_content:
            sets_by_content[cid] = RangeSet(content)
        ords.append(ordinal(d))
        sets.append(sets_by_content[cid])
        cids.append(cid)
    lists[name] = {"ords": ords, "sets": sets, "cids": cids}

cf_text = "".join(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}), timeout=30)
                  .read().decode() + "\n" for u in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"))
cloudflare = RangeSet(cf_text.split())

H, CAT = Counter(), Counter()
ips_by_site, never_by_site = {}, {}
member_cache, cf_cache, day_cache, first_use = {}, {}, {}, {}
t0 = time.time()
lines = 0
for fname in FILES:
    site = fname.replace("-access_log", "")
    n_file = 0
    with open(LOGDIR + fname, "rb") as fh:
        for raw in fh:
            n_file += 1
            if LIMIT and n_file > LIMIT:
                break
            low = raw.lower()
            cls = None
            for token, name in CLASSES:
                if token in low:
                    cls = name
                    break
            if cls is None:
                continue
            lb = raw.find(b"[")
            key_day = raw[lb + 1:lb + 12]
            od = day_cache.get(key_day)
            if od is None:
                try:
                    od = day_cache[key_day] = datetime.date(int(key_day[7:11]), MONTHS[key_day[3:6]],
                                                            int(key_day[0:2])).toordinal()
                except (KeyError, ValueError):
                    continue
            ip_text = raw.split(b" ", 1)[0].decode("ascii", "replace")
            try:
                addr = ipaddress.ip_address(ip_text)
            except ValueError:
                H[f"{site}|{cls}|bad"] += 1
                continue
            is_cf = cf_cache.get(ip_text)
            if is_cf is None:
                is_cf = cf_cache[ip_text] = addr in cloudflare
            if is_cf:
                H[f"{site}|{cls}|cf"] += 1
                continue
            info = lists[cls]
            ck = (cls, ip_text)
            holding = member_cache.get(ck)
            if holding is None:
                holding = member_cache[ck] = tuple(i for i, s in enumerate(info["sets"]) if addr in s)
            if ck not in first_use or od < first_use[ck]:
                first_use[ck] = od
            ips_by_site.setdefault((site, cls), set()).add(ip_text)
            active = bisect.bisect_right(info["ords"], od) - 1
            if not holding:
                H[f"{site}|{cls}|never"] += 1
                CAT[f"{site}|{cls}|never|-"] += 1
                never_by_site.setdefault((site, cls), set()).add(ip_text)
                continue
            if active in holding:
                H[f"{site}|{cls}|0"] += 1
                CAT[f"{site}|{cls}|active|-"] += 1
                continue
            H[f"{site}|{cls}|{dist_bucket(min(abs(info['ords'][i] - od) for i in holding))}"] += 1
            older = [i for i in holding if i <= active]
            newer = [i for i in holding if i > active]
            if newer and not older:
                CAT[f"{site}|{cls}|added_later|{dist_bucket(info['ords'][min(newer)] - od)}"] += 1
            elif older and not newer:
                CAT[f"{site}|{cls}|removed_earlier|{dist_bucket(od - info['ords'][max(older)])}"] += 1
            else:
                CAT[f"{site}|{cls}|flapping|-"] += 1
    lines += n_file

IPS = Counter()
for (site, cls), s in ips_by_site.items():
    IPS[f"{site}|{cls}|ips"] = len(s)
    IPS[f"{site}|{cls}|never_ips"] = len(never_by_site.get((site, cls), ()))

LAG = {}
for (cls, ip), t_first in first_use.items():
    holding = member_cache[(cls, ip)]
    if not holding:
        continue
    info = lists[cls]
    f = min(holding)
    observed = max(0, info["ords"][f] - t_first)
    proven = None
    if f > 0 and info["cids"][f - 1] not in set(info["cids"][f:]):
        proven = max(0, info["ords"][f - 1] - t_first)
    elif f == 0:
        proven = 0  # held by the earliest version: no evidence of any lag
    LAG.setdefault(cls, []).append([proven, observed])

sys.stdout.write(json.dumps({"H": H, "CAT": CAT, "IPS": IPS, "LAG": LAG, "lines": lines,
                             "versions": {k: len(v["ords"]) for k, v in lists.items()},
                             "unique_contents": {k: len(set(v["cids"])) for k, v in lists.items()},
                             "seconds": round(time.time() - t0, 1)}) + "\n")
