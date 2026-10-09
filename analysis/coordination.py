"""Test for coordination among impersonating crawlers (claimed crawler UA, IP in no published list version).

Signals, all aggregate (no IP leaves the server):
  cross_site   IPs seen on >= 2 of the sites
  bursts       hours in which >= K distinct impersonating IPs were active, and the share of requests in them
  shared_paths (hour, path) cells hit by >= 3 distinct impersonating IPs, and the share of requests in them
  ua_diversity distinct user-agent strings used by the impersonating IPs per class
  rdns         reverse-DNS registered domain of the 25 busiest impersonating IPs (provider level only)
A null model (same signals on verified crawler IPs) is computed for comparison.
"""
import base64
import bisect
import ipaddress
import json
import os
import socket
import sys
import urllib.request
import zlib
from collections import Counter, defaultdict

SNAPSHOTS_B64 = "__SNAPSHOTS__"
LOGDIR = "/www/wwwlogs/"
FILES = os.environ.get("FILES", "").split(",")
BURST_K = 5
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
            self.starts[v] = [s for s, _ in items]
            self.ends[v] = [e for _, e in items]
            # running max of ends so overlapping spans are handled by bisect
            m = -1
            for i, e in enumerate(self.ends[v]):
                m = max(m, e)
                self.ends[v][i] = m

    def __contains__(self, addr):
        v, n = addr.version, int(addr)
        i = bisect.bisect_right(self.starts[v], n) - 1
        return i >= 0 and n <= self.ends[v][i]


store = json.loads(zlib.decompress(base64.b64decode(SNAPSHOTS_B64)))
union = {}
for name, entry in store.items():
    every = set(entry["live"])
    for body in entry["bodies"].values():
        every.update(body)
    union[name] = RangeSet(every)
def fetch(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=30).read().decode()


cf = RangeSet((fetch("https://www.cloudflare.com/ips-v4") + "\n" + fetch("https://www.cloudflare.com/ips-v6")).split())

groups = {"impersonating": defaultdict(list), "verified": defaultdict(list)}  # group -> ip -> [(site, hour, path, cls, ua)]
for fname in FILES:
    site = fname.replace("-access_log", "")
    with open(LOGDIR + fname, "rb") as fh:
        for raw in fh:
            low = raw.lower()
            cls = None
            for token, name in CLASSES:
                if token in low:
                    cls = name
                    break
            if cls is None:
                continue
            parts = raw.split(b'"')
            if len(parts) < 6:
                continue
            ip = parts[0].split(b" ", 1)[0].decode("ascii", "replace")
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr in cf:
                continue
            lb = parts[0].find(b"[")
            hour = parts[0][lb + 1:lb + 15].decode()          # dd/Mon/yyyy:HH
            req = parts[1].split(b" ")
            path = req[1].split(b"?")[0].decode("ascii", "replace") if len(req) > 1 else "-"
            g = "verified" if addr in union[cls] else "impersonating"
            if g == "verified" and cls == "googlebot":
                continue  # real Googlebot crawls massively by design; not a fair null model, and too large to hold
            groups[g][ip].append((site, hour, path, cls, parts[5][:120]))


def signals(by_ip):
    reqs = sum(len(v) for v in by_ip.values())
    if not reqs:
        return {}
    cross = sum(1 for v in by_ip.values() if len({r[0] for r in v}) >= 2)
    hour_ips, cell_ips = defaultdict(set), defaultdict(set)
    for ip, rows in by_ip.items():
        for site, hour, path, cls, ua in rows:
            hour_ips[(site, hour)].add(ip)
            cell_ips[(site, hour, path)].add(ip)
    burst_hours = {h for h, s in hour_ips.items() if len(s) >= BURST_K}
    in_burst = sum(1 for rows in by_ip.values() for r in rows if (r[0], r[1]) in burst_hours)
    shared_cells = {c for c, s in cell_ips.items() if len(s) >= 3}
    in_shared = sum(1 for rows in by_ip.values() for r in rows if (r[0], r[1], r[2]) in shared_cells)
    per_ip = sorted((len(v) for v in by_ip.values()), reverse=True)
    ua_div = defaultdict(set)
    for rows in by_ip.values():
        for r in rows:
            ua_div[r[3]].add(r[4])
    return {
        "ips": len(by_ip), "requests": reqs,
        "median_requests_per_ip": per_ip[len(per_ip) // 2],
        "ips_on_2plus_sites": cross, "pct_ips_cross_site": round(100 * cross / len(by_ip), 1),
        "burst_hours": len(burst_hours), "pct_requests_in_bursts": round(100 * in_burst / reqs, 1),
        "max_distinct_ips_in_one_hour": max(len(s) for s in hour_ips.values()),
        "shared_path_cells": len(shared_cells), "pct_requests_on_shared_paths": round(100 * in_shared / reqs, 1),
        "distinct_ua_strings_by_class": {k: len(v) for k, v in ua_div.items()},
        "requests_by_class": dict(Counter(r[3] for rows in by_ip.values() for r in rows)),
    }


def registered_domain(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        return ".".join(host.split(".")[-2:])
    except Exception:
        return "no-ptr"


busiest = sorted(groups["impersonating"].items(), key=lambda kv: -len(kv[1]))[:25]
rdns = Counter(registered_domain(ip) for ip, _ in busiest)
out = {"impersonating": signals(groups["impersonating"]), "verified_null_model": signals(groups["verified"]),
       "rdns_top25_impersonating": dict(rdns), "burst_k": BURST_K}
sys.stdout.write(json.dumps(out) + "\n")
