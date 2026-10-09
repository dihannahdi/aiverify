"""Second-round historical analysis, run on the log server with the deployed aiverify package.

Uses the same verifier code as the live system. Emits one JSON object of aggregates. No IP address leaves the
server: IPs are used in memory only, and reverse-DNS results are reduced to the PTR's registered domain.

  REPRO   site|cls|verdict          strict verdicts for the six original lists (must match verify_full CAT)
                                    Requests of the newer lists dated before their first archived version
                                    are labelled pre_history and kept out of every rate.
  VER     site|cls|verdict          request counts with the tolerance window, every class
  VERIP   cls|label                 distinct IPs: listed (held by some version) or never
  CROSS   cls|other_list            never-listed IPs of cls that some version of another list holds
  ROBOTS  cls|label|stat            IPs, IPs that fetched /robots.txt, robots requests, all requests
  UARULE  cls|window|norm|level|cell confusion counts of the online user-agent novelty rule
  BAN     ttl|stat                  reactive IP-ban simulation (server-wide, direct connections only)
  INLINE  stat                      inline L7 decision with the tolerance window
  THIN    cls|q|stat                robustness when archive versions are missing
  RDNS    cls|list_label|result|provider   FCrDNS now, for claim IPs seen in the last 14 days

Env: FILES (comma-separated names under /www/wwwlogs/), STORE (path), SEED (default 42), REPS (default 50).
"""
import calendar
import concurrent.futures
import datetime
import ipaddress
import json
import os
import random
import re
import sys
import time
from collections import Counter, defaultdict

from aiverify import store as store_mod
from aiverify.ranges import VersionedList
from aiverify.vendors import CLASS_LIST, RDNS_SUFFIXES, UA_CLASSES, USER_TRIGGERED
from aiverify.verify import DEFAULT_TOLERANCE, cloudflare_ranges, fcrdns

LOGDIR = "/www/wwwlogs/"
FILES = os.environ["FILES"].split(",")
SEED, REPS = int(os.environ.get("SEED", "42")), int(os.environ.get("REPS", "50"))
ORIGINAL = ("googlebot", "gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "perplexity-user")
# Anthropic's page says the list identifies "a crawler" from Anthropic without naming the bots it covers, so
# only ClaudeBot is judged; Claude-User and Claude-SearchBot are reported but never called impersonation.
COVERAGE_UNKNOWN = ("claude-user", "claude-searchbot")
GENERIC_BOT = (b"bot", b"crawler", b"spider", b"curl/", b"python-requests", b"go-http", b"wget", b"headless",
               b"scrapy", b"httpclient", b"okhttp", b"axios", b"node-fetch")
MONTHS = {b"Jan": 1, b"Feb": 2, b"Mar": 3, b"Apr": 4, b"May": 5, b"Jun": 6,
          b"Jul": 7, b"Aug": 8, b"Sep": 9, b"Oct": 10, b"Nov": 11, b"Dec": 12}
TOKENS = tuple(t for t, _ in UA_CLASSES)
DIGITS = re.compile(rb"\d+")
t_start = time.time()

store = store_mod.load(os.environ["STORE"])
lists = store_mod.all_versioned(store)
cloudflare = cloudflare_ranges()


def cls_of(low):
    for token, name in UA_CLASSES:
        if token in low:
            return name
    return None


_date_cache = {}


def parse_time(head):
    """Apache %t -> (epoch seconds, local date ordinal)."""
    lb = head.find(b"[")
    s = head[lb + 1:lb + 27]  # 08/Oct/2026:15:12:01 +0700
    dkey = s[:11]
    d = _date_cache.get(dkey)
    if d is None:
        d = _date_cache[dkey] = (int(s[7:11]), MONTHS[s[3:6]], int(s[0:2]))
    hh, mm, ss = int(s[12:14]), int(s[15:17]), int(s[18:20])
    sign = -1 if s[21:22] == b"-" else 1
    off = sign * (int(s[22:24]) * 3600 + int(s[24:26]) * 60)
    epoch = calendar.timegm((d[0], d[1], d[2], hh, mm, ss)) - off
    return epoch, datetime.date(*d).toordinal()


# ---- pass 1: every claimed crawler request -------------------------------------------------------------
claims = []  # (epoch, day, site, cls, ip_text, ua_bytes, kind, bytes)
cf_cache = {}
for fname in FILES:
    site = fname.replace("-access_log", "")
    with open(LOGDIR + fname, "rb") as fh:
        for raw in fh:
            low = raw.lower()
            if not any(t in low for t in TOKENS):
                continue
            parts = raw.split(b'"')
            if len(parts) < 6:
                continue
            ua_low = parts[5].lower()
            cls = cls_of(ua_low)
            if cls is None:
                continue
            ip_text = parts[0].split(b" ", 1)[0].decode("ascii", "replace")
            is_cf = cf_cache.get(ip_text)
            if is_cf is None:
                try:
                    is_cf = cf_cache[ip_text] = ipaddress.ip_address(ip_text) in cloudflare
                except ValueError:
                    is_cf = cf_cache[ip_text] = None
            if is_cf is not False:
                continue  # Cloudflare peer or unparsable: the client IP is unknown
            try:
                epoch, day = parse_time(parts[0])
            except (KeyError, ValueError, IndexError):
                continue
            req = parts[1].split(b" ")
            path = req[1].split(b"?")[0].lower() if len(req) > 1 else b""
            kind = "robots" if path == b"/robots.txt" else "page"
            fields = parts[2].split()
            size = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0
            claims.append((epoch, day, site, cls, ip_text, parts[5][:300], kind, size))
claims.sort(key=lambda c: c[0])
t_pass1 = time.time() - t_start

# ---- verdicts ------------------------------------------------------------------------------------------
verdict_cache = {}


def verdicts(cls, ip_text, day):
    """(strict verdict, tolerance verdict) or (None, None) when the class has no list."""
    key = (cls, ip_text, day)
    v = verdict_cache.get(key)
    if v is None:
        name = CLASS_LIST.get(cls)
        if name is None or name not in lists:
            v = (None, None)
        elif cls not in ORIGINAL and day < lists[name].firsts[0]:
            v = ("pre_history", "pre_history")  # the vendor had not published (or archived) a list yet
        else:
            addr = ipaddress.ip_address(ip_text)
            vl = lists[name]
            v = (vl.verdict(addr, day, 0), vl.verdict(addr, day, DEFAULT_TOLERANCE.get(name, 0)))
        verdict_cache[key] = v
    return v


def label(tol, cls=None):
    if cls in COVERAGE_UNKNOWN and tol is not None and tol != "pre_history":
        return "coverage_unknown"
    if tol is None:
        return "unverifiable"
    if tol == "pre_history":
        return "pre_history"
    if tol in ("verified", "tolerance"):
        return "genuine"
    return "never" if tol == "never" else "other_time"


REPRO, VER = Counter(), Counter()
ips_by_label = defaultdict(set)
robots = defaultdict(lambda: [set(), set(), 0, 0])  # ips, ips with robots, robots requests, requests
labelled = []  # (epoch, day, cls, ip, ua, label, strict)
for epoch, day, site, cls, ip, ua, kind, size in claims:
    strict, tol = verdicts(cls, ip, day)
    lab = label(tol, cls)
    if cls in ORIGINAL:
        REPRO[f"{site}|{cls}|{strict}"] += 1
    VER[f"{site}|{cls}|{tol or 'unverifiable'}"] += 1
    ips_by_label[(cls, "listed" if lab in ("genuine", "other_time") else lab)].add(ip)
    r = robots[(cls, lab)]
    r[0].add(ip)
    r[3] += 1
    if kind == "robots":
        r[1].add(ip)
        r[2] += 1
    labelled.append((epoch, day, cls, ip, ua, lab, strict))

VERIP = Counter({f"{c}|{lab}": len(s) for (c, lab), s in ips_by_label.items()})
ROBOTS = Counter()
for (c, lab), (ips, rips, rreq, req) in robots.items():
    ROBOTS[f"{c}|{lab}|ips"] = len(ips)
    ROBOTS[f"{c}|{lab}|ips_fetching_robots"] = len(rips)
    ROBOTS[f"{c}|{lab}|robots_requests"] = rreq
    ROBOTS[f"{c}|{lab}|requests"] = req

# ---- cross-list membership of never-listed IPs ----------------------------------------------------------
CROSS = Counter()
for (c, lab), ips in ips_by_label.items():
    if lab != "never":
        continue
    own = CLASS_LIST.get(c)
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        hits = [name for name, vl in lists.items() if name != own and vl.holding(addr)]
        for name in hits:
            CROSS[f"{c}|{name}"] += 1
        CROSS[f"{c}|_total"] += 1
        CROSS[f"{c}|_in_any_other"] += 1 if hits else 0

# ---- online user-agent novelty rule ---------------------------------------------------------------------
# Learns known-good user-agent strings only from strictly verified requests (what an online system can know),
# and is scored against the tolerance labels (the best available truth). The first 30 days are warm-up.
UARULE = Counter()
t0 = labelled[0][0] if labelled else 0
for window_days in (7, 30, 90):
    for norm in ("exact", "digits"):
        known = defaultdict(dict)  # cls -> ua key -> last epoch seen from a verified IP
        first_decision = {}
        for epoch, day, cls, ip, ua, lab, strict in labelled:
            key = DIGITS.sub(b"#", ua) if norm == "digits" else ua
            seen = known[cls].get(key)
            flagged = seen is None or epoch - seen > window_days * 86400
            if strict == "verified":
                known[cls][key] = epoch
            if epoch < t0 + 30 * 86400:
                continue
            if lab not in ("genuine", "never"):
                continue
            cell = ("tp" if flagged else "fn") if lab == "never" else ("fp" if flagged else "tn")
            UARULE[f"{cls}|{window_days}|{norm}|req|{cell}"] += 1
            if (cls, ip) not in first_decision:
                first_decision[(cls, ip)] = cell
                UARULE[f"{cls}|{window_days}|{norm}|ip|{cell}"] += 1

# ---- pass 2: every request from never-listed IPs, for the reactive ban simulation -----------------------
never_ips = set()
for (c, lab), ips in ips_by_label.items():
    if lab == "never":
        never_ips.update(ips)
never_bytes = {ip.encode() for ip in never_ips}
events = defaultdict(list)  # ip -> [(epoch, kind, bytes)] kind: never | genuine | other_claim | nonclaim
claim_kind = {}
for epoch, day, cls, ip, ua, lab, strict in labelled:
    claim_kind[(ip, epoch, cls)] = lab
for fname in FILES:
    with open(LOGDIR + fname, "rb") as fh:
        for raw in fh:
            sp = raw.find(b" ")
            if raw[:sp] not in never_bytes:
                continue
            parts = raw.split(b'"')
            if len(parts) < 6:
                continue
            try:
                epoch, _ = parse_time(parts[0])
            except (KeyError, ValueError, IndexError):
                continue
            fields = parts[2].split()
            size = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0
            ua_low = parts[5].lower()
            cls = cls_of(ua_low)
            if cls is None:
                kind = "nonclaim_bot" if any(t in ua_low for t in GENERIC_BOT) else "nonclaim_browser"
            else:
                lab = claim_kind.get((raw[:sp].decode(), epoch, cls), "other_claim")
                kind = "never" if lab == "never" else ("genuine" if lab == "genuine" else "other_claim")
            events[raw[:sp].decode()].append((epoch, kind, size))

BAN = Counter()
for ttl_name, ttl in (("1h", 3600), ("24h", 86400), ("7d", 604800), ("forever", float("inf"))):
    for ip, evs in events.items():
        evs.sort()
        banned_until = float("-inf")
        for epoch, kind, size in evs:
            if epoch < banned_until:
                BAN[f"{ttl_name}|blocked_{kind}"] += 1
                BAN[f"{ttl_name}|blocked_{kind}_bytes"] += size
                continue
            BAN[f"{ttl_name}|passed_{kind}"] += 1
            if kind == "never":
                banned_until = epoch + ttl
browser_per_ip = []
for ip, evs in events.items():
    BAN["ips_with_nonclaim_traffic"] += 1 if any(k.startswith("nonclaim") for _, k, _ in evs) else 0
    nb = sum(1 for _, k, _ in evs if k == "nonclaim_browser")
    BAN["ips_with_browser_traffic"] += 1 if nb else 0
    browser_per_ip.append(nb)
browser_per_ip.sort(reverse=True)
BAN["browser_requests_top1_ip"] = browser_per_ip[0] if browser_per_ip else 0
BAN["browser_requests_top5_ips"] = sum(browser_per_ip[:5])
BAN["browser_requests_all"] = sum(browser_per_ip)
BAN["never_ips"] = len(events)

INLINE = Counter()
for epoch, day, cls, ip, ua, lab, strict in labelled:
    INLINE[f"{lab}|{'deny' if lab in ('never', 'other_time') else 'allow'}"] += 1
    if lab == "other_time" and cls in USER_TRIGGERED:
        INLINE["other_time_user_triggered"] += 1

# ---- robustness to missing archive versions --------------------------------------------------------------
THIN = Counter()
rng = random.Random(SEED)
weights = defaultdict(Counter)  # list name -> (ip, day) -> requests
for epoch, day, cls, ip, ua, lab, strict in labelled:
    name = CLASS_LIST.get(cls)
    if cls in ORIGINAL and name in lists:
        weights[name][(ip, day)] += 1
for name, w in weights.items():
    full = lists[name]
    tol = DEFAULT_TOLERANCE.get(name, 0)
    total = sum(w.values())
    addr_of = {ip: ipaddress.ip_address(ip) for ip, _ in w}
    holding = {ip: full.holding(a) for ip, a in addr_of.items()}
    for q in (0.0, 0.25, 0.5, 0.75):
        rates_strict, rates_tol, rates_tol30 = [], [], []
        for _ in range(1 if q == 0 else REPS):
            keep = [v for i, v in enumerate(full.versions) if i == len(full.versions) - 1 or rng.random() >= q]
            sub = VersionedList(keep, {cid: full.contents[cid] for _, _, cid in keep})
            for ip, a in addr_of.items():
                sub._holding[(int(a), a.version)] = holding[ip] & frozenset(sub.sets)
            bad_s = bad_t = bad_30 = 0
            for (ip, day), n in w.items():
                v = sub.verdict(addr_of[ip], day, tol)
                if v not in ("verified",):
                    bad_s += n
                if v not in ("verified", "tolerance"):
                    bad_t += n
                if v != "verified" and (sub.distance(addr_of[ip], day) is None or sub.distance(addr_of[ip], day) > 30):
                    bad_30 += n
            rates_strict.append(bad_s / total)
            rates_tol.append(bad_t / total)
            rates_tol30.append(bad_30 / total)
        for stat, rates in (("strict", rates_strict), ("tol", rates_tol), ("tol30", rates_tol30)):
            rates.sort()
            THIN[f"{name}|{q}|{stat}|mean"] = round(sum(rates) / len(rates), 5)
            THIN[f"{name}|{q}|{stat}|p05"] = round(rates[int(0.05 * (len(rates) - 1))], 5)
            THIN[f"{name}|{q}|{stat}|p95"] = round(rates[int(0.95 * (len(rates) - 1))], 5)
    THIN[f"{name}|versions"] = len(full.versions)
    THIN[f"{name}|requests"] = total

# ---- forward-confirmed reverse DNS now, for recently seen claim IPs --------------------------------------
RDNS = Counter()
recent_cut = time.time() - 14 * 86400
recent = {}
for epoch, day, cls, ip, ua, lab, strict in labelled:
    if cls in RDNS_SUFFIXES and epoch >= recent_cut:
        recent[(cls, ip)] = lab  # latest label wins
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    futs = {pool.submit(fcrdns, ip, cls): (cls, lab) for (cls, ip), lab in recent.items()}
    for fut in concurrent.futures.as_completed(futs):
        cls, lab = futs[fut]
        try:
            result, provider = fut.result()
        except Exception:
            result, provider = "error", "-"
        RDNS[f"{cls}|{lab}|{result}|{provider}"] += 1

sys.stdout.write(json.dumps({
    "REPRO": REPRO, "VER": VER, "VERIP": VERIP, "CROSS": CROSS, "ROBOTS": ROBOTS, "UARULE": UARULE, "BAN": BAN, "INLINE": INLINE, "THIN": THIN, "RDNS": RDNS,
    "claims": len(claims), "lists": {n: len(v.versions) for n, v in lists.items()},
    "seconds": {"pass1": round(t_pass1, 1), "total": round(time.time() - t_start, 1)},
}) + "\n")
