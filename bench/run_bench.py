"""Functional tests and overhead measurement of the generated Apache enforcement, on an isolated instance.

Usage (on the server, as root): python3 -I run_bench.py STORE [REPS] [N] [CONCURRENCY]
One connection (the default) keeps queueing out of %D, so it reflects service time only.
Prints one JSON object: functional test results and per-condition server-side latency (%D, microseconds)
and ab throughput. Conditions run interleaved in a shuffled order per repetition to spread drift and noise.
"""
import ipaddress
import json
import os
import random
import re
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from aiverify import apache, store as store_mod  # noqa: E402
from aiverify.verify import DEFAULT_TOLERANCE, today  # noqa: E402

HTTPD = "/www/server/apache/bin/httpd"
CONF = os.path.join(HERE, "httpd-bench.conf")
RUN, RULES, HTDOCS = (os.path.join(HERE, d) for d in ("run", "rules", "htdocs"))
URL = "http://127.0.0.1:18089/"
STORE = sys.argv[1]
REPS, N, CONC = (int(sys.argv[i]) if len(sys.argv) > i else d for i, d in ((2, 10), (3, 5000), (4, 1)))
UA = {
    "browser": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "gptbot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)",
    "amazonbot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
    "bytespider": "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)",
}
UNLISTED = "203.0.113.10"  # TEST-NET-3, never in any vendor list


def sh(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def host_in(prefix, last=False):
    net = ipaddress.ip_network(prefix)
    return str(net[-2] if last and net.num_addresses > 2 else net[1] if net.num_addresses > 2 else net[0])


def set_rules(text):
    path = os.path.join(RULES, "enforce.conf")
    if text is None:
        if os.path.exists(path):
            os.remove(path)
    else:
        with open(path, "w") as fh:
            fh.write(text)
    sh(HTTPD, "-f", CONF, "-t")
    sh(HTTPD, "-f", CONF, "-k", "graceful")
    time.sleep(2)


def status(path, ua, ip):
    req = urllib.request.Request(URL + path, headers={"User-Agent": ua, "X-Bench-IP": ip})
    try:
        return urllib.request.urlopen(req, timeout=10).status
    except urllib.error.HTTPError as e:
        return e.code


def ab(ua, ip):
    log = os.path.join(RUN, "access.log")
    open(log, "w").close()
    out = sh("ab", "-q", "-k", "-n", str(N), "-c", str(CONC), "-H", f"User-Agent: {ua}", "-H", f"X-Bench-IP: {ip}",
             URL + "index.html").stdout
    rps = float(re.search(r"Requests per second:\s+([\d.]+)", out).group(1))
    time.sleep(0.5)
    with open(log) as fh:
        rows = [line.split() for line in fh]
    us = sorted(int(r[0]) for r in rows if len(r) == 2)
    codes = sorted({r[1] for r in rows if len(r) == 2})
    return {"rps": rps, "us_p50": us[len(us) // 2], "us_p99": us[int(len(us) * 0.99)],
            "us_mean": round(statistics.fmean(us), 2), "n": len(us), "codes": codes}


def main():
    for d in (RUN, RULES, HTDOCS):
        os.makedirs(d, exist_ok=True)
    with open(os.path.join(HTDOCS, "index.html"), "w") as fh:
        fh.write("<!doctype html><title>bench</title>" + "x" * 1024)
    with open(os.path.join(HTDOCS, ".env"), "w") as fh:
        fh.write("SECRET=bench\n")
    store = store_mod.load(STORE)
    lists = store_mod.all_versioned(store)
    variants = {"off": None}
    for gate in ("location", "if"):
        variants[gate], counts = apache.enforce_conf(lists, today(), DEFAULT_TOLERANCE, stamp="bench", gate=gate)
    allowed = {name: lists[name].allowed_prefixes(today(), DEFAULT_TOLERANCE.get(name, 0)) for name in lists}
    v4 = {n: [p for p in a if ":" not in p] for n, a in allowed.items()}
    ip_gpt, ip_google_last = host_in(v4["gptbot"][0]), host_in(v4["googlebot"][-1], last=True)
    ip_amazon_last = host_in(v4["amazonbot"][-1], last=True) if v4.get("amazonbot") else UNLISTED

    sh(HTTPD, "-f", CONF, "-t")
    sh(HTTPD, "-f", CONF, "-k", "start")
    time.sleep(2)
    result = {"prefix_counts": counts, "rules_bytes": len(variants["if"]), "reps": REPS, "n": N,
              "concurrency": CONC, "load_before": os.getloadavg()}
    try:
        cases = [  # (name, path, ua, ip, expected with rules, expected without)
            ("browser", "index.html", "browser", UNLISTED, 200, 200),
            ("gptbot_listed", "index.html", "gptbot", ip_gpt, 200, 200),
            ("gptbot_unlisted", "index.html", "gptbot", UNLISTED, 403, 200),
            ("googlebot_listed_last_prefix", "index.html", "googlebot", ip_google_last, 200, 200),
            ("googlebot_unlisted", "index.html", "googlebot", UNLISTED, 403, 200),
            ("googlebot_ua_from_gptbot_ip", "index.html", "googlebot", ip_gpt, 403, 200),
            ("amazonbot_listed_last_prefix", "index.html", "amazonbot", ip_amazon_last, 200, 200),
            ("bytespider_no_list", "index.html", "bytespider", UNLISTED, 200, 200),
            ("env_browser", ".env", "browser", UNLISTED, 403, 403),
            ("env_verified_bot", ".env", "gptbot", ip_gpt, 403, 403),
        ]
        functional = []
        for variant, text in variants.items():
            set_rules(text)
            for name, path, ua, ip, exp_on, exp_off in cases:
                got = status(path, UA[ua], ip)
                exp = exp_off if text is None else exp_on
                functional.append({"variant": variant, "case": name, "expected": exp, "got": got, "pass": got == exp})
        result["functional"] = functional

        conditions = {  # name -> (ua, ip), run under every variant
            "browser": ("browser", UNLISTED),
            "gptbot_listed": ("gptbot", ip_gpt),
            "googlebot_listed_last": ("googlebot", ip_google_last),
            "googlebot_unlisted": ("googlebot", UNLISTED),
            "amazonbot_listed_last": ("amazonbot", ip_amazon_last),
        }
        runs = {f"{v}|{c}": [] for v in variants for c in conditions}
        rng = random.Random(42)
        for rep in range(REPS):
            order = list(variants)
            rng.shuffle(order)
            for variant in order:
                set_rules(variants[variant])
                names = list(conditions)
                rng.shuffle(names)
                for name in names:
                    ua, ip = conditions[name]
                    runs[f"{variant}|{name}"].append(ab(UA[ua], ip))
        result["overhead"] = runs
        result["load_after"] = os.getloadavg()
    finally:
        sh(HTTPD, "-f", CONF, "-k", "stop", check=False)
        set_rules_path = os.path.join(RULES, "enforce.conf")
        if os.path.exists(set_rules_path):
            os.remove(set_rules_path)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
