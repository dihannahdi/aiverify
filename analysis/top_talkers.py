"""Characterize the busiest IPs that also sent crawler claims. Prints categories only, never an IP."""
import ipaddress, json, os, socket, subprocess, sys
from collections import Counter, defaultdict
sys.path.insert(0, "/opt/aiverify")
from aiverify import store as store_mod
from aiverify.vendors import CLASS_LIST, classify
FILES = os.environ["FILES"].split(",")
lists = store_mod.all_versioned(store_mod.load(os.environ["STORE"]))
own = set(subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split())
total, claims, sites = Counter(), defaultdict(Counter), defaultdict(set)
for f in FILES:
    with open("/www/wwwlogs/" + f, "rb") as fh:
        for raw in fh:
            ip = raw[:raw.find(b" ")]
            total[ip] += 1
            sites[ip].add(f)
            low = raw.lower()
            if b"bot" in low or b"user" in low or b"spider" in low or b"agent" in low:
                parts = raw.split(b'"')
                if len(parts) > 5:
                    c = classify(parts[5])
                    if c:
                        claims[ip][c] += 1
rank = 0
for ip, n in total.most_common(40):
    if not claims[ip]:
        continue
    rank += 1
    text = ip.decode()
    addr = ipaddress.ip_address(text)
    held = {c: bool(lists[CLASS_LIST[c]].holding(addr)) for c in claims[ip] if CLASS_LIST.get(c) in lists}
    try:
        ptr = socket.gethostbyaddr(text)[0]
        dom = ".".join(ptr.split(".")[-2:])
    except OSError:
        dom = "-"
    print(json.dumps({"rank_among_claiming_ips": rank, "requests": n, "claims": dict(claims[ip]),
                      "listed_for_claimed_class": held, "own_server_ip": text in own, "private": addr.is_private,
                      "ptr_domain": dom, "sites": len(sites[ip])}))
    if rank >= 5:
        break
