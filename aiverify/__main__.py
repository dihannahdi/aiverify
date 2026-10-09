"""aiverify command line.

  init        --store S --snapshots F   import the Wayback history used by the historical analysis
  backfill    --store S [list ...] [--url U]   add Wayback (or RIPEstat for an AS) history; existing
                                        versions are kept and re-folded in time order
  sync        --store S [--apache-out F [--reload]]   fetch every list now; regenerate enforcement config
  claims-conf --log F                   print the additive GlobalLog config for the claims log
  monitor     --store S --log F --db D  follow the claims log and keep aggregates
  report      --db D                    print the monitor aggregates as JSON (no IP addresses)
"""
import argparse
import datetime
import json
import os
import shutil
import sqlite3
import subprocess
import sys

from . import apache, fetch, store as store_mod
from .vendors import LISTS
from .verify import DEFAULT_TOLERANCE, cloudflare_prefixes, today


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_init(a):
    store = store_mod.load(a.store)
    with open(a.snapshots) as fh:
        store_mod.import_snapshots(store, json.load(fh))
    store_mod.save(store, a.store)
    print(json.dumps({n: len(e["versions"]) for n, e in store["lists"].items()}))


def cmd_backfill(a):
    store = store_mod.load(a.store)
    names = a.lists or [n for n in LISTS if n not in store["lists"]]
    since = datetime.datetime.fromisoformat(a.since).replace(tzinfo=datetime.timezone.utc)
    end = datetime.datetime.now(datetime.timezone.utc)
    for name in names:
        kind, location = LISTS[name]
        location = a.url or location  # an older or newer address of the same list
        if kind == "asn":
            obs = [(d + "T00:00:00Z", p, "ripestat") for d, p in fetch.asn_daily(location, since, end)]
        else:
            obs = [(store_mod.wayback_time(ts), p, "wayback:" + ts) for ts, p in fetch.wayback(kind, location)]
        old = store["lists"].pop(name, None)
        if old:  # keep what was already observed, re-folded in time order with the history
            for first, last, cid, src in old["versions"]:
                obs += [(first, old["contents"][cid], src), (last, old["contents"][cid], src)]
        for when, prefixes, src in sorted(obs, key=lambda o: o[0]):
            store_mod.observe(store, name, prefixes, when, src)
        store_mod.save(store, a.store)
        entry = store["lists"].get(name, {"versions": [], "contents": {}})
        print(json.dumps({"list": name, "observations": len(obs), "versions": len(entry["versions"]),
                          "contents": len(entry["contents"])}), flush=True)


def cmd_sync(a):
    store = store_mod.load(a.store)
    report = {"time": now_iso(), "changed": [], "failed": []}
    for name, (kind, location) in LISTS.items():
        prefixes = fetch.live(kind, location)
        if not prefixes:
            report["failed"].append(name)
            continue
        if name in store["lists"] and store["lists"][name]["versions"][-1][1] > report["time"]:
            report["failed"].append(name + ":clock")
            continue
        if store_mod.observe(store, name, prefixes, report["time"], "live"):
            report["changed"].append(name)
    store_mod.save(store, a.store)
    if a.apache_out:
        exempt = cloudflare_prefixes() if a.exempt_cloudflare else ()
        text, counts = apache.enforce_conf(store_mod.all_versioned(store), today(), DEFAULT_TOLERANCE,
                                           stamp=report["time"], exempt=exempt)
        report["prefixes"] = counts
        old = open(a.apache_out).read() if os.path.exists(a.apache_out) else ""
        if old.split("\n", 1)[-1] != text.split("\n", 1)[-1]:
            if old:
                shutil.copyfile(a.apache_out, a.apache_out + ".prev")
            with open(a.apache_out + ".tmp", "w") as fh:
                fh.write(text)
            os.replace(a.apache_out + ".tmp", a.apache_out)
            report["apache"] = "written"
            if a.reload:
                test = subprocess.run([a.httpd, "-t"], capture_output=True, text=True)
                if test.returncode != 0:
                    if old:
                        shutil.copyfile(a.apache_out + ".prev", a.apache_out)
                    else:
                        os.remove(a.apache_out)
                    report["apache"] = "rejected: " + test.stderr.strip()[-300:]
                    print(json.dumps(report))
                    sys.exit(1)
                subprocess.run([a.httpd, "-k", "graceful"], check=True)
                report["apache"] = "reloaded"
    print(json.dumps(report))


def cmd_claims_conf(a):
    sys.stdout.write(apache.claims_log_conf(a.log))


def cmd_monitor(a):
    from .monitor import Monitor
    Monitor(a.store, a.log, a.db, rdns=not a.no_rdns, ipset=a.ipset, ban_ttl=a.ban_ttl, breaker=a.breaker).run()


def cmd_report(a):
    db = sqlite3.connect(a.db)
    out = {}
    for table in ("agg", "rdns", "perf", "status", "guard"):
        cur = db.execute(f"SELECT * FROM {table}")
        cols = [c[0] for c in cur.description]
        out[table] = [dict(zip(cols, row)) for row in cur]
    print(json.dumps(out))


def main():
    p = argparse.ArgumentParser(prog="aiverify")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init"); s.add_argument("--store", required=True); s.add_argument("--snapshots", required=True)
    s = sub.add_parser("backfill"); s.add_argument("--store", required=True); s.add_argument("lists", nargs="*")
    s.add_argument("--since", default="2025-01-01")
    s.add_argument("--url", help="archive history from this address instead (one list only)")
    s = sub.add_parser("sync"); s.add_argument("--store", required=True); s.add_argument("--apache-out")
    s.add_argument("--reload", action="store_true"); s.add_argument("--httpd", default="/www/server/apache/bin/httpd")
    s.add_argument("--exempt-cloudflare", action="store_true", help="always allow Cloudflare peers (fail-open)")
    s = sub.add_parser("claims-conf"); s.add_argument("--log", required=True)
    s = sub.add_parser("monitor"); s.add_argument("--store", required=True); s.add_argument("--log", required=True)
    s.add_argument("--db", required=True); s.add_argument("--no-rdns", action="store_true")
    s.add_argument("--ipset"); s.add_argument("--ban-ttl", type=int, default=86400)
    s.add_argument("--breaker", help="command run as `CMD off all` when the list and FCrDNS disagree")
    s = sub.add_parser("report"); s.add_argument("--db", required=True)
    a = p.parse_args()
    {"init": cmd_init, "backfill": cmd_backfill, "sync": cmd_sync, "claims-conf": cmd_claims_conf,
     "monitor": cmd_monitor, "report": cmd_report}[a.cmd](a)


if __name__ == "__main__":
    main()
