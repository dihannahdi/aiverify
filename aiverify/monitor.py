"""Follow the claims log, verify every claimed crawler request as it arrives, and keep only aggregates.

What only a live monitor can record is the reverse-DNS answer at request time, because PTR records of cloud IPs
change owner later. Everything else can be recomputed from the claims log in batch.
"""
import concurrent.futures
import datetime
import os
import re
import sqlite3
import subprocess
import time
from collections import Counter

try:
    import resource
except ImportError:  # not on Windows; perf rows then carry no CPU or memory figures
    resource = None

from . import store as store_mod
from .verify import Verifier, client_ip, cloudflare_ranges, fcrdns
from .vendors import RDNS_SUFFIXES

LINE = re.compile(rb'^(\d+) (\S+) (\S+) "([^"]*)" "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-) '
                  rb'"((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"$')
STATIC_EXT = (b".js", b".css", b".png", b".jpg", b".jpeg", b".gif", b".svg", b".webp", b".ico", b".woff",
              b".woff2", b".ttf", b".map", b".avif", b".mp4", b".webm")
SCHEMA = """
CREATE TABLE IF NOT EXISTS agg (hour TEXT, site TEXT, cls TEXT, verdict TEXT, kind TEXT, route TEXT,
    n INTEGER, bytes INTEGER, PRIMARY KEY (hour, site, cls, verdict, kind, route));
CREATE TABLE IF NOT EXISTS rdns (day TEXT, cls TEXT, list_verdict TEXT, result TEXT, provider TEXT, n INTEGER,
    PRIMARY KEY (day, cls, list_verdict, result, provider));
CREATE TABLE IF NOT EXISTS perf (minute TEXT PRIMARY KEY, lines INTEGER, cpu_s REAL, rss_kb INTEGER,
    verify_us_p50 REAL, verify_us_p99 REAL);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS status (day TEXT, site TEXT, cls TEXT, verdict TEXT, status TEXT, n INTEGER,
    PRIMARY KEY (day, site, cls, verdict, status));
CREATE TABLE IF NOT EXISTS guard (time TEXT, site TEXT, cls TEXT, action TEXT);
"""
# Verdicts the enforcement rule denies. A request with one of these whose IP passes the vendor's official FCrDNS
# means the list and the second method disagree: the rule would block a real crawler.
DENY = ("never", "other_time")
RDNS_TTL = 86400


def kind_of(request):
    parts = request.split(b" ")
    path = parts[1].split(b"?")[0].lower() if len(parts) > 1 else b""
    if path == b"/robots.txt":
        return "robots"
    return "static" if path.endswith(STATIC_EXT) else "page"


class Monitor:
    def __init__(self, store_path, log_path, db_path, rdns=True, ipset=None, ban_ttl=86400, breaker=None):
        self.store_path, self.log_path = store_path, log_path
        self.db = sqlite3.connect(db_path)
        self.db.executescript(SCHEMA)
        self.cloudflare = cloudflare_ranges()
        self.rdns = concurrent.futures.ThreadPoolExecutor(max_workers=4) if rdns else None
        self.rdns_pending, self.rdns_cache = [], {}  # ip -> (result, checked at); IPs stay in memory only
        self.ipset, self.ban_ttl, self.breaker, self.tripped = ipset, ban_ttl, breaker, False
        self.agg, self.rdns_agg, self.status = Counter(), Counter(), Counter()
        self.timings, self.lines = [], 0
        self._load_store()

    def _load_store(self):
        self.store_mtime = os.path.getmtime(self.store_path)
        self.verifier = Verifier(store_mod.load(self.store_path))

    def handle(self, raw):
        m = LINE.match(raw.rstrip(b"\n"))
        if not m:
            return
        sec, vhost, peer, cf, request, status, size, _ref, ua = m.groups()
        t = time.perf_counter_ns()
        addr, route = client_ip(peer.decode(), cf.decode(), self.cloudflare)
        when = datetime.datetime.fromtimestamp(int(sec), datetime.timezone.utc)
        if addr is None:
            cls, verdict = None, route
        else:
            cls, verdict = self.verifier.check(addr, ua, when.date().toordinal())
        self.timings.append((time.perf_counter_ns() - t) / 1000)
        self.lines += 1
        if cls is None and verdict == "not_crawler":
            return
        key = (when.strftime("%Y-%m-%dT%H"), vhost.decode(), cls or "-", verdict, kind_of(request), route)
        self.agg[key + ("n",)] += 1
        self.agg[key + ("bytes",)] += 0 if size == b"-" else int(size)
        self.status[(when.strftime("%Y-%m-%d"), vhost.decode(), cls or "-", verdict, status.decode())] += 1
        if addr is None:
            return
        ip = str(addr)
        if self.rdns and cls in RDNS_SUFFIXES:
            cached = self.rdns_cache.get(ip)
            if cached and cached[1] >= time.time() - RDNS_TTL:
                if verdict in DENY and cached[0] == "pass":
                    self.trip(vhost.decode(), cls)
            else:
                self.rdns_cache[ip] = ("pending", time.time())
                fut = self.rdns.submit(fcrdns, ip, cls)
                self.rdns_pending.append((when.strftime("%Y-%m-%d"), cls, verdict, vhost.decode(), ip, fut))
        if self.ipset and verdict == "never" and route == "direct":
            subprocess.run(["ipset", "add", self.ipset, ip, "timeout", str(self.ban_ttl), "-exist"], check=False)

    def flush(self):
        still = []
        for item in self.rdns_pending:
            day, cls, verdict, site, ip, fut = item
            if not fut.done():
                still.append(item)
                continue
            try:
                result, provider = fut.result()
            except Exception:
                result, provider = "error", "-"
            self.rdns_cache[ip] = (result, time.time())
            self.rdns_agg[(day, cls, verdict, result, provider)] += 1
            if verdict in DENY and result == "pass":
                self.trip(site, cls)
        self.rdns_pending = still
        self.db.executemany("INSERT INTO status VALUES (?,?,?,?,?,?) ON CONFLICT DO UPDATE SET n = n + excluded.n",
                            [k + (v,) for k, v in self.status.items()])
        self.status.clear()
        rows = {}
        for (*key, field), v in self.agg.items():
            rows.setdefault(tuple(key), [0, 0])[0 if field == "n" else 1] += v
        self.db.executemany("INSERT INTO agg VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO UPDATE SET "
                            "n = n + excluded.n, bytes = bytes + excluded.bytes",
                            [k + tuple(v) for k, v in rows.items()])
        self.db.executemany("INSERT INTO rdns VALUES (?,?,?,?,?,?) ON CONFLICT DO UPDATE SET n = n + excluded.n",
                            [k + (v,) for k, v in self.rdns_agg.items()])
        if self.timings:
            s = sorted(self.timings)
            usage = resource.getrusage(resource.RUSAGE_SELF) if resource else None
            self.db.execute("INSERT OR REPLACE INTO perf VALUES (?,?,?,?,?,?)",
                            (datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M"), self.lines,
                             usage.ru_utime + usage.ru_stime if usage else None, usage.ru_maxrss if usage else None,
                             s[len(s) // 2], s[int(len(s) * 0.99)]))
        self.db.commit()
        self.agg.clear()
        self.rdns_agg.clear()
        self.timings, self.lines = [], 0
        cutoff = time.time() - RDNS_TTL
        if len(self.rdns_cache) > 100_000:
            self.rdns_cache = {ip: v for ip, v in self.rdns_cache.items() if v[1] >= cutoff}

    def trip(self, site, cls):
        """The list says deny, the vendor's own FCrDNS says genuine. Record it and pull enforcement everywhere."""
        action = "none"
        if self.breaker and not self.tripped:
            done = subprocess.run([self.breaker, "off", "all"], capture_output=True, text=True)
            action = "enforcement off" if done.returncode == 0 else "breaker failed: " + done.stderr.strip()[-200:]
            self.tripped = done.returncode == 0
        print(f"GUARD list/FCrDNS disagreement site={site} cls={cls} action={action}", flush=True)
        self.db.execute("INSERT INTO guard VALUES (?,?,?,?)",
                        (datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), site, cls, action))
        self.db.commit()

    def _offset(self, inode=None, offset=None):
        if inode is None:
            row = self.db.execute("SELECT value FROM state WHERE key = 'position'").fetchone()
            return tuple(map(int, row[0].split(":"))) if row else (None, None)
        self.db.execute("INSERT OR REPLACE INTO state VALUES ('position', ?)", (f"{inode}:{offset}",))

    def run(self):
        saved_inode, saved_offset = self._offset()
        last_flush = time.time()
        while True:
            try:
                fh = open(self.log_path, "rb")
            except FileNotFoundError:
                time.sleep(5)
                continue
            inode = os.fstat(fh.fileno()).st_ino
            if inode == saved_inode and saved_offset <= os.fstat(fh.fileno()).st_size:
                fh.seek(saved_offset)
            while True:
                raw = fh.readline()
                if raw.endswith(b"\n"):
                    self.handle(raw)
                    continue
                if raw:
                    fh.seek(-len(raw), os.SEEK_CUR)  # partial line: wait for the rest
                if time.time() - last_flush >= 60:
                    self._offset(inode, fh.tell())
                    self.flush()
                    last_flush = time.time()
                    if os.path.getmtime(self.store_path) != self.store_mtime:
                        self._load_store()
                    try:
                        st = os.stat(self.log_path)
                        if st.st_ino != inode or st.st_size < fh.tell():
                            break  # rotated or truncated: reopen from the start
                    except FileNotFoundError:
                        break
                time.sleep(1)
            fh.close()
            saved_inode, saved_offset = None, None
