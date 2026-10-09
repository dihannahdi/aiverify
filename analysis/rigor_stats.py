"""Statistical rigor layer: confidence intervals, trend tests, lag statistics, sensitivity analyses.

Usage: python rigor_stats.py full_out.json verify_out.json out.md
"""
import json
import math
import statistics
import sys
from collections import defaultdict

FULL, VERIFY, DST = sys.argv[1], sys.argv[2], sys.argv[3]
full, ver = json.load(open(FULL)), json.load(open(VERIFY))
VERIFIABLE = ["googlebot", "gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "perplexity-user"]
AI = ["gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "perplexity-user", "claudebot",
      "claude-searchbot", "claude-user", "meta-externalagent", "bytespider", "amazonbot", "ccbot"]
USER_TRIGGERED = {"chatgpt-user", "perplexity-user", "claude-user"}
VENDORS = {
    "OpenAI": (["gptbot", "oai-searchbot", "chatgpt-user"], ["openai"]),
    "Perplexity": (["perplexitybot", "perplexity-user"], ["perplexity"]),
    "Anthropic": (["claudebot", "claude-searchbot", "claude-user"], ["anthropic"]),
    "Meta": (["meta-externalagent"], ["meta_ai"]),
    "ByteDance": (["bytespider"], []),
    "Amazon": (["amazonbot"], []),
}
EDGES = [(0, "0"), (7, "1-7"), (30, "8-30"), (90, "31-90"), (180, "91-180"), (365, "181-365"), (10**9, ">365")]
out = []
w = out.append


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return 100 * p, 100 * max(0.0, centre - half), 100 * min(1.0, centre + half)


def fmt_ci(k, n):
    r = wilson(k, n)
    return "-" if r is None else f"{r[0]:.1f}% [{r[1]:.1f}–{r[2]:.1f}]"


def mann_kendall(x):
    n = len(x)
    s = sum((x[j] > x[i]) - (x[j] < x[i]) for i in range(n) for j in range(i + 1, n))
    # variance with tie correction
    ties = defaultdict(int)
    for v in x:
        ties[v] += 1
    var = (n * (n - 1) * (2 * n + 5) - sum(t * (t - 1) * (2 * t + 5) for t in ties.values())) / 18
    if var <= 0:
        return s, 0.0, 1.0
    z = (s - 1) / math.sqrt(var) if s > 0 else (s + 1) / math.sqrt(var) if s < 0 else 0.0
    p = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    return s, z, p


def sen_slope(x):
    slopes = [(x[j] - x[i]) / (j - i) for i in range(len(x)) for j in range(i + 1, len(x))]
    return statistics.median(slopes) if slopes else 0.0


# ---- reshape -----------------------------------------------------------------------------------
H = defaultdict(int)
for k, v in ver["H"].items():
    s, c, b = k.split("|")
    H[(s, c, b)] += v
sites = sorted({s for s, _, _ in H}, key=lambda s: -full["lines"].get(s, 0))


def unverified_at(items, n_days):
    n = sum(v for b, v in items.items() if b not in ("cf", "bad"))
    ok = sum(items.get(name, 0) for edge, name in EDGES if edge <= n_days)
    return n - ok, n


def knee(items, threshold_pp):
    rates = []
    for edge, _ in EDGES[:-1]:
        k, n = unverified_at(items, edge)
        rates.append(100 * k / n if n else 0.0)
    for i in range(len(rates) - 1):
        if rates[i] - rates[i + 1] < threshold_pp:
            return EDGES[i][0]
    return EDGES[len(rates) - 1][0]


w("## 11. Uji statistik dan sensitivitas\n")
w(f"Versi daftar IP yang dipakai: {ver['versions']} (isi unik: {ver['unique_contents']}). "
  f"Baris log: {ver['lines']:,}.\n")

# ---- A. verification with CI, request- and IP-level --------------------------------------------
w("### 11.1 Proporsi klaim crawler yang tidak terverifikasi, dengan selang kepercayaan 95% (Wilson)\n")
w("Tingkat request dihitung pada N siku kelas masing-masing. Tingkat IP = porsi IP berbeda yang tidak pernah ada di "
  "versi daftar mana pun. Tingkat IP penting karena request dari IP yang sama tidak saling independen.\n")
w("| Kelas | N siku | Request: tidak terverifikasi [CI95] | n request | IP: tidak pernah terdaftar [CI95] | n IP |")
w("|---|---|---|---|---|---|")
ips = defaultdict(int)
for k, v in ver["IPS"].items():
    s, c, stat = k.split("|")
    ips[(c, stat)] += v
knees = {}
for c in VERIFIABLE:
    items = defaultdict(int)
    for (s, cc, b), v in H.items():
        if cc == c:
            items[b] += v
    kn = knee(items, 1.0)
    knees[c] = kn
    k, n = unverified_at(items, kn)
    w(f"| {c} | {kn} hari | {fmt_ci(k, n)} | {n:,} | {fmt_ci(ips[(c, 'never_ips')], ips[(c, 'ips')])} | "
      f"{ips[(c, 'ips')]:,} |")

# ---- B. direction of mismatch ------------------------------------------------------------------
w("\n### 11.2 Arah ketidakcocokan (tingkat request)\n")
w("| Kelas | Cocok versi berlaku | IP baru masuk daftar setelah dipakai | IP dipakai setelah dihapus | Bolak-balik | Tak pernah |")
w("|---|---|---|---|---|---|")
cat = defaultdict(int)
for k, v in ver["CAT"].items():
    s, c, kind, _ = k.split("|")
    cat[(c, kind)] += v
for c in VERIFIABLE:
    n = sum(cat[(c, kind)] for kind in ("active", "added_later", "removed_earlier", "flapping", "never"))
    if not n:
        continue
    w(f"| {c} | " + " | ".join(f"{100 * cat[(c, kind)] / n:.1f}%" for kind in
                              ("active", "added_later", "removed_earlier", "flapping", "never")) + " |")

# ---- C. publication lag ------------------------------------------------------------------------
w("\n### 11.3 Keterlambatan publikasi IP crawler (tingkat IP)\n")
w("Teramati = hari dari pemakaian pertama yang teramati sampai versi pertama yang memuat IP. "
  "Terbukti = hari sampai versi terakhir yang *masih belum* memuat IP; hanya dihitung jika isi versi itu tidak pernah "
  "muncul lagi sesudahnya. Keterlambatan sebenarnya ≥ nilai terbukti.\n")
w("| Kelas | IP | IP dengan lag terbukti > 0 | Median terbukti (hari) | P90 terbukti | Maks terbukti | "
  "Median teramati | Tidak dapat dibuktikan |")
w("|---|---|---|---|---|---|---|---|")
for c in VERIFIABLE:
    rows = ver["LAG"].get(c, [])
    if not rows:
        continue
    proven = [p for p, _ in rows if p is not None]
    pos = sorted(p for p in proven if p > 0)
    obs = sorted(o for _, o in rows)
    unprov = sum(1 for p, _ in rows if p is None)
    if pos:
        p90 = pos[min(len(pos) - 1, int(0.9 * len(pos)))]
        stats_txt = f"{statistics.median(pos):.0f} | {p90} | {pos[-1]}"
    else:
        stats_txt = "- | - | -"
    w(f"| {c} | {len(rows):,} | {len(pos):,} ({fmt_ci(len(pos), len(rows))}) | {stats_txt} | "
      f"{statistics.median(obs):.0f} | {unprov:,} |")

# ---- D. trend tests ----------------------------------------------------------------------------
w("\n### 11.4 Uji tren bulanan request crawler AI (Mann–Kendall, slope Sen)\n")
w("Hanya bulan dengan trafik nyata (≥ 1.000 request non-internal). Karena ada satu uji per situs, p dikoreksi "
  "dengan metode Holm–Bonferroni. Arah ditentukan dari p Holm < 0,05.\n")
w("| Situs | Bulan | S | Z | p | p Holm | Slope Sen (request/bulan) | Arah |")
w("|---|---|---|---|---|---|---|---|")
monthly = defaultdict(lambda: defaultdict(int))
real = defaultdict(lambda: defaultdict(int))
for k, v in full["A"].items():
    s, m, c, f = k.split("|")
    if f != "req":
        continue
    if c in AI:
        monthly[s][m] += v
    if c != "internal":
        real[s][m] += v
trend_rows = []
for s in sites:
    months = sorted(m for m, v in real[s].items() if v >= 1000)
    series = [monthly[s][m] for m in months]
    if len(series) < 4:
        continue
    S, Z, p = mann_kendall(series)
    trend_rows.append([s, len(series), S, Z, p, sen_slope(series)])
# Holm: sort p ascending, multiply the i-th smallest by (m - i), keep the running maximum, cap at 1.
running = 0.0
for i, row in enumerate(sorted(trend_rows, key=lambda r: r[4])):
    running = max(running, min(1.0, (len(trend_rows) - i) * row[4]))
    row.append(running)
for s, n, S, Z, p, slope, p_holm in trend_rows:
    direction = "naik" if p_holm < 0.05 and S > 0 else "turun" if p_holm < 0.05 and S < 0 else "tidak signifikan"
    w(f"| {s} | {n} | {S} | {Z:.2f} | {p:.4f} | {p_holm:.4f} | {slope:,.1f} | {direction} |")

# ---- E. sensitivity ----------------------------------------------------------------------------
w("\n### 11.5 Sensitivitas terhadap parameter yang dipilih peneliti\n")
w("Ambang siku kurva toleransi (poin persentase) → N terpilih per kelas:\n")
w("| Ambang | " + " | ".join(VERIFIABLE) + " |")
w("|---|" + "---|" * len(VERIFIABLE))
for th in (0.5, 1.0, 2.0):
    cells = []
    for c in VERIFIABLE:
        items = defaultdict(int)
        for (s, cc, b), v in H.items():
            if cc == c:
                items[b] += v
        cells.append(f"{knee(items, th)} hari")
    w(f"| {th} pp | " + " | ".join(cells) + " |")

req, byt, page, refs = defaultdict(int), defaultdict(int), defaultdict(int), defaultdict(int)
for k, v in full["A"].items():
    s, m, c, f = k.split("|")
    {"req": req, "bytes": byt, "page": page}[f][(s, c)] += v
for k, v in full["R"].items():
    s, m, p = k.split("|")
    refs[(s, p)] += v
w("\nAmbang rasio kebijakan P3 → total semua situs:\n")
w("| Ambang rasio | Request diblokir | Byte dihemat | Rujukan berisiko |")
w("|---|---|---|---|")
all_sites = sorted({s for s, _ in req})
tot_bytes = sum(v for (s, c), v in byt.items() if c != "internal") or 1
for cutoff in (100, 1000, 10000):
    br = bb = rr = 0
    for s in all_sites:
        for vendor, (cl, pl) in VENDORS.items():
            crawl = [c for c in cl if c not in USER_TRIGGERED]
            cp = sum(page[(s, c)] for c in crawl)
            r = sum(refs[(s, p)] for p in pl)
            if cp and (r == 0 or cp / r > cutoff):
                br += sum(req[(s, c)] for c in crawl)
                bb += sum(byt[(s, c)] for c in crawl)
                rr += r
    w(f"| {cutoff:,} : 1 | {br:,} | {100 * bb / tot_bytes:.2f}% | {rr:,} |")

open(DST, "w", encoding="utf-8").write("\n".join(out) + "\n")
sys.stdout.reconfigure(encoding="utf-8")
print("\n".join(out))
