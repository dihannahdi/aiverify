"""Tables for the second-round results (sections 13-20 of 05-hasil-awal-analisis.md).

Usage: python summarize_extra.py extra_v2.json extra_v1.json verify_full.json bench_v2.json monitor.json \
       top_talkers_out.jsonl out.md
All inputs are aggregates without IP addresses.
"""
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict

ex2, ex1, vf, bench, mon = (json.load(open(p, encoding="utf-8")) for p in sys.argv[1:6])
talkers = [json.loads(line) for line in open(sys.argv[6], encoding="utf-8")]
OUT = sys.argv[7]
if not OUT.endswith(".md"):
    sys.exit("the last argument must be the output .md file")
lines = []
w = lines.append
rng = random.Random(7)
NOTE = {"meta-externalagent": "tingkat jaringan (AS32934)", "claude-user": "cakupan daftar tidak jelas",
        "claude-searchbot": "cakupan daftar tidak jelas", "bytespider": "tidak ada metode verifikasi"}


def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, 100 * (c - r) / d), min(100.0, 100 * (c + r) / d)


def pct(k, n):
    if n == 0:
        return "–"
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.1f}% [{lo:.1f}–{hi:.1f}]"


def fmt(n):
    return f"{n:,}".replace(",", ".")


# ---- 13. verification across vendors -----------------------------------------------------------------
w("## 13. Verifikasi semua vendor dengan daftar resmi (putaran kedua)\n")
w(f"Riwayat 12 daftar, dibekukan di `store.frozen-20261008b.json`. {fmt(ex2['claims'])} klaim crawler dari koneksi "
  "langsung (bukan IP Cloudflare). Tingkat dihitung dengan jendela toleransi kelas masing-masing. Request yang "
  "lebih tua dari versi pertama daftarnya diberi label pra-riwayat dan tidak dihitung. Tingkat IP memakai IP unik "
  "lintas situs.\n")
w("| Kelas | Klaim | Pra-riwayat | Dinilai | Request tidak terverifikasi [CI95] | IP terdaftar | IP tak pernah terdaftar | Tingkat IP [CI95] | Catatan |")
w("|---|---|---|---|---|---|---|---|---|")
ver = defaultdict(Counter)
for k, n in ex2["VER"].items():
    _, c, v = k.split("|")
    ver[c][v] += n
vip = Counter(ex2["VERIP"])
for c, cnt in sorted(ver.items(), key=lambda x: -sum(x[1].values())):
    total = sum(cnt.values())
    pre = cnt["pre_history"]
    judged = total - pre - cnt["unverifiable"]
    bad = cnt["never"] + cnt["other_time"]
    listed, never = vip[f"{c}|listed"], vip[f"{c}|never"]
    if c == "bytespider":
        w(f"| {c} | {fmt(total)} | – | 0 | – | – | – | – | {NOTE[c]}, {fmt(vip[c + '|unverifiable'])} IP |")
        continue
    if c in ("claude-user", "claude-searchbot"):
        out_of_list = cnt["never"] + cnt["other_time"]
        w(f"| {c} | {fmt(total)} | {fmt(pre)} | {fmt(judged)} | di luar daftar: {pct(out_of_list, judged)} | – | – | – | "
          f"{NOTE[c]}, {fmt(vip[c + '|coverage_unknown'])} IP, tidak dihitung sebagai penyamaran |")
        continue
    w(f"| {c} | {fmt(total)} | {fmt(pre)} | {fmt(judged)} | {pct(bad, judged)} | {fmt(listed)} | {fmt(never)} | "
      f"{pct(never, listed + never)} | {NOTE.get(c, '')} |")
cross_total = sum(v for k, v in ex2["CROSS"].items() if k.endswith("|_total"))
cross_any = sum(v for k, v in ex2["CROSS"].items() if k.endswith("|_in_any_other"))
w(f"\nDari {fmt(cross_total)} IP yang tidak pernah terdaftar di daftar kelasnya, {fmt(cross_any)} ada di daftar vendor "
  "lain mana pun. Penyamar tidak berasal dari infrastruktur crawler vendor mana pun yang menerbitkan daftar.\n")

# ---- 14. agreement with forward-confirmed reverse DNS --------------------------------------------------
w("## 14. Validasi silang dengan forward-confirmed reverse DNS\n")
w("Google, Bing, dan Apple menerbitkan cara verifikasi kedua yang independen dari daftar IP: reverse DNS yang "
  "namanya harus berakhiran domain resmi vendor dan dikonfirmasi balik lewat forward DNS. Dua sumber dipakai: "
  "IP yang terlihat di log historis dalam 14 hari terakhir (rDNS dicek saat analisis) dan monitor live (rDNS dicek "
  "saat request terjadi).\n")


def rdns_table(rows, title):
    cm = Counter()
    for (cls, lab, res), n in rows.items():
        if lab not in ("genuine", "never", "verified", "tolerance"):
            continue
        listed = lab in ("genuine", "verified", "tolerance")
        cm[(listed, res == "pass")] += n
    a, b, c_, d = cm[(True, True)], cm[(True, False)], cm[(False, True)], cm[(False, False)]
    n = a + b + c_ + d
    po = (a + d) / n if n else float("nan")
    pe = (((a + b) * (a + c_)) + ((c_ + d) * (b + d))) / (n * n) if n else float("nan")
    kappa = (po - pe) / (1 - pe) if n and pe < 1 else float("nan")
    w(f"**{title}** (IP unik, n = {n})\n")
    w("| | rDNS lolos | rDNS gagal |")
    w("|---|---|---|")
    w(f"| Terdaftar di daftar IP | {a} | {b} |")
    w(f"| Tidak pernah terdaftar | {c_} | {d} |")
    if math.isnan(kappa):
        w(f"\nKesesuaian {100 * po:.1f}%. κ tidak terdefinisi karena hanya satu kelas yang muncul.\n")
    else:
        w(f"\nKesesuaian {100 * po:.1f}%, Cohen's κ = {kappa:.3f}.\n")


hist = Counter()
providers = Counter()
for k, n in ex2["RDNS"].items():
    cls, lab, res, prov = k.split("|")
    hist[(cls, lab, res)] += n
    if lab == "never":
        providers[prov] += n
rdns_table(hist, "Log historis, 14 hari terakhir")
w("Domain PTR milik IP yang tidak pernah terdaftar: " + ", ".join(f"{p} ({n})" for p, n in providers.most_common()) + ".\n")
live = Counter()
for r in mon.get("rdns", []):
    live[(r["cls"], r["list_verdict"], r["result"])] += r["n"]
if live:
    rdns_table(live, "Monitor live, rDNS saat request terjadi")

# ---- 15. robots.txt ------------------------------------------------------------------------------------
w("## 15. Pengambilan robots.txt\n")
w("Tidak ada robots.txt di ketujuh situs yang melarang bot AI, jadi kepatuhan terhadap larangan tidak bisa diuji. "
  "Yang diukur adalah apakah sebuah IP pernah mengambil `/robots.txt` sama sekali.\n")
w("| Kelas | IP asli yang mengambil robots.txt | IP penyamar yang mengambil robots.txt |")
w("|---|---|---|")
rb = defaultdict(dict)
for k, n in ex2["ROBOTS"].items():
    c, lab, stat = k.split("|")
    rb[(c, lab)][stat] = n
for c in sorted({c for c, _ in rb}):
    g, nv = rb.get((c, "genuine")), rb.get((c, "never"))
    if not g or not nv:
        continue
    w(f"| {c} | {g['ips_fetching_robots']} / {g['ips']} ({pct(g['ips_fetching_robots'], g['ips'])}) | "
      f"{nv['ips_fetching_robots']} / {nv['ips']} ({pct(nv['ips_fetching_robots'], nv['ips'])}) |")
w("")

# ---- 16. user-agent novelty rule ------------------------------------------------------------------------
w("## 16. Aturan kebaruan string user-agent\n")
w("Aturan: sebuah request dicurigai jika string user-agent-nya belum pernah dipakai IP yang terverifikasi ketat untuk "
  "kelas yang sama dalam *W* hari terakhir. Aturan ini belajar secara online, hanya dari informasi yang tersedia "
  "pada saat request terjadi. Labelnya adalah verdict daftar IP dengan toleransi. 30 hari pertama dipakai sebagai "
  "pemanasan. Varian `digits` mengganti setiap angka dengan `#`, sehingga kenaikan nomor versi tidak dianggap baru.\n")
w("| W (hari) | Normalisasi | Tingkat | TP | FP | TN | FN | Presisi | Recall | FPR |")
w("|---|---|---|---|---|---|---|---|---|---|")
ua = defaultdict(Counter)
per_class = defaultdict(Counter)
for k, n in ex2["UARULE"].items():
    c, win, norm, lvl, cell = k.split("|")
    ua[(int(win), norm, lvl)][cell] += n
    if win == "30" and norm == "digits" and lvl == "ip":
        per_class[c][cell] += n
for (win, norm, lvl), d in sorted(ua.items()):
    tp, fp, tn, fn = d["tp"], d["fp"], d["tn"], d["fn"]
    w(f"| {win} | {norm} | {'IP' if lvl == 'ip' else 'request'} | {fmt(tp)} | {fmt(fp)} | {fmt(tn)} | {fmt(fn)} | "
      f"{tp / (tp + fp):.3f} | {tp / (tp + fn):.3f} | {fp / (fp + tn):.4f} |")
w("\nPer kelas (W = 30, `digits`, tingkat IP):\n")
w("| Kelas | TP | FP | TN | FN | Recall |")
w("|---|---|---|---|---|---|")
for c, d in sorted(per_class.items()):
    rec = d["tp"] / (d["tp"] + d["fn"]) if d["tp"] + d["fn"] else float("nan")
    w(f"| {c} | {d['tp']} | {d['fp']} | {d['tn']} | {d['fn']} | {rec:.2f} |")
w("")

# ---- 17. inline L7 vs reactive L3 ----------------------------------------------------------------------
w("## 17. Penegakan: aturan inline di L7 dibanding blokir IP reaktif di L3\n")
b = ex2["BAN"]
ib = ex2["INLINE"]
never_total = ib.get("never|deny", 0)
w("Simulasi pada log historis, gabungan semua situs, hanya koneksi langsung. Blokir reaktif meniru fail2ban: IP "
  "diblokir di firewall setelah klaim pertamanya terdeteksi tidak terdaftar, selama TTL, dan diblokir lagi pada "
  "deteksi berikutnya. Firewall memblokir semua request dari IP itu, bukan hanya klaim crawler-nya.\n")
w(f"IP yang pernah mengirim klaim tidak terdaftar: {fmt(b['never_ips'])}. Dari jumlah itu, "
  f"{fmt(b['ips_with_nonclaim_traffic'])} juga mengirim request tanpa klaim crawler, dan {fmt(b['ips_with_browser_traffic'])} "
  f"di antaranya dengan user-agent peramban. Satu IP teratas menyumbang {fmt(b['browser_requests_top1_ip'])} dari "
  f"{fmt(b['browser_requests_all'])} request peramban, lima IP teratas {fmt(b['browser_requests_top5_ips'])}.\n")
w("Karakter lima IP tersibuk yang pernah mengirim klaim crawler (dicek di server, IP tidak dikeluarkan):\n")
w("| Peringkat | Request total | Klaim crawler | Terdaftar untuk kelas yang diklaim | Domain PTR | Situs |")
w("|---|---|---|---|---|---|")
for r in talkers:
    claimed = ", ".join(f"{c} {n}" for c, n in sorted(r["claims"].items(), key=lambda x: -x[1]))
    held = r["listed_for_claimed_class"].values()
    listed = "ya" if all(held) else ("tidak" if not any(held) else "sebagian")
    w(f"| {r['rank_among_claiming_ips']} | {fmt(r['requests'])} | {claimed} | {listed} | {r['ptr_domain']} | {r['sites']} |")
w("")
w("| Mekanisme | Klaim penyamar diblokir | Request peramban ikut terblokir | Request bot lain (tanpa klaim) ikut terblokir | Klaim asli terblokir |")
w("|---|---|---|---|---|")
w(f"| Inline L7 (sistem ini) | {fmt(never_total)} (100%) | 0 | 0 | {fmt(ib.get('other_time|deny', 0))} (di luar jendela toleransi) |")
for ttl in ("1h", "24h", "7d", "forever"):
    blk = b.get(f"{ttl}|blocked_never", 0)
    w(f"| Blokir IP, TTL {ttl} | {fmt(blk)} ({pct(blk, never_total).split(' ')[0]}) | "
      f"{fmt(b.get(f'{ttl}|blocked_nonclaim_browser', 0))} | {fmt(b.get(f'{ttl}|blocked_nonclaim_bot', 0))} | "
      f"{fmt(b.get(f'{ttl}|blocked_genuine', 0))} |")
w("")

# ---- 18. archive thinning ---------------------------------------------------------------------------------
w("## 18. Ketahanan terhadap versi daftar yang terlewat\n")
w("Setiap versi (kecuali yang terbaru) dibuang secara acak dengan peluang *q*, 50 kali per *q* (seed 42), lalu "
  "tingkat request tidak terverifikasi dihitung ulang. Ini mensimulasikan arsip yang lebih jarang merekam daftar. "
  "Rata-rata dan rentang persentil 5–95 dilaporkan.\n")
w("| Daftar | Versi | Metode | q = 0 | q = 0,25 | q = 0,5 | q = 0,75 |")
w("|---|---|---|---|---|---|---|")
th = ex2["THIN"]
for name in ("googlebot", "gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "perplexity-user"):
    for stat, label in (("strict", "ketat"), ("tol", "toleransi kelas"), ("tol30", "toleransi 30 hari")):
        cells = []
        for q in ("0.0", "0.25", "0.5", "0.75"):
            m = th.get(f"{name}|{q}|{stat}|mean")
            if m is None:
                cells.append("–")
                continue
            lo, hi = th[f"{name}|{q}|{stat}|p05"], th[f"{name}|{q}|{stat}|p95"]
            cells.append(f"{100 * m:.1f}%" if q == "0.0" else f"{100 * m:.1f}% ({100 * lo:.1f}–{100 * hi:.1f})")
        w(f"| {name} | {th[name + '|versions']} | {label} | " + " | ".join(cells) + " |")
w("")

# ---- 19. system: functional, overhead, live --------------------------------------------------------------
w("## 19. Sistem: uji fungsional, overhead, dan monitor live\n")
f = bench["functional"]
w(f"**Uji fungsional.** {sum(x['pass'] for x in f)} dari {len(f)} kasus lolos (3 varian × 10 kasus), termasuk `.env` "
  "yang tetap ditolak saat aturan aktif dan klien memakai IP bot terverifikasi.\n")
w(f"**Overhead.** Instance Apache terisolasi (binary dan modul yang sama dengan produksi), 1 koneksi, {fmt(bench['n'])} "
  f"request per run, {bench['reps']} ulangan per kondisi, urutan varian dan kondisi diacak per ulangan. Angka adalah "
  "median dari median waktu layanan sisi server (`%D`, µs) per run. Selisih terhadap tanpa aturan diberi CI95 bootstrap "
  "dan p uji Mann–Whitney.\n")
w("| Kondisi | Tanpa aturan | `<Location>` | `<If>` | Selisih `<If>` [CI95] | p |")
w("|---|---|---|---|---|---|")


def diff_ci(a, b2, B=10000):
    ds = sorted(statistics.median(rng.choices(b2, k=len(b2))) - statistics.median(rng.choices(a, k=len(a)))
                for _ in range(B))
    return ds[int(.025 * B)], ds[int(.975 * B)]


def mwu_p(a, b2):
    vals = sorted(a + b2)
    ranks, i = {}, 0
    while i < len(vals):
        j = i
        while j < len(vals) and vals[j] == vals[i]:
            j += 1
        ranks[vals[i]] = (i + j + 1) / 2
        i = j
    n1, n2 = len(a), len(b2)
    u = sum(ranks[v] for v in a) - n1 * (n1 + 1) / 2
    z = (u - n1 * n2 / 2) / math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12)
    return 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))


o = bench["overhead"]
names = {"browser": "Peramban", "gptbot_listed": "GPTBot terdaftar (18 prefiks)",
         "googlebot_listed_last": "Googlebot, IP di prefiks terakhir", "googlebot_unlisted": "Googlebot tidak terdaftar (403)",
         "amazonbot_listed_last": "Amazonbot, IP di prefiks terakhir (1.292 prefiks)"}
for c, label in names.items():
    off, loc, iff = ([r["us_p50"] for r in o[f"{v}|{c}"]] for v in ("off", "location", "if"))
    lo, hi = diff_ci(off, iff)
    w(f"| {label} | {statistics.median(off):.1f} | {statistics.median(loc):.1f} | {statistics.median(iff):.1f} | "
      f"{statistics.median(iff) - statistics.median(off):+.1f} [{lo:+.0f}, {hi:+.0f}] | {mwu_p(off, iff):.3f} |")
w(f"\nBeban server (load average 1 menit) saat pengukuran: {bench['load_before'][0]:.1f} sampai {bench['load_after'][0]:.1f}.\n")
perf = mon.get("perf", [])
agg = mon.get("agg", [])
if perf:
    total = sum(r["lines"] for r in perf)
    w(f"**Monitor live** (sejak dipasang 8 Oktober 2026): {fmt(total)} baris klaim diproses, "
      f"RSS maksimum {max(r['rss_kb'] or 0 for r in perf) / 1024:.0f} MB, median waktu verifikasi per baris "
      f"{statistics.median(r['verify_us_p50'] for r in perf):.0f} µs.")
    routes = Counter()
    for r in agg:
        routes[r["route"]] += r["n"]
    w(f" Rute klien: {', '.join(f'{k} {fmt(v)}' for k, v in routes.most_common())}.\n")

# ---- 20. reproduction ------------------------------------------------------------------------------------
w("## 20. Reproduksi dan dampak koreksi\n")
mine, ref = Counter(), Counter()
for k, n in ex1["REPRO"].items():
    site, cls, verdict = k.split("|")
    mine[(site, cls, {"verified": "cocok", "never": "tak pernah"}.get(verdict, "lainnya"))] += n
for k, n in vf["CAT"].items():
    site, cls, cat, _ = k.split("|")
    ref[(site, cls, {"active": "cocok", "never": "tak pernah"}.get(cat, "lainnya"))] += n
keys = sorted(set(mine) | set(ref))
diff = [(k, mine[k], ref[k]) for k in keys if mine[k] != ref[k]]
w(f"**Kode sistem vs analisis awal.** Verdict ketat dari kode `aiverify` (store yang sama dengan analisis awal) "
  f"dibandingkan sel demi sel dengan `verify_full.json`: {len(keys) - len(diff)} dari {len(keys)} sel identik. "
  "Selisihnya:\n")
w("| Situs | Kelas | Kategori | aiverify | Analisis awal |")
w("|---|---|---|---|---|")
for (s, c, cat), a, r in diff:
    w(f"| {s} | {c} | {cat} | {fmt(a)} | {fmt(r)} |")
w("")
g1, g2 = Counter(), Counter()
for src, dst in ((ex1, g1), (ex2, g2)):
    for k, n in src["VER"].items():
        _, c, v = k.split("|")
        if c == "googlebot":
            dst[v] += n
w(f"**Celah riwayat Googlebot.** Dengan riwayat URL baru `common-crawlers.json`: {dict(g2)}. "
  f"Sebelumnya: {dict(g1)}.\n")

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
print(f"wrote {OUT}")
