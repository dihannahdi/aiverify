"""Turn the aggregate JSON from analyze_logs.py into thesis result tables (Markdown)."""
import json
import sys
from collections import defaultdict

SRC, DST = sys.argv[1], sys.argv[2]
d = json.load(open(SRC))

VENDORS = {
    "Google": (["googlebot"], ["google_search"]),
    "OpenAI": (["gptbot", "oai-searchbot", "chatgpt-user"], ["openai"]),
    "Perplexity": (["perplexitybot", "perplexity-user"], ["perplexity"]),
    "Anthropic": (["claudebot", "claude-searchbot", "claude-user"], ["anthropic"]),
    "Meta": (["meta-externalagent"], ["meta_ai"]),
    "ByteDance": (["bytespider"], []),
    "Amazon": (["amazonbot"], []),
    "Microsoft": (["bingbot"], ["bing_search", "copilot"]),
}
AI = ["gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "perplexity-user", "claudebot",
      "claude-searchbot", "claude-user", "meta-externalagent", "bytespider", "amazonbot", "ccbot"]
USER_TRIGGERED = {"chatgpt-user", "perplexity-user", "claude-user"}
SEARCH = ["googlebot", "bingbot", "applebot"]
VERIFIABLE = ["googlebot", "gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "perplexity-user"]
RATIO_CUTOFF = 1000

# ---- reshape -----------------------------------------------------------------------------------
req = defaultdict(int)      # (site, cls) -> requests
byt = defaultdict(int)      # (site, cls) -> bytes
page = defaultdict(int)     # (site, cls) -> page requests
mreq = defaultdict(int)     # (month, cls) -> requests
months_by_site = defaultdict(set)
for k, v in d["A"].items():
    site, month, cls, field = k.split("|")
    months_by_site[site].add(month)
    if field == "req":
        req[(site, cls)] += v
        mreq[(month, cls)] += v
    elif field == "bytes":
        byt[(site, cls)] += v
    else:
        page[(site, cls)] += v
refs = defaultdict(int)     # (site, platform) -> referrals
mrefs = defaultdict(int)
for k, v in d["R"].items():
    site, month, plat = k.split("|")
    refs[(site, plat)] += v
    mrefs[(month, plat)] += v
ver = defaultdict(int)      # (site, cls, scheme, outcome)
for k, v in d["V"].items():
    site, cls, scheme, outcome = k.split("|")
    ver[(site, cls, scheme, outcome)] += v
sites = sorted(d["lines"], key=lambda s: -d["lines"][s])
classes = sorted({c for _, c in req})


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "-"


def ratio(c, r):
    if c == 0:
        return "-"
    if not r:
        return f"{c:,} : 0"
    x = c / r
    return f"{x:,.1f} : 1" if x < 10 else f"{x:,.0f} : 1"


out = []
w = out.append
w("# Hasil Awal Analisis Log Historis\n")
w(f"Sumber: {sum(d['lines'].values()):,} baris log dari {len(sites)} situs. Baris gagal dibaca: "
  f"{sum(d['bad'].values()):,}. Waktu proses di server: {d['seconds']:,} detik.\n")
w(f"Riwayat daftar IP yang dipakai (jumlah versi): {d['snapshot_counts']}\n")

# ---- 1. dataset --------------------------------------------------------------------------------
w("## 1. Dataset\n")
w("| Situs | Baris | Bulan pertama | Bulan terakhir | Jumlah bulan |")
w("|---|---|---|---|---|")
for s in sites:
    ms = sorted(months_by_site[s])
    w(f"| {s} | {d['lines'][s]:,} | {ms[0]} | {ms[-1]} | {len(ms)} |")

# ---- 2. composition ----------------------------------------------------------------------------
w("\n## 2. Komposisi trafik per situs (persentase request dan byte)\n")
w("| Situs | Browser | Bot mesin pencari | Crawler AI | Bot lain | Byte ke crawler AI |")
w("|---|---|---|---|---|---|")
for s in sites:
    tot_r = sum(req[(s, c)] for c in classes if c != "internal")
    tot_b = sum(byt[(s, c)] for c in classes if c != "internal")
    br = req[(s, "browser")]
    se = sum(req[(s, c)] for c in SEARCH)
    ai = sum(req[(s, c)] for c in AI)
    ob = req[(s, "other-bot")]
    ai_b = sum(byt[(s, c)] for c in AI)
    w(f"| {s} | {pct(br, tot_r)} | {pct(se, tot_r)} | {pct(ai, tot_r)} | {pct(ob, tot_r)} | {pct(ai_b, tot_b)} |")

# ---- 3. crawl-to-referral ----------------------------------------------------------------------
w(f"\n## 3. Rasio crawl terhadap rujukan per vendor (crawl = request halaman, bukan aset statis)\n")
w("| Situs | " + " | ".join(VENDORS) + " |")
w("|---|" + "---|" * len(VENDORS))
for s in sites:
    cells = []
    for vendor, (cls_list, plat_list) in VENDORS.items():
        c = sum(page[(s, x)] for x in cls_list)
        r = sum(refs[(s, p)] for p in plat_list)
        cells.append(ratio(c, r))
    w(f"| {s} | " + " | ".join(cells) + " |")
w("\nTotal semua situs:\n")
w("| Vendor | Crawl halaman | Rujukan | Rasio |")
w("|---|---|---|---|")
for vendor, (cls_list, plat_list) in VENDORS.items():
    c = sum(page[(s, x)] for s in sites for x in cls_list)
    r = sum(refs[(s, p)] for s in sites for p in plat_list)
    w(f"| {vendor} | {c:,} | {r:,} | {ratio(c, r)} |")

# ---- 4. verification ---------------------------------------------------------------------------
# Naive (today's list) comes from the main pass; it depends only on today's list, which is identical in both runs.
# Strict temporal and union come from the verification pass over the complete archive when it is supplied.
VERIFY_PATH = sys.argv[3] if len(sys.argv) > 3 else None
vh = defaultdict(int)
if VERIFY_PATH:
    for k, v in json.load(open(VERIFY_PATH))["H"].items():
        s_, c_, b_ = k.split("|")
        vh[(s_, c_, b_)] += v


def temporal_union(s, c):
    """(n, strict-temporal unverified, union unverified, cloudflare rows) for one site and class."""
    if VERIFY_PATH:
        n = sum(v for (ss, cc, b), v in vh.items() if ss == s and cc == c and b not in ("cf", "bad"))
        return n, n - vh[(s, c, "0")], vh[(s, c, "never")], vh[(s, c, "cf")]
    n = ver[(s, c, "temporal", "ok")] + ver[(s, c, "temporal", "no")]
    return n, ver[(s, c, "temporal", "no")], ver[(s, c, "union", "no")], ver[(s, c, "temporal", "cf")]


w("\n## 4. Verifikasi identitas crawler (IP Cloudflare dikeluarkan dari penyebut)\n")
w("Naif = daftar IP hari ini. Temporal = versi yang berlaku pada tanggal request. Gabungan = versi mana pun. "
  "Kolom temporal dan gabungan memakai arsip daftar IP yang lengkap.\n")
w("| Situs | Kelas | n | Tidak terverifikasi: naif | temporal | gabungan | Baris via Cloudflare |")
w("|---|---|---|---|---|---|---|")
for s in sites:
    for c in VERIFIABLE:
        n, no_t, no_u, cf = temporal_union(s, c)
        if n + cf == 0:
            continue
        no_n = ver[(s, c, "today", "no")]
        w(f"| {s} | {c} | {n:,} | {pct(no_n, n)} | {pct(no_t, n)} | {pct(no_u, n)} | {cf:,} |")
w("\nTotal semua situs:\n")
w("| Kelas | n | Naif | Temporal | Gabungan | Salah label oleh metode naif (naif − gabungan) |")
w("|---|---|---|---|---|---|")
for c in VERIFIABLE:
    agg = [temporal_union(s, c) for s in sites]
    n, no_t, no_u = sum(a[0] for a in agg), sum(a[1] for a in agg), sum(a[2] for a in agg)
    no_n = sum(ver[(s, c, "today", "no")] for s in sites)
    w(f"| {c} | {n:,} | {pct(no_n, n)} | {pct(no_t, n)} | {pct(no_u, n)} | {no_n - no_u:+,} |")

# ---- 5. monthly trend --------------------------------------------------------------------------
w("\n## 5. Rekap bulanan gabungan semua situs (deskriptif saja)\n")
w("**Jangan dikutip sebagai tren.** Komposisi situs berubah: ada situs yang masuk dan berhenti di tengah periode. "
  "Tren yang sah ada di bagian 9 (per situs) dan bagian 11.4 (uji Mann–Kendall).\n")
w("| Bulan | Total request | Crawler AI | Porsi AI | Rujukan OpenAI | Rujukan Perplexity | Rujukan Google |")
w("|---|---|---|---|---|---|---|")
for m in sorted({m for m, _ in mreq}):
    tot = sum(v for (mm, c), v in mreq.items() if mm == m and c != "internal")
    ai = sum(mreq[(m, c)] for c in AI)
    w(f"| {m} | {tot:,} | {ai:,} | {pct(ai, tot)} | {mrefs[(m, 'openai')]:,} | {mrefs[(m, 'perplexity')]:,} | "
      f"{mrefs[(m, 'google_search')]:,} |")

# ---- 6. policy replay --------------------------------------------------------------------------
TOL_PATH = sys.argv[3] if len(sys.argv) > 3 else None
unv180 = defaultdict(int)  # (site, cls) -> requests unverified with a 180-day tolerance window
if TOL_PATH:
    for k, v in json.load(open(TOL_PATH))["H"].items():
        site, cls, b = k.split("|")
        if b in ("181-365", ">365", "never"):
            unv180[(site, cls)] += v

w("\n## 6. Replay kebijakan akses\n")
w("P1 = blokir user-agent crawler AI (kecuali yang dipicu pengguna). "
  + ("P2 = blokir klaim crawler yang tidak terverifikasi dengan jendela toleransi 180 hari (byte P2 = estimasi dari "
     "rata-rata byte per request kelas itu di situs tersebut). " if TOL_PATH else
     "P2 = blokir klaim crawler yang tidak terverifikasi (temporal ketat). ") +
  f"P3 = blokir crawler vendor yang rasio crawl:rujukan-nya > {RATIO_CUTOFF}:1 atau tanpa rujukan di situs itu. "
  "P4 = gabungan P2 dan P3, tanpa menghitung ganda request yang kena keduanya.\n")
w("| Situs | Kebijakan | Request diblokir | Byte dihemat (dari total situs) | Rujukan berisiko | Googlebot terverifikasi diblokir |")
w("|---|---|---|---|---|---|")
bno = d["BNO"]
for s in sites:
    tot_b = sum(byt[(s, c)] for c in classes if c != "internal") or 1
    p1_cls = [c for c in AI if c not in USER_TRIGGERED]
    p1_r = sum(req[(s, c)] for c in p1_cls)
    p1_b = sum(byt[(s, c)] for c in p1_cls)
    p1_ref = sum(refs[(s, p)] for v, (cl, pl) in VENDORS.items() if set(cl) & set(p1_cls) for p in pl)
    if TOL_PATH:
        p2_r = sum(unv180[(s, c)] for c in VERIFIABLE)
        p2_b = sum(unv180[(s, c)] * byt[(s, c)] / req[(s, c)] for c in VERIFIABLE if req[(s, c)])
    else:
        p2_r = sum(bno.get(f"{s}|{c}|req", 0) for c in VERIFIABLE)
        p2_b = sum(bno.get(f"{s}|{c}|bytes", 0) for c in VERIFIABLE)
    p3_cls, p3_ref = [], 0
    for vendor, (cl, pl) in VENDORS.items():
        if vendor in ("Google", "Microsoft"):
            continue
        crawl_cls = [c for c in cl if c not in USER_TRIGGERED]
        c = sum(page[(s, x)] for x in crawl_cls)
        r = sum(refs[(s, p)] for p in pl)
        if c and (r == 0 or c / r > RATIO_CUTOFF):
            p3_cls += crawl_cls
            p3_ref += r
    p3_r = sum(req[(s, c)] for c in p3_cls)
    p3_b = sum(byt[(s, c)] for c in p3_cls)
    # P4 is the union of P2 and P3: unverified requests of a class P3 already blocks are not counted twice.
    if TOL_PATH:
        extra_r = sum(unv180[(s, c)] for c in VERIFIABLE if c not in p3_cls)
        extra_b = sum(unv180[(s, c)] * byt[(s, c)] / req[(s, c)] for c in VERIFIABLE if c not in p3_cls and req[(s, c)])
    else:
        extra_r = sum(bno.get(f"{s}|{c}|req", 0) for c in VERIFIABLE if c not in p3_cls)
        extra_b = sum(bno.get(f"{s}|{c}|bytes", 0) for c in VERIFIABLE if c not in p3_cls)
    w(f"| {s} | P1 | {p1_r:,} | {pct(p1_b, tot_b)} | {p1_ref:,} | 0 |")
    w(f"| {s} | P2 | {p2_r:,} | {pct(p2_b, tot_b)} | 0 | 0 |")
    w(f"| {s} | P3 | {p3_r:,} | {pct(p3_b, tot_b)} | {p3_ref:,} | 0 |")
    w(f"| {s} | P4 | {p3_r + extra_r:,} | {pct(p3_b + extra_b, tot_b)} | {p3_ref:,} | 0 |")

# ---- 7. status codes for crawlers --------------------------------------------------------------
w("\n## 7. Status respons untuk crawler AI (semua situs)\n")
st = defaultdict(int)
for k, v in d["S"].items():
    site, cls, sc = k.split("|")
    if cls in AI:
        st[sc] += v
tot = sum(st.values()) or 1
w(" · ".join(f"{k}: {v:,} ({pct(v, tot)})" for k, v in sorted(st.items())))

# ---- 8. tolerance-window verification ------------------------------------------------------------
TOL = sys.argv[3] if len(sys.argv) > 3 else None
EDGES = [(0, "0"), (7, "1-7"), (30, "8-30"), (90, "31-90"), (180, "91-180"), (365, "181-365"), (10**9, ">365")]
chosen_n = None
if TOL:
    t = json.load(open(TOL))
    hist = defaultdict(int)
    for k, v in t["H"].items():
        site, cls, b = k.split("|")
        hist[(site, cls, b)] += v

    def unverified_rate(items, n_days):
        """Share of requests whose nearest list version holding the IP is more than n_days away."""
        n = sum(v for b, v in items.items() if b not in ("cf", "bad"))
        if not n:
            return None, 0
        ok = sum(items.get(name, 0) for edge, name in EDGES if edge <= n_days)
        return 100 * (n - ok) / n, n

    w("\n## 8. Verifikasi dengan jendela toleransi\n")
    w("Untuk tiap request dihitung jarak (hari) ke versi daftar IP terdekat yang memuat IP-nya. "
      "N = toleransi yang diterima. N = 0 sama dengan temporal ketat; kolom \"tak pernah\" = IP tidak ada di "
      "versi mana pun, termasuk daftar hari ini. IP Cloudflare dikeluarkan.\n")
    w("| Kelas | n | N=0 | N=7 | N=30 | N=90 | N=180 | N=365 | Tak pernah | N siku |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    knees = {}
    for c in VERIFIABLE:
        items = defaultdict(int)
        for (s, cc, b), v in hist.items():
            if cc == c:
                items[b] += v
        rates = []
        n = 0
        for edge, _ in EDGES[:-1]:
            r, n = unverified_rate(items, edge)
            rates.append(r)
        never = 100 * items.get("never", 0) / n if n else None
        if not n:
            continue
        # knee: first N after which widening the window lowers the rate by < 1 percentage point
        knee = EDGES[len(rates) - 1][0]
        for i in range(len(rates) - 1):
            if rates[i] - rates[i + 1] < 1.0:
                knee = EDGES[i][0]
                break
        knees[c] = knee
        w(f"| {c} | {n:,} | " + " | ".join(f"{r:.1f}%" for r in rates) + f" | {never:.1f}% | {knee} hari |")
    chosen_n = max(knees.values()) if knees else 0
    w(f"\nN yang dipakai untuk tabel per situs: **{chosen_n} hari** (siku terbesar antar kelas).\n")
    w("| Situs | Kelas | n | Tidak terverifikasi (N terpilih) | Tak pernah ada di daftar mana pun |")
    w("|---|---|---|---|---|")
    for s in sites:
        for c in VERIFIABLE:
            items = {b: v for (ss, cc, b), v in hist.items() if ss == s and cc == c}
            r, n = unverified_rate(items, chosen_n)
            if not n:
                continue
            w(f"| {s} | {c} | {n:,} | {r:.1f}% | {100 * items.get('never', 0) / n:.1f}% |")

# ---- 9. fixed-panel trend ----------------------------------------------------------------------
all_months = sorted({m for m, _ in mreq})
panel_months = [m for m in all_months if m <= "2026-09"]
mreq_site = defaultdict(int)
for k, v in d["A"].items():
    site, month, cls, field = k.split("|")
    if field == "req":
        mreq_site[(site, month, cls)] += v


def real_traffic(s, m):
    return sum(v for (ss, mm, c), v in mreq_site.items() if ss == s and mm == m and c != "internal")


MIN_MONTHLY = 1000  # below this a site-month is treated as "no real traffic"
w("\n## 9. Tren bulanan per situs: jumlah request crawler AI\n")
w("Tiap situs adalah deretnya sendiri, jadi tidak ada bias komposisi dari situs yang masuk atau berhenti. "
  f"\"·\" = situs tidak punya trafik nyata bulan itu (< {MIN_MONTHLY:,} request non-internal). "
  "Jumlah absolut dipakai karena porsi bisa menyesatkan saat trafik total melonjak.\n")
w("| Bulan | " + " | ".join(sites) + " |")
w("|---|" + "---|" * len(sites))
for m in all_months:
    cells = []
    for s in sites:
        if real_traffic(s, m) < MIN_MONTHLY:
            cells.append("·")
        else:
            cells.append(f"{sum(mreq_site[(s, m, c)] for c in AI):,}")
    w(f"| {m} | " + " | ".join(cells) + " |")

# ---- 10. validity notes ------------------------------------------------------------------------
w("\n## 10. Validasi dan batasan\n")
w("**Sudah divalidasi:**")
w("- Penyamaran Googlebot di site-g adalah penyamaran nyata, bukan artefak. Ada tiga sinyal independen: "
  "IP-nya berada di luar keempat daftar resmi Google, reverse DNS-nya `googleusercontent.com` (mesin Google Cloud "
  "milik pihak ketiga), dan user-agent-nya string Googlebot persis.")
w("- Verifikasi Googlebot dipakai sebagai kontrol per situs. Kalau Googlebot di suatu situs terverifikasi dengan baik, "
  "berarti IP yang tercatat di log adalah IP klien asli. Dengan begitu, tingginya angka tidak terverifikasi untuk "
  "crawler AI di situs yang sama (bagian 8) bukan efek proxy.")
w("- Kolom \"temporal\" di bagian 4 tidak lagi dipakai sebagai hasil. Kolom itu menghukum keterlambatan arsip. "
  "Penggantinya adalah bagian 8, yaitu verifikasi dengan jendela toleransi yang N-nya dipilih dari siku kurva per kelas.")
w("- Tren dihitung per situs dalam jumlah absolut (bagian 9), sehingga tidak bias komposisi.")
w("\n**Batasan yang masih berlaku:**")
w("- Jarak ke versi terdekat dihitung dua arah. Arah yang satu adalah IP yang baru masuk daftar setelah dipakai "
  "(keterlambatan publikasi vendor atau keterlambatan arsip). Arah yang lain adalah IP yang masih dipakai setelah "
  "dihapus dari daftar. Keduanya belum dipisahkan.")
w("- ChatGPT-User dan Perplexity-User adalah fetcher yang dipicu pengguna, sehingga \"tidak terverifikasi\" pada kelas "
  "ini tidak otomatis berarti palsu.")
w("- Efek kausal kebijakan terhadap rujukan di masa depan tidak bisa diukur dari replay. Ini butuh uji langsung.")
w("- Beban CPU tidak tercatat di log Apache. Yang tercatat hanya byte.")
w("- Data CBI tidak bisa dipakai: lognya bercampur antardomain, hanya tersimpan 14 hari, dan sebagian besar IP-nya "
  "IP Cloudflare.")
w("- Rujukan dari aplikasi AI bisa tercatat lebih rendah dari aslinya karena header Referer sering dibuang. "
  "`utm_source` sudah ikut dihitung.")

open(DST, "w", encoding="utf-8").write("\n".join(out) + "\n")
sys.stdout.reconfigure(encoding="utf-8")
print("\n".join(out))
