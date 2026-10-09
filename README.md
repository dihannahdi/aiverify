# aiverify

Verify AI crawler claims against the **history** of the vendors' official IP lists, and enforce the result in Apache.

Anyone can send `User-Agent: Googlebot` or `GPTBot`. Vendors publish IP lists for their crawlers, but those lists change. Checking last year's logs against today's list marks real crawlers as fake. aiverify keeps every version of 12 official lists, checks each request against the version that was in force on the request's date, and turns the current lists into an Apache access rule.

This repository holds the code, the frozen list history, and the anonymized aggregate results of a study on 28.6 million log lines from 7 sites (January 2025 to October 2026). It is the software artifact of an undergraduate (D4) final project at Universitas Gadjah Mada.

## What it found

| Finding | Value |
|---|---|
| ChatGPT-User requests marked fake when checked against today's list vs. the list in force at the time (n = 16,792) | 65.8% vs 7.8% |
| Requests claiming Googlebot from IPs never in any Googlebot list (n = 939,380) | 0.9% |
| Distinct IPs claiming Googlebot that were never listed (546 of 1,148) | 47.6% |
| Agreement with the vendors' own forward-confirmed reverse DNS (Google, Bing, Apple; 256 IPs) | 100%, κ = 1.00 |
| GPTBot requests wrongly rejected if 25% of archived list versions are missing | 4.6% → 11.4% |
| Fake claims blocked: Apache rule (L7) vs. reactive IP ban at the firewall (L3, 24 h) | 100% vs 93.9% |
| Browser requests blocked as collateral: L7 vs. L3 (upper bound) | 0 vs ≤ 54,956 |
| Added server time per verified crawler request (18 to 1,292 prefixes) | +17 to +35 µs |

Confidence intervals, methods and limitations are in the thesis. Proportions use Wilson intervals, trends use Mann–Kendall with Holm correction, and the benchmark uses randomized repetitions with bootstrap intervals. A live, pre-registered enforcement experiment started on 9 October 2026 ([docs/preregistration.md](docs/preregistration.md)).

## How it works

```
12 official lists ──hourly sync──► versioned store ──► verifier (version in force + tolerance window)
Wayback Machine / RIPEstat ─backfill─┘                     ├─► monitor: claims log + FCrDNS at request time
                                                           └─► generated Apache 2.4 authz rules (opt-in per vhost)
```

| Crawler class | Verified with |
|---|---|
| Googlebot, Bingbot, Applebot | vendor IP lists (also FCrDNS for the cross-check) |
| GPTBot, OAI-SearchBot, ChatGPT-User | OpenAI's three lists |
| PerplexityBot, Perplexity-User | Perplexity's two lists |
| ClaudeBot | claude.com/crawling/bots.json (Claude-User and Claude-SearchBot are reported, not judged, because the list's coverage is not stated) |
| Amazonbot, CCBot | Amazon and Common Crawl lists |
| Meta-ExternalAgent | prefixes announced by AS32934 (network level only) |
| Bytespider | no published method, so never blocked |

A list version is identified by its content. Old versions come from the Wayback Machine CDX index (raw `id_` replay, gzip and Brotli decoded). The tolerance window per class (30 days for OAI-SearchBot, 90 for ChatGPT-User, 0 otherwise) was chosen at the knee of the tolerance curve.

## Use

Python 3.12, standard library only (`brotli` is optional, for backfilling Brotli-encoded archive captures).

```bash
python3 -m aiverify init --store data/store.json --snapshots data/lists/snapshots.final.json
python3 -m aiverify backfill --store data/store.json             # history for every other list
python3 -m aiverify sync --store data/store.json --apache-out data/enforce.conf --exempt-cloudflare
python3 -m aiverify claims-conf --log /var/log/apache2/aiverify-claims.log > 0.aiverify.conf
python3 -m aiverify monitor --store data/store.json --log /var/log/apache2/aiverify-claims.log --db data/monitor.sqlite
python3 -m aiverify report --db data/monitor.sqlite              # aggregates only, no IP addresses
```

`deploy/` has the systemd units (hourly sync with `httpd -t` before every reload, the monitor with an automatic circuit breaker), a logrotate rule, and `enforce.sh` to switch the rule on or off per vhost. The rule uses `AuthMerging And`, so it never loosens a stricter rule a vhost already has, such as a `<Files>` deny on `.env`.

Tests:

```bash
python3 -I -m unittest discover -s tests                        # 27 unit tests
python3 -I bench/run_bench.py data/store.json 10 3000 1         # functional + overhead, isolated Apache on 127.0.0.1
```

## Data in this repository

- `data/lists/` holds the frozen history of the public vendor lists. `store.frozen-20261008b.json` is the store used for the final results (SHA-256 prefix `462d54e0fec08127`).
- `data/results/` holds aggregate outputs only. There are no IP addresses. Study sites are renamed `site-a` to `site-g` in order of log volume, other virtual hosts are `other-NN`, and reverse-DNS providers outside the major vendors are `other`.
- `analysis/` holds the scripts that produced them. They run on the log server and print aggregates.

The raw logs are not published. They contain personal data (IP addresses) and belong to the site owners, who consented to aggregate publication only (Indonesian Law 27/2022 on Personal Data Protection).

## Cite

See [CITATION.cff](CITATION.cff).

## License

MIT, see [LICENSE](LICENSE).
