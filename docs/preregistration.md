# Pre-registration: live L7 enforcement experiment

Written on 9 October 2026, before the rule was switched on. Changes after that date are listed at the end with their reasons. Sites are anonymized as in `data/results/`.

## Hypotheses

- **H1.** With the rule on, 100% of claims whose client IP is outside the allowed set get 403, and 0 requests from IPs that pass the vendor's official FCrDNS (Google, Bing, Apple) get 403.
- **H2.** Daily requests from verified crawlers on treated sites do not change relative to not-yet-treated sites (difference-in-differences not different from zero).
- **H3.** Daily referral visits from AI platforms and search engines do not change relative to control sites.
- **H4 (exploratory).** Impersonators change behaviour after a 403, for example by retrying from another IP, switching user-agent, or stopping.

## Design

Staggered rollout. Every site is a control for the others until its own rule is switched on.

| Wave | Date | Sites | Condition |
|---|---|---|---|
| 1 | 9 Oct 2026 | site-g | Direct connections, low SEO risk |
| 2 | 16 Oct 2026 | site-c, site-e | Written owner consent for blocking |
| 3 | 23 Oct 2026 | site-a, site-d, site-f | `mod_remoteip` for Cloudflare enabled and tested per site, plus owner consent |
| End | 6 Nov 2026 | – | Analysis starts |

Wave order follows risk and is not randomized, which is a stated limitation. site-b is excluded because its log stopped on 19 September 2026. A wave whose condition is not met on its date is postponed, and the postponement is recorded.

The pre-period is the historical data from January 2025 to 8 October 2026, plus live monitor data from 8 October 2026.

## Rule under test

The `enforce.conf` generated hourly by `aiverify sync`. A claim is rejected (403) when the client IP is outside the union of list versions in force within the class's tolerance window. Cloudflare peers are exempt (fail-open), because the client IP is not visible on vhosts without `mod_remoteip`. Classes without a verification method (Bytespider) and Claude-User and Claude-SearchBot are never rejected. Apache reloads after `httpd -t` passes, whenever the lists change.

## Measures (per site per day)

1. Fake claims served (2xx/3xx) and rejected (403).
2. Verified crawler requests and their status.
3. 403 to IPs that pass FCrDNS. This is the safety measure and must be 0.
4. Bytes sent to fake claims.
5. Referral visits from AI platforms and search engines.
6. Impersonator behaviour: new IPs per day, claims per IP, share of IPs that return after a 403.

## Analysis plan

- H1 is computed directly from the claims log (status per verdict), with Wilson intervals.
- H2 and H3 use difference-in-differences with site and day fixed effects on log(1 + daily count). Inference is by permutation of activation dates across sites, because there are few sites. Each site is also reported as an interrupted time series.
- H4 is descriptive, before and after per site.
- α = 0.05, with Holm correction across H2 and H3.

## Safeguards

- **Automatic circuit breaker.** If the monitor sees a request whose list verdict says reject but whose IP passes the vendor's FCrDNS, the rule is removed from every site and Apache is reloaded. The event is recorded in the `guard` table.
- **Manual switch-off.** `deploy/enforce.sh off all`.
- **Early stop.** The experiment stops if the breaker trips more than once, or if a site owner asks.

## Changes

1. **9 Oct 2026, before activation.** Functional test requests after activation come from the server itself (peer 127.0.0.1) with a user-agent ending in `aiverify-selftest`. All such requests are excluded from the analysis.
2. **9 Oct 2026, 01:40 UTC.** The first activation attempt was rejected by `httpd -t`, because an end-of-line comment after `IncludeOptional` is not valid Apache syntax. The vhost file was restored automatically and no request was affected. The include path itself is now the marker.
3. **9 Oct 2026, 01:41:44 UTC.** Wave 1 active on site-g. Server-side test: Googlebot and GPTBot claims from an unlisted IP get 403 (before: 303 and 200), browsers still get 303, Bytespider is still served, and control sites are unchanged.
