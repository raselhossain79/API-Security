# 06 — Cheatsheet: API Rate Limit and Bot Protection Bypass

Quick reference only. Read files 01–05 for the "why" behind each entry — this file intentionally omits explanation in favor of speed during testing.

## Decision Tree: Which Technique to Try First

```
1. Does the target return 429 / a block response after N requests?
   NO  -> Not a bypass scenario, this is a missing-control finding (out of scope for this series)
   YES -> continue

2. Test header spoofing first (file 02) — cheapest, fastest to test
   Rotate: X-Forwarded-For, X-Real-IP, X-Originating-IP, True-Client-IP
   If target is behind Cloudflare, also check for origin IP exposure -> CF-Connecting-IP spoof via direct origin connection
   BYPASSED?  -> Done (but verify layer coverage - test again post-auth if applicable)
   NOT BYPASSED -> continue

3. Is the endpoint reachable via a URL variation? (file 03, section 2)
   Try: case variation, trailing slash, double slash, dot-segments, query string noise, alt API version
   BYPASSED? -> Done
   NOT BYPASSED -> continue

4. Is the limit keyed on account/session rather than IP? (file 03, section 1)
   Check signup friction - email only? disposable email accepted?
   If low friction -> multi-account distribution viable
   BYPASSED? -> Done
   NOT BYPASSED -> continue

5. Identify the algorithm (file 01, section 3 heuristics) and apply timing bypass (file 04)
   Fixed window -> boundary burst
   Token bucket -> exhaust + refill-rate hugging
   Possible race condition (in-app limiter, increment-after-process)? -> concurrent burst test
   BYPASSED? -> Done
   NOT BYPASSED -> continue

6. Check for TLS/header/behavioral bot-management layer (file 05)
   Fingerprint mismatch between User-Agent and TLS handshake?
   Missing modern browser headers (sec-ch-ua*, full Accept-Language)?
   Perfectly regular request cadence?
   -> Fix whichever inconsistency is present, retest from step 2
```

## Header Spoofing Quick Table

| Header | Format | Trust likelihood | Notes |
|---|---|---|---|
| `X-Forwarded-For` | `ip1, ip2, ip3` (comma list) | High (de facto standard) | Test first value manipulation |
| `X-Real-IP` | single IP | Medium-High (NGINX ecosystem) | Test independently of XFF |
| `X-Originating-IP` | single IP | Medium (legacy/custom code) | Often unfiltered by CDNs |
| `True-Client-IP` | single IP | High if Akamai/CF Enterprise | Only spoofable via origin IP exposure |
| `CF-Connecting-IP` | single IP | High if behind Cloudflare | Only spoofable via origin IP exposure |
| `Forwarded` (RFC 7239) | `for=ip;proto=x;by=y` | Low-Medium | Standards-compliant frameworks may prioritize over XFF |

**Origin IP discovery for CF-Connecting-IP / True-Client-IP bypass:** `crt.sh` (cert transparency), historical DNS (SecurityTrails), mail records (SPF/MX often point at unproxied origin infra), exposed non-proxied subdomains.

## Endpoint Variation Quick List

```
/api/v1/login
/api/v1/Login
/api/v1/LOGIN
/api/v1/login/
/api/v1/login;
/api/v1/login%2F
/api/v1/login/./
/api/v1/./login
/api/v1//login
/api/v1/login?x=<random>
/api/v2/login   (if same logic reachable via alt version)
```
Verify each still reaches the real handler (check response body/status matches a genuine attempt, not a 404).

## Timing Bypass Quick Reference

| Algorithm | Tell-tale sign | Technique |
|---|---|---|
| Fixed window | Resets sharply at round clock time | Burst at end of window N + burst at start of window N+1 |
| Sliding window log/counter | Gradual, per-request expiry | Timing tricks largely ineffective — use identity distribution instead |
| Token bucket | Burst succeeds, then throttles to steady trickle | Exhaust bucket, then send at exactly refill rate `1/R` |
| Leaky bucket | Constant ceiling regardless of burst pattern | Timing tricks ineffective — use identity distribution instead |

Check `X-RateLimit-Reset` / `Retry-After` response headers before guessing window boundaries manually.

## Bot Protection Inconsistency Checklist

- [ ] Does TLS fingerprint (JA3/JA4) match the claimed `User-Agent`'s real browser/version?
- [ ] Are modern Client Hints headers present (`sec-ch-ua`, `sec-fetch-*`) if claiming a recent Chromium browser?
- [ ] Is `Accept-Language` / `Accept-Encoding` a realistic browser default, not a bare library default?
- [ ] Is request cadence jittered, or perfectly periodic (a red flag)?
- [ ] Within one session, are IP/TLS/User-Agent internally consistent throughout, or do they shift mid-session?

## Account Distribution Feasibility Checklist

- [ ] What does signup require? (email only / disposable-blocked email / phone / KYC)
- [ ] Is there a per-IP cap on account creation itself? (If yes, must combine with file 02 header rotation during signup, not just during abuse.)
- [ ] Does the program consider multi-account abuse in-scope? (Check policy/past disclosed reports — frequently ruled business risk, not a security bug.)

## Report-Writing Reminder

A bypass finding should state explicitly:
1. Which identity key or window mechanism was assumed trustworthy
2. Why that assumption failed (config gap, missing normalization, missing secondary check)
3. Which specific header/technique demonstrated it
4. Remediation should target the **trust assumption**, not just "add more rate limiting" — e.g., "only trust XFF from allowlisted upstream proxy IPs" rather than "lower the rate limit threshold," since a lower threshold doesn't fix a spoofable identity key.
