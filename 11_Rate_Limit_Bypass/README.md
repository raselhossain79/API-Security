# API Rate Limit and Bot Protection Bypass

A deep-dive note series on bypassing rate limits and bot/API protection mechanisms that **already exist** — not on finding missing rate limiting (that gap is covered separately as "Missing Rate Limiting" under API4/API Security Top 10 misconfiguration notes).

This series assumes the target has *some* rate limiting or bot protection deployed, and focuses on the identity signals those systems trust, why they trust them, and how that trust is exploited.

## Scope and Philosophy

Rate limiting and bot protection are both fundamentally **identity problems**. A server has to decide, on every request, "is this the same client that made the last N requests?" and "is this client a human/legitimate integration or an automated abuser?" Every bypass technique in this series follows the same pattern:

1. Identify what signal the server is using to answer that question (source IP, header value, account ID, URL string match, request cadence, TLS fingerprint, etc.)
2. Understand why the server trusts that signal in its deployment context (reverse proxy config, CDN setup, load balancer, WAF rule, business logic assumption)
3. Manipulate that signal without triggering re-evaluation, because the underlying enforcement logic is doing simple pattern-matching, not identity verification

## File Index

| # | File | Covers |
|---|------|--------|
| 1 | `01-how-api-rate-limiting-works.md` | Rate limiting algorithms (fixed window, sliding window/log, token bucket, leaky bucket), what a "client identity key" is, common deployment layers (CDN, WAF, app-level, API gateway) |
| 2 | `02-header-based-ip-spoofing-bypass.md` | X-Forwarded-For, X-Real-IP, X-Originating-IP, CF-Connecting-IP, True-Client-IP, Forwarded — which platforms trust which header and why, header rotation to bypass per-IP limits |
| 3 | `03-account-endpoint-variation-bypass.md` | Multi-account request distribution to stay under per-account limits, URL/endpoint variation (casing, trailing slash, path parameters, versioning, encoding) to evade counter matching |
| 4 | `04-timing-window-distribution-bypass.md` | Identifying rate limit window type and duration, threshold-hugging request pacing, race-condition-adjacent burst timing, distributing load across time and infrastructure |
| 5 | `05-bot-protection-fingerprinting-bypass.md` | API-specific bot/anti-automation detection (behavioral analysis, TLS/JA3 fingerprinting, header consistency checks, request entropy) and how to defeat each without image CAPTCHA solving |
| 6 | `06-cheatsheet.md` | Condensed reference: headers to test, decision tree for choosing a bypass technique, PortSwigger lab mapping, quick payload/header table |

## PortSwigger Web Security Academy Coverage — Honest Gap Disclosure

PortSwigger's Academy does **not** have a dedicated "Rate Limiting" topic as of this writing. Rate-limit-adjacent content exists inside:

- **Business logic vulnerabilities** topic — labs on "Rate limit bypass via race condition" and "Rate limit bypass via multi-endpoint request distribution" — closest direct labs
- **Authentication** topic — labs involving brute-force protection bypass (IP block bypass via X-Forwarded-For, account lockout bypass) are the most directly transferable, since brute-force protection is a specialized case of a per-account/per-IP rate limit
- There is **no PortSwigger lab** specifically covering CDN header trust chains (CF-Connecting-IP, True-Client-IP) or TLS/JA3 fingerprinting bypass — this content is sourced from real-world CDN/WAF documentation (Cloudflare, AWS, Akamai) and public bug bounty writeups, and is flagged as such in each file

Each file states explicitly whether a technique has an official lab or is industry-sourced only. Do not assume Academy-completeness for this topic the way it exists for SQLi or XSS.

## Real-World Sources Referenced Throughout

- Cloudflare, AWS CloudFront/WAF, and Akamai documentation on header trust and bot management
- crAPI (Completely Ridiculous API) — used for hands-on practice where relevant
- Public disclosed bug bounty reports on rate-limit and bot-protection bypass (HackerOne/Bugcrowd program writeups, cited generically by technique, not by exact report text)
- OWASP API Security Top 10 (API4:2023 — Unrestricted Resource Consumption) as the umbrella classification this entire series sits under

## How to Use This Series

Read in file order (01 → 06). File 1 is required background — the bypass techniques in files 2–5 only make sense once you understand *which* identity key a given rate limiter is keying on, because the correct bypass technique depends entirely on that.
