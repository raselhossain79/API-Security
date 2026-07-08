# API Rate Limit & Bot Protection Bypass — Note Series

A focused reference series on bypassing rate limits and bot protections that are **actively enforced** — not on discovering endpoints with no rate limiting at all (that scenario is covered separately under API4: Unrestricted Resource Consumption).

## File Index

| File | Contents |
|---|---|
| [00-Overview-Rate-Limit-Fundamentals.md](./00-Overview-Rate-Limit-Fundamentals.md) | How rate limiting actually works (counting key, counting window, enforcement point), threat model, WAF/gateway relevance breakdown per technique, full lab and crAPI mapping |
| [01-Header-Based-IP-Spoofing-Bypass.md](./01-Header-Based-IP-Spoofing-Bypass.md) | `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `CF-Connecting-IP`, `True-Client-IP` — mechanism, per-platform trust matrix, rotation workflow |
| [02-Timing-Distribution-Endpoint-Variation-Bypass.md](./02-Timing-Distribution-Endpoint-Variation-Bypass.md) | Window-boundary timing exploitation, multi-account distribution, URL/path variation bypass |
| [03-WAF-Bot-Protection-Evasion.md](./03-WAF-Bot-Protection-Evasion.md) | Detection mechanics (TLS fingerprint, header order, behavioral telemetry), evasion techniques, honest ceiling on what's achievable with API-only tooling |
| [04-Turbo-Intruder-Rate-Limit-Bypass.md](./04-Turbo-Intruder-Rate-Limit-Bypass.md) | Full script breakdowns: single-packet gate attacks, sustained distributed bypass, HTTP/2 considerations, every `RequestEngine` parameter explained |
| [05-Final-Cheatsheet.md](./05-Final-Cheatsheet.md) | Condensed quick-reference for all techniques, lab sequence, report-writing checklist |

## Recommended Reading Order

Read in numeric order — File 00 establishes the mechanism vocabulary (counting key, window type, enforcement point) that every later file depends on.

## PortSwigger Lab Sequence (Apprentice → Practitioner → Expert)

Full mapping and rationale is in File 00, Section 5. Quick sequence:

**Apprentice:** Username enumeration via different responses → Username enumeration via subtly different responses → Limit overrun race conditions

**Practitioner:** Broken brute-force protection, IP block → Username enumeration via response timing → Username enumeration via account lock → Password brute-force via password change → Bypassing rate limits via race conditions → Multi-endpoint race conditions → Single-endpoint race conditions → Exploiting time-sensitive vulnerabilities

**Expert:** Partial construction race conditions *(adjacent skill, not a direct rate-limit-bypass lab — see honest gap disclosure in File 00)*

**Supplementary:** crAPI (OTP/forgot-password flow, coupon/voucher redemption endpoint)

## Conventions Used in This Series

- Mechanism-first explanations before any payload or tool usage
- Every header example and script broken down flag-by-flag / parameter-by-parameter
- Honest disclosure of PortSwigger lab coverage gaps rather than forcing a fit
- A stated WAF/Gateway relevance assessment in every file — explicit reasoning given where relevance is low, not silently omitted
- Full English only, no informal shorthand
