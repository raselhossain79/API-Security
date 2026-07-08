# Rate Limit & Bot Protection Bypass — Final Cheatsheet

Quick-reference summary. See individual files for full mechanism explanations.

---

## 1. Identify the Rate Limit Key First

Before trying any bypass, determine what's being counted:

| Observed behavior | Likely key | Try this bypass |
|---|---|---|
| Block persists across different accounts, same network | IP address | Header spoofing (Section 2) |
| Block persists across VPN/IP changes, same login | Account/session | Account distribution (Section 3) |
| Block resets sharply at round-number timestamps | Fixed time window | Timing boundary bypass (Section 4) |
| Block applies to exact URL only, not equivalent paths | Route-string key | Endpoint variation (Section 5) |

---

## 2. Header-Based IP Spoofing — Quick Reference

| Header | Spoofable directly? | Notes |
|---|---|---|
| `X-Forwarded-For` | Yes, if app trusts it without hop validation | Try single value first, then comma-chain; check both first and last position |
| `X-Real-IP` | Yes, if app trusts it | Single value only, no chain |
| `X-Originating-IP` | Yes, if app has custom logic reading it | Less standardized, less commonly checked defensively |
| `CF-Connecting-IP` | No — Cloudflare overwrites it at the edge | Bypass requires discovering and hitting the origin IP directly |
| `True-Client-IP` | No — Akamai/Cloudflare Enterprise overwrites it | Same as above — origin exposure is the real vector |

**Fast test sequence:**
1. `X-Forwarded-For: <random_ip>` — rotate per request
2. `X-Real-IP: <random_ip>`
3. `X-Originating-IP: <random_ip>`
4. Try `127.0.0.1` / `localhost` specifically — some apps whitelist loopback
5. For AWS ALB targets: test reading BOTH first and last IP in the XFF chain
6. For CDN-fronted targets: search cert transparency logs / DNS history for the real origin IP, then hit it directly with `Host` header set correctly

---

## 3. Account Distribution — Quick Reference

1. Check account creation friction: CAPTCHA? Email verification? IP limit on signup?
2. Use email `+` aliasing (`user+1@domain.com`) to defeat uniqueness checks cheaply
3. Build a pool of 10–50 accounts (sufficient for PoC; note theoretical scale in report)
4. Round-robin the target action across account tokens/API keys
5. If signup itself is IP-rate-limited, combine with Section 2's header rotation during account creation specifically

---

## 4. Timing/Window Boundary — Quick Reference

1. Check for `X-RateLimit-Reset` / `Retry-After` headers first — they often disclose the window directly
2. If absent, empirically hit the limit, then burst again exactly at the next round-number time boundary
3. Full success at boundary = fixed window (exploitable). Partial/no success = sliding window or token bucket (not exploitable this way)
4. Use Turbo Intruder gating (File 4) to script precise burst timing rather than manual attempts

---

## 5. Endpoint Variation — Quick Reference

Test each independently, don't combine:

```
POST /api/v1/login          (baseline)
POST /api/v1/Login          (case variation)
POST /api/v1/LOGIN
POST /api/v1/login/         (trailing slash)
POST /api/v1//login         (double slash)
POST /api/v1/./login        (dot-segment)
POST /api/v1/%6cogin        (percent-encoding)
```
Confirm variant produces IDENTICAL business logic outcome (not a 404, not different session handling) before reporting as valid.

---

## 6. WAF / Bot Protection Evasion — Quick Reference

| Signal | Evasion technique | Realistic ceiling |
|---|---|---|
| Static User-Agent | Rotate real, current browser UAs | Fully addressable |
| Regular request timing | Add randomized jitter | Tension with timing-boundary bypass — accept some scriptedness on the critical burst |
| Header order/casing mismatch | Match claimed browser's real header conventions | Addressable with effort (browser automation) |
| TLS/JA3 fingerprint | Requires genuine browser TLS stack | NOT addressable with raw HTTP client tools |
| Behavioral/JS telemetry absence | Requires real browser + simulated interaction | NOT addressable with API-only tooling |
| Datacenter IP reputation | Residential/mobile proxy rotation | Addressable but requires third-party service + scope clearance |

**Honest bottom line:** basic evasion (UA rotation, jitter, header matching) defeats weak/absent bot management. Mature bot-management products require full browser automation to evade reliably — don't oversell partial evasion as complete.

---

## 7. Turbo Intruder Quick Config Reference

**Single-packet race attack (rate-limit/lockout race condition):**
```python
engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                        requestsPerConnection=N, pipeline=False, engine=Engine.BURP2)
# queue with gate='name', then engine.openGate('name')
```

**Sustained distributed bypass (header rotation across many requests):**
```python
engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=20,
                        requestsPerConnection=1, engine=Engine.BURP2, maxRetriesPerRequest=0)
```

**HTTP/2 targets:** set `engine=Engine.HTTP2` explicitly — check ALPN/protocol column in Burp history first.

---

## 8. PortSwigger Lab Sequence (Full Series, Correct Order)

**Apprentice**
1. Username enumeration via different responses
2. Username enumeration via subtly different responses
3. Limit overrun race conditions

**Practitioner**
4. Broken brute-force protection, IP block
5. Username enumeration via response timing
6. Username enumeration via account lock
7. Password brute-force via password change
8. Bypassing rate limits via race conditions
9. Multi-endpoint race conditions
10. Single-endpoint race conditions
11. Exploiting time-sensitive vulnerabilities

**Expert**
12. Partial construction race conditions *(adjacent skill — see honest gap note in Overview file)*

**Supplementary:** crAPI — OTP/forgot-password flow, coupon/voucher redemption endpoint

---

## 9. Report-Writing Checklist

- [ ] State the exact rate-limit key identified (IP / account / route-string)
- [ ] State the exact header/technique used and exact values sent
- [ ] Include exact request count and timing (screenshots or Turbo Intruder script output)
- [ ] Frame the impact around what the bypass ENABLES (brute-force, OTP guessing, financial abuse) not just "limit bypassed"
- [ ] Note whether WAF/bot-management was present and whether it was evaded, weak, or absent
- [ ] Include the literal script/payload used for reproducibility
