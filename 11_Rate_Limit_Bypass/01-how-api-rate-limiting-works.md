# 01 — How API Rate Limiting Actually Works

## Why This File Comes First

Every bypass technique in this series exploits a mismatch between **what a rate limiter is supposed to identify** (a distinct client/user) and **what it actually measures** (a proxy signal like an IP address, a header value, or a URL string). You cannot choose the correct bypass technique without first knowing which of these proxy signals a target is using. This file breaks down the mechanics before any offense.

## 1. The Core Question Every Rate Limiter Answers

A rate limiter's entire job reduces to one repeated decision:

> "Has *this* client already made N requests in the current time window?"

Two sub-problems hide inside that sentence, and both are exploitable:

1. **"This client"** — how is a client identified? (the **identity key** problem)
2. **"Current time window"** — how is the window measured and when does it reset? (the **windowing** problem)

Files 02–04 each attack one of these sub-problems specifically.

## 2. Identity Keys — What a Rate Limiter Actually Counts On

A rate limiter needs a key to count against. Common keys, roughly in order of how commonly they're used in production APIs:

| Identity Key | How it's derived | Why it's chosen | Why it's weak |
|---|---|---|---|
| Source IP address | TCP connection or trusted proxy header | Free, no client cooperation needed | Behind CDNs/proxies, the "real" IP is a header value the server chooses to trust — this is the entire attack surface of file 02 |
| API key / access token | Client-supplied credential | Ties usage to a registered identity | An attacker can register many keys/accounts (file 03) |
| Session/cookie | Server-issued session identifier | Ties usage to an authenticated session | Same weakness as API keys — new sessions are usually cheap to obtain |
| User/account ID | Post-authentication identity | Most accurate signal available | Only as strong as account creation friction — if signup is free/instant, this collapses to the API key problem |
| Device fingerprint | TLS handshake, header ordering, JS-collected signals | Attempts to survive IP/account rotation | Covered in file 05 — fingerprints can be normalized/randomized |
| Composite key (IP + endpoint, IP + account, etc.) | Combination of the above | Reduces false positives from shared IPs (NAT, corporate proxies) | Still inherits the weaknesses of each component; a composite key can sometimes be *partially* satisfied by varying only one component (see file 03, endpoint variation) |

**The single most important idea in this entire series:** a rate limiter's key is almost never "the human/organization behind this traffic." It's always a cheap-to-compute proxy for that. Every bypass in this series is really just "find the proxy the limiter is actually using, then change it without changing anything the server cares about."

## 3. Rate Limiting Algorithms — How the Counting Actually Happens

The algorithm matters because it directly determines what a "timing bypass" (file 04) looks like against a given target.

### 3.1 Fixed Window Counter

- A counter increments per identity key and resets at fixed clock boundaries (e.g., every minute on the `:00` mark).
- **Why it's used:** simplest to implement — literally `INCR key; EXPIRE key 60` in Redis.
- **The exploitable flaw:** requests clustered at the boundary of two windows can produce up to **2x the intended limit** in a short burst. If the limit is 100 req/min, an attacker can send 100 requests at 23:59:59 and another 100 at 00:00:00 — 200 requests in a two-second span, both technically compliant with "100 per window."
- This is the algorithm file 04's "window boundary timing" section directly targets.

### 3.2 Sliding Window Log

- Every request timestamp is stored; the count is "how many timestamps fall within the last N seconds from *now*," recalculated on every request.
- **Why it's used:** eliminates the fixed-window boundary flaw — much harder to burst.
- **The tradeoff that matters to you:** it's expensive to store (a timestamp per request per key), so it's less commonly deployed at high-volume public APIs than the alternatives below. When you do encounter it, boundary-timing bypass does not work — you need the account/header distribution techniques from files 02–03 instead.

### 3.3 Sliding Window Counter (approximated)

- A hybrid: keeps two fixed-window counters (current and previous) and computes a weighted estimate assuming even request distribution within the previous window.
- **Why it's used:** most of sliding-log's accuracy at fixed-window's storage cost — this is what Cloudflare, AWS API Gateway, and most modern API gateways actually run by default.
- **The exploitable flaw:** the "weighted estimate" assumes requests were evenly distributed across the previous window. If you concentrate all of your previous-window traffic at its very start, the weighting formula under-counts your effective rate near the boundary. This is a subtler, smaller version of the fixed-window flaw — still boundary-timing-relevant, but requires more precise pacing.

### 3.4 Token Bucket

- A bucket holds up to *B* tokens; each request consumes one token; tokens refill at rate *R* per second, capped at *B*.
- **Why it's used:** naturally allows short bursts (useful for legitimate bursty traffic like a page loading 10 resources at once) while enforcing a long-run average rate.
- **The exploitable flaw:** the burst allowance itself. If *B* is large relative to *R* (common — burst capacity is usually sized generously for UX reasons), an attacker who has been idle can spend the entire bucket in one burst, then trickle requests at exactly the refill rate indefinitely. This is the "identify refill rate, then hug it" pattern in file 04.

### 3.5 Leaky Bucket

- Requests queue into a bucket that "leaks" (processes) at a fixed rate; if the bucket is full, new requests are dropped/rejected.
- **Why it's used:** smooths bursty traffic into a constant outbound rate — common at the load balancer/queueing layer rather than the application layer.
- **Relevance to bypass:** leaky bucket enforces an *average* rate over time regardless of burst pattern, so boundary-timing tricks don't help here — the only way to exceed the effective rate is to add more identity keys (more IPs, accounts, or connections), which is exactly what files 02–03 cover.

## 4. Where Rate Limiting Is Enforced — Layers Matter

The same API can have rate limiting enforced at multiple layers simultaneously, and **each layer may use a different identity key**, which is why a bypass that works against one layer can still get caught by another.

| Layer | Typical identity key | Example real-world tech |
|---|---|---|
| CDN / edge | Connecting IP, TLS fingerprint | Cloudflare Rate Limiting, Akamai Bot Manager |
| WAF | Source IP + header combination, request signature | AWS WAF rate-based rules, Cloudflare WAF |
| API Gateway | API key, client ID | Kong, AWS API Gateway usage plans, Apigee |
| Application code | Session, user ID, custom business logic | Custom Redis/Memcached counters in app code |
| Load balancer | Source IP | NGINX `limit_req`, HAProxy stick-tables |

**Real-world note:** the most common real-world finding in bug bounty programs is a mismatch between layers — e.g., the CDN rate-limits by IP (bypassable with header spoofing per file 02) but the actual sensitive business logic endpoint behind it has *no independent application-level check*, so once the edge is bypassed, nothing stops the abuse. Always test every layer independently rather than assuming "rate limited" means "rate limited everywhere the request passes through."

## 5. What "Bypass" Actually Means Here — Setting Expectations

This series does not cover:
- Exploiting the *absence* of rate limiting (that's a missing-control finding, not a bypass)
- Brute-forcing CAPTCHA image solving (out of scope — file 05 covers non-image bot detection only)

This series does cover:
- Techniques where a rate limit control **exists, is enforced, and is circumvented** by manipulating the identity key or timing it relies on

This distinction matters for report-writing: a missing rate limit is typically reported as a single finding with straightforward remediation ("add rate limiting"). A rate limit *bypass* is a more nuanced finding — the fix usually isn't "add rate limiting," it's "stop trusting the identity signal being spoofed," which is a different and often harder remediation conversation with the client/program.

## Next File

`02-header-based-ip-spoofing-bypass.md` — the identity-key attack surface for IP-based rate limiters.
