# 02 — Header-Based IP Spoofing for Rate Limit Bypass

## Prerequisite

Read `01-how-api-rate-limiting-works.md` first. This file assumes you already understand that "source IP" is frequently not a TCP-layer fact but a **header value the application chooses to trust**.

## PortSwigger Lab Mapping (Honest Disclosure)

There is no PortSwigger lab titled "IP spoofing for rate limit bypass." The closest official labs, in difficulty-progression order, are in the **Authentication** topic:

1. **"Username enumeration via subtly different responses"** — not directly relevant, but establishes the same target application used in lab 2 below
2. **"Broken brute-force protection, IP block"** — this is the actual transferable lab. It teaches bypassing an IP-based lockout by rotating the `X-Forwarded-For` header, which is mechanically identical to bypassing an IP-keyed rate limiter
3. **"Rate limit bypass via race condition"** (Business logic vulnerabilities topic) — different mechanism (concurrency, covered in file 04), but often chained with header spoofing in the same target

Everything else in this file — the CDN-specific headers (`CF-Connecting-IP`, `True-Client-IP`) and the platform trust tables — is sourced from Cloudflare, AWS, and Akamai's own documentation plus patterns observed in public bug bounty writeups, not from an Academy lab. Treat it as industry knowledge that extends beyond what Academy currently teaches.

## 1. Why This Works At All — The Trust Chain Problem

When a request passes through one or more proxies (CDN, load balancer, reverse proxy) before reaching the application server, the TCP connection the application actually sees originates from the *last* proxy in the chain, not the original client. To recover the "real" client IP for logging, geolocation, or rate limiting, applications rely on **headers that any proxy in the chain — including the client itself — can set**.

The application has to answer: "which of these header values do I trust as the real client IP?" This answer depends entirely on the application's deployment architecture, and getting it wrong is what makes every technique below work.

### The trust chain, piece by piece:

```
[Attacker] --> [CDN edge] --> [Load Balancer] --> [App Server]
```

- The attacker's HTTP client can set **any header it wants**, including `X-Forwarded-For: 1.2.3.4`
- The CDN edge is the first hop that has a *real*, un-spoofable fact: the TCP source IP of the attacker's connection to the CDN
- If the CDN is configured correctly, it **overwrites or prepends** to `X-Forwarded-For` with the real connecting IP before forwarding upstream — this is what a correctly configured deployment looks like
- If the CDN is configured to **append rather than overwrite**, or if the application reads the *first* value in a comma-separated `X-Forwarded-For` list rather than the *last trusted* value, the attacker-supplied fake IP survives all the way to the application's rate limiter
- This misconfiguration — trusting the wrong position in the header chain, or trusting a header the edge never touches at all — is the entire vulnerability class

## 2. Header-by-Header Breakdown

### 2.1 `X-Forwarded-For` (XFF)

**Format:** `X-Forwarded-For: client, proxy1, proxy2`  — a comma-separated list, appended to left-to-right as the request passes through each proxy.

**Why servers trust it:** it's the de facto standard for IP forwarding, supported by essentially every proxy and CDN. Many rate limiters are configured with a simple rule: "use the first IP in `X-Forwarded-For` if present, else use the TCP source IP."

**Why that trust is exploitable, piece by piece:**
- The attacker controls the *first* entry, because they're the one closest to the origin of the chain — a `X-Forwarded-For` header only reflects reality if every hop in the chain is a proxy that correctly appends and none of them blindly trusts a client-supplied value
- If the application (or the CDN in front of it) doesn't strip/overwrite any pre-existing `X-Forwarded-For` sent by the client, the attacker can simply prepend a fake IP: `X-Forwarded-For: 203.0.113.7` before the real chain gets appended
- Rate limiter keys on "first value in XFF" → attacker sends a fresh, arbitrary first value per request → each request appears to originate from a different IP → the per-IP counter never accumulates against any single key

**Bypass in practice — rotation:**
```
Request 1: X-Forwarded-For: 1.1.1.1
Request 2: X-Forwarded-For: 1.1.1.2
Request 3: X-Forwarded-For: 1.1.1.3
...
```
Each value only needs to be syntactically valid and distinct — it does not need to be a real, routable, or geographically plausible IP unless the application does additional validation (some do check for private/reserved ranges — avoid `10.x.x.x`, `192.168.x.x`, `127.x.x.x` for that reason, and prefer addresses from real public ranges to blend into legitimate-looking traffic and pass any sanity filtering).

### 2.2 `X-Real-IP`

**Format:** single IP value, no list — `X-Real-IP: 203.0.113.7`

**Why servers trust it:** it's the NGINX-ecosystem convention for "the one IP the immediately-preceding proxy is vouching for," as opposed to XFF's full chain. Because it's a single value rather than a list, some applications treat it as *more* authoritative than XFF, on the (often incorrect) assumption that a single-value header is less spoofable.

**Why that trust is exploitable:** the header has no cryptographic binding to anything — it's exploitable for the identical reason as XFF (client-settable, only as trustworthy as the first proxy's overwrite behavior) but is worth testing **separately** from XFF because:
- Some applications check XFF for one purpose (logging) and `X-Real-IP` for another (rate limiting) — testing only one may miss the actual key
- Some rate limiters fall back to `X-Real-IP` only when XFF is absent, so spoofing both together, or spoofing whichever one the app prioritizes, is worth enumerating explicitly

### 2.3 `X-Originating-IP`

**Origin:** historically an email/mail-relay header (indicating the IP that originated a message), but adopted by some web application firewalls and legacy load balancers as an additional client-IP hint.

**Why it's worth testing:** it's less commonly *validated or stripped* by CDNs than XFF/X-Real-IP because it's less commonly used for legitimate purposes at the HTTP layer — meaning fewer deployments have hardened against it. When application code implements custom "get client IP" logic (rather than relying on a well-known framework helper), developers sometimes check a whole list of headers in sequence for maximum compatibility, and `X-Originating-IP` shows up in those lists more often than you'd expect from custom or older codebases.

### 2.4 `CF-Connecting-IP`

**Context:** Cloudflare-specific. When traffic passes through Cloudflare, Cloudflare sets this header to the real connecting client IP **and this value is not directly spoofable by an external attacker if the origin server only accepts traffic from Cloudflare's IP ranges**, because Cloudflare overwrites any client-supplied `CF-Connecting-IP` at its edge.

**Why this header is different from XFF/X-Real-IP — the important distinction:**
- If the origin server is correctly configured to only accept connections from Cloudflare's published IP ranges (and Cloudflare strips/overwrites client-supplied `CF-Connecting-IP`), this header is **genuinely trustworthy** and not spoofable through the front door
- **The actual bypass vector is not the header itself — it's origin IP exposure.** If an attacker discovers the origin server's real IP (via DNS history, SSL certificate transparency logs, subdomain misconfiguration, or a service that leaks it), they can connect **directly to the origin, bypassing Cloudflare entirely**, and set `CF-Connecting-IP` to whatever they want because the origin has no way to know the request didn't come through Cloudflare
- **This is the single most valuable real-world finding in this file.** Bug bounty programs frequently pay well for "Cloudflare/WAF bypass via origin IP exposure" because it doesn't just bypass rate limiting — it bypasses every edge-layer protection simultaneously (WAF rules, bot management, DDoS protection, rate limiting, everything)
- **How to find the origin IP:** check `crt.sh` or other certificate transparency logs for subdomains that might not be proxied through Cloudflare (a staging server, a mail server, an old A record); check historical DNS records (SecurityTrails, historical WHOIS/DNS databases) for IPs the domain pointed to before Cloudflare was added; check for SPF/DKIM/mail records which often point directly at origin infrastructure

### 2.5 `True-Client-IP`

**Context:** used by Akamai and also honored by Cloudflare Enterprise plans as an alternative to `CF-Connecting-IP`. Functionally identical trust model to `CF-Connecting-IP` — trustworthy only if the origin enforces edge-only connectivity, bypassable via the same origin-exposure technique.

### 2.6 `Forwarded` (RFC 7239 standardized header)

**Format:** `Forwarded: for=203.0.113.7;proto=https;by=203.0.113.43`

**Why it's rarely the primary key but worth testing:** it's the standardized replacement for XFF, but adoption in application code is much lower than the de facto XFF standard. Worth testing on any target because some frameworks (particularly newer ones, or ones using standards-compliant proxy middleware) prioritize it over XFF **if present**, meaning it can override a value you'd otherwise fail to spoof via XFF alone.

## 3. Determining Which Header a Target Actually Trusts

Don't guess — verify. A systematic, piece-by-piece approach:

1. **Baseline:** send requests until you get rate-limited (HTTP 429, or a custom block response/CAPTCHA challenge) with no spoofed headers. Note the exact number of requests and the response.
2. **Test one header at a time:** reset your baseline (wait out the window or use a fresh real IP if available), then repeat the same request count while sending a *single* spoofed header with a fresh value on every request (e.g., only `X-Forwarded-For`, incrementing). If the limit no longer triggers, that header is trusted by the rate limiter.
3. **Repeat independently for each candidate header** (`X-Real-IP`, `X-Originating-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Forwarded`) — do not assume that because one worked, others don't matter; some deployments check multiple headers with OR logic for redundancy, meaning you may need to spoof *all* trusted headers simultaneously, not just one.
4. **Test combinations:** some applications require internal consistency (e.g., `X-Forwarded-For`'s first value must match `X-Real-IP`) as a basic anti-spoofing check — if single-header spoofing fails, try setting multiple headers to the *same* fake value simultaneously before concluding the target is hardened.

## 4. Real-World Notes

- The most common real-world root cause is a reverse proxy or load balancer configuration that passes through client-supplied `X-Forwarded-For` **without overwriting the first hop**, combined with application code that naively trusts `request.headers['X-Forwarded-For'].split(',')[0]`.
- Cloud load balancers (AWS ALB, GCP Load Balancer) generally *append* to XFF correctly and are hard to spoof through directly — but the application-layer code reading that header is where the actual vulnerability usually lives, not the load balancer itself.
- This exact bypass class has appeared repeatedly in disclosed bug bounty reports against login/OTP endpoints, where header rotation was used to bypass brute-force lockouts, not just generic rate limits — treat login, OTP-verification, and password-reset endpoints as high-value targets for this technique specifically, since account takeover impact is higher there than on a generic read-only API endpoint.
- Defensive teams that understand this class typically remediate by (a) only trusting proxy headers from a known, IP-allowlisted set of upstream proxies, and (b) rate limiting on a *second*, harder-to-spoof key (authenticated session/account ID) as a backstop — which is exactly what file 03 addresses when IP spoofing alone isn't enough.

## Next File

`03-account-endpoint-variation-bypass.md` — bypassing account-keyed and URL-keyed rate limiters when IP spoofing isn't the applicable identity key.
