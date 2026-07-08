# Header-Based IP Spoofing for Rate Limit Bypass

## Mechanism: Why This Works At All

A rate limiter keyed on IP address needs to answer one question: "what is this client's IP?" There are exactly two ways to answer it:

1. **Read the actual TCP source address** of the connection (`socket.remote_addr` / `req.connection.remoteAddress`). This is authoritative and cannot be spoofed by an external client — the TCP handshake requires a real, routable return address.
2. **Read a client-supplied HTTP header** that claims to state the client's IP. This is a request header like any other — the client controls its value completely.

The vulnerability exists when a server sits behind one or more proxies (load balancer, CDN, reverse proxy) and, because the *proxy's* TCP connection is now the visible source address, the application falls back to reading a forwarded-IP header to recover the "real" client IP for logging, geolocation, or — critically — rate limiting.

**The bypass is simple once you see it:** if the application trusts a header value without verifying which hop actually set it, you set that header yourself, with a different value on every request, and the application will treat each request as coming from a "new" IP — resetting your rate limit counter every time.

---

## 1. The Headers, One at a Time

### 1.1 `X-Forwarded-For` (XFF)

**Format:** `X-Forwarded-For: <client>, <proxy1>, <proxy2>`

This is a comma-separated list, appended to (not replaced) by each proxy hop in the chain. The leftmost value is supposed to be the original client; each subsequent value is a proxy that the request passed through.

**Why it's trusted:** XFF is the de facto standard, defined originally by Squid and later formalized in RFC 7239 (as part of the `Forwarded` header family). Almost every reverse proxy (NGINX, HAProxy, Apache) and framework tutorial demonstrates reading `req.headers['x-forwarded-for']` to "get the real client IP" when the app is behind a proxy — this is copy-pasted into production code constantly, usually without validating hop count or trusted proxy list.

**Why it's exploitable:** the header is **client-settable on the first hop**. If your request goes: `You → NGINX → App`, NGINX will append your IP to whatever XFF value you already sent, producing something like `X-Forwarded-For: 6.6.6.6, <NGINX_IP>`. If the application-layer code (or the rate limiter middleware) naively takes the **first** comma-separated value as "the real IP," it takes your spoofed `6.6.6.6` at face value.

**Exploit pattern:**
```
X-Forwarded-For: 1.2.3.4
X-Forwarded-For: 5.6.7.8
X-Forwarded-For: 9.10.11.12
```
Send one value per request, rotating through a list (random IPs, or a purpose-built list — see Section 3). Each value resets the per-IP counter because the application believes it's a distinct client.

**Common code-level root cause (Node/Express):**
```javascript
app.set('trust proxy', true); // trusts ALL upstream hops, including attacker-controlled headers
const clientIp = req.ip; // Express resolves this from XFF because trust proxy is enabled
rateLimiter.check(clientIp); // now keyed on attacker-controlled value
```
The fix (`trust proxy` set to a specific hop count or trusted CIDR list, e.g. `app.set('trust proxy', 1)`) is well documented — but frequently skipped, because the naive `true` setting "just works" in dev.

### 1.2 `X-Real-IP`

**Format:** `X-Real-IP: <single IP address>` — no comma-separated chain, just one value.

**Why it's trusted:** this header originates from NGINX's own `ngx_http_realip_module` convention, where NGINX itself sets it to the real client IP when acting as a reverse proxy, specifically because XFF's comma-chain is ambiguous to parse. Because NGINX documentation recommends this pattern, many app-layer integrations read `X-Real-IP` as an authoritative single source of truth — with the same blind-trust problem as XFF, but without even the ambiguity-defense of a chain to inspect.

**Why it's exploitable:** exactly the same as XFF — if NGINX is not configured to *overwrite* this header (rather than pass through a client-supplied one), the client's own `X-Real-IP` value reaches the application unchanged. Many NGINX configs set it correctly (`proxy_set_header X-Real-IP $remote_addr;`) at the edge, but internal microservice-to-microservice hops (App → internal API) frequently forget this, letting a spoofed value survive all the way to the rate-limiting service.

**Exploit pattern:**
```
X-Real-IP: 203.0.113.7
```
Simple single-value rotation, same principle as XFF but no chain to construct.

### 1.3 `X-Originating-IP`

**Format:** `X-Originating-IP: <IP address>`

**Why it's trusted:** originally an email-header convention (Microsoft Outlook Web Access used it to record the sender's originating IP), it was later adopted informally by some web application load balancers and WAFs as an alternate "real IP" signal. It's less standardized than XFF or X-Real-IP, which paradoxically makes it MORE likely to be trusted blindly where present — because it's rare enough that developers who do handle it usually do so via a single custom code path with no validation, having copied it from a specific vendor's documentation rather than a general convention with security caveats attached.

**Why it's exploitable:** identical root cause — client-controlled, no cryptographic binding to the actual TCP source.

**Exploit pattern:**
```
X-Originating-IP: 198.51.100.23
```

### 1.4 `CF-Connecting-IP`

**Format:** `CF-Connecting-IP: <IP address>`

**Critical distinction from the above three:** this header is set by **Cloudflare's edge**, not by the origin's own reverse proxy, and Cloudflare strips any client-supplied `CF-Connecting-IP` header before setting its own authoritative value. **You cannot spoof this header directly against a properly configured Cloudflare-fronted origin** — Cloudflare overwrites it regardless of what you send.

**Where the exploit actually lives:** the vulnerability is not "Cloudflare trusts a fake header" — it's **origin misconfiguration that allows direct-to-origin access, bypassing Cloudflare entirely.** If you can discover the origin server's real IP address (via DNS history, SSL certificate transparency logs, or a subdomain that isn't proxied through Cloudflare), you can connect to the origin directly, and if the origin's rate limiter is keyed on `CF-Connecting-IP` while the origin has no logic to verify the request actually came through Cloudflare, you can set `CF-Connecting-IP` to anything you want because you're now talking to the origin's application code directly, with no Cloudflare edge in between to overwrite it.

**Exploit pattern (requires origin IP discovery first):**
```
GET /api/login HTTP/1.1
Host: victim.com
CF-Connecting-IP: 1.1.1.1
```
sent directly to the discovered origin IP, with the `Host` header set to the real hostname so the origin's virtual-host routing still serves the correct application.

**This is why File 3 (WAF/Bot Protection Evasion)'s relevance note matters here:** this specific header's bypass is fundamentally an origin-exposure issue, not a header-trust-parsing issue like the first three. Treat it as a distinct vulnerability class even though the symptom (rate limit reset) looks identical.

### 1.5 `True-Client-IP`

**Format:** `True-Client-IP: <IP address>`

**Why it's trusted:** this is Akamai's equivalent of Cloudflare's `CF-Connecting-IP` — set at Akamai's edge for origins behind Akamai CDN. It has since also been adopted by Cloudflare Enterprise plans as an alternate header name for the same purpose (client IP as seen by the edge).

**Why it's exploitable:** same class of issue as `CF-Connecting-IP` — the CDN provider overwrites this header at their edge, so it's not spoofable against a properly fronted request. The exploit path is again origin exposure: if the origin is reachable directly (bypassing Akamai/Cloudflare), the origin's application code has no way to distinguish a genuine edge-set header from a self-supplied one, because verifying that distinction would require validating a shared secret or mTLS certificate between edge and origin — a control that's commonly documented as best practice (Cloudflare "Authenticated Origin Pulls") but inconsistently implemented.

---

## 2. Platform / Framework Trust Matrix

| Platform / Framework | Header(s) trusted by default | Trust condition |
|---|---|---|
| NGINX (as reverse proxy) | None inbound by default | Only trusts what IT sets outbound to upstream; the vulnerability is in what the upstream app does with it |
| Express.js (`trust proxy`) | `X-Forwarded-For` | Trusts ALL hops if set to `true`; trusts N hops if set to an integer; trusts nothing if unset (default) |
| Django (`SECURE_PROXY_SSL_HEADER` + custom middleware) | `X-Forwarded-For` (via custom `get_client_ip()` utility functions, not built-in) | Entirely dependent on how the dev's own middleware parses the header — Django has no built-in XFF trust, so every Django app's behavior here is bespoke and unpredictable |
| Ruby on Rails (`config.action_dispatch.trusted_proxies`) | `X-Forwarded-For` | Rails has explicit trusted-proxy configuration; misconfiguration (empty trusted list = trust everything) is the common flaw |
| Cloudflare (edge) | Sets `CF-Connecting-IP`, `True-Client-IP` (Enterprise) | Overwrites client-supplied values; NOT spoofable at the edge, only bypassable via direct origin access |
| Akamai (edge) | Sets `True-Client-IP` | Same as Cloudflare — overwrites, not spoofable at edge |
| AWS API Gateway + ALB | `X-Forwarded-For` (ALB appends real IP) | ALB appends the true IP as the LAST entry in the chain; app code reading the FIRST entry instead of the last is the common flaw here |
| Kong Gateway | `X-Forwarded-For`, `X-Real-IP` (configurable via `trusted_ips`) | If `trusted_ips` isn't restricted, Kong will trust and forward client-supplied values downstream unchanged |

**Key operational takeaway:** for AWS ALB specifically, the real client IP is always the LAST IP in the XFF chain, not the first — this is opposite to the naive assumption most developers make when they write `xff.split(',')[0]`. When testing, try both interpretations; the specific bug is often "app reads index 0, but should read index -1" (or vice versa) after passing through a specific number of trusted hops.

---

## 3. Practical Rotation Workflow

1. **Baseline the limit.** Send requests without any spoofed header until you get rate-limited (HTTP 429, or a WAF challenge, or a silent drop). Note the exact request count and time window.
2. **Add one header, rotate value per request.** Start with `X-Forwarded-For` since it's the most commonly trusted. Use Burp Intruder with a "Sniper" attack, payload position on the header value, payload list = randomized IPv4 addresses (avoid RFC 1918 private ranges unless testing internal trust boundaries specifically, since some apps whitelist/blacklist private ranges differently).
3. **If XFF fails, try `X-Real-IP`, then `X-Originating-IP`.** Test them individually first — sending multiple conflicting IP headers simultaneously can sometimes cause the app to fall back to a different header than the one you're manipulating, masking whether your target header actually worked.
4. **If both fail, test header stacking.** Some parsers concatenate or get confused by multiple headers present at once, occasionally re-introducing a bypass that a single-header test wouldn't reveal — e.g. sending both `X-Forwarded-For: <spoofed>` and a legitimate-looking `X-Real-IP`, if the app's fallback logic checks XFF first but the rate limiter middleware checks X-Real-IP first (a coordination bug is common when logging and rate-limiting are implemented by different teams/libraries).
5. **Confirm the reset, not just the absence of a 429.** Some apps silently cap you at a lower "unknown IP" tier rather than truly resetting the counter — verify by checking response headers like `X-RateLimit-Remaining` if present, or by pushing well past the original threshold to confirm total request count, not just the first non-429 response.

---

## 4. WAF / API Gateway Relevance for This Specific Technique

WAF/Gateway relevance here is **direct and central** — this entire technique's success or failure is determined by gateway/application configuration, not by evading a detection system after the fact. There are two distinct scenarios:

- **Misconfigured trust (Sections 1.1–1.3):** the "bypass" isn't evading a defense — it's exploiting the defense's own trust assumption. There's nothing to "get past" beyond sending the header; the gateway or app was never validating it in the first place.
- **CDN-fronted origin exposure (Sections 1.4–1.5):** here, the CDN edge is functioning correctly and DOES block header spoofing — the actual finding is origin exposure allowing you to bypass the CDN entirely. Detection at this layer would need to be origin-side (e.g. verifying a shared secret header set only by the CDN, checking `mTLS` client certs from the edge), which most origins don't implement.

**Realistic bypass ceiling:** if a gateway is correctly configured (explicit trusted-proxy IP list, correct hop-count validation, or CDN-set headers that are cryptographically or network-level protected from client override), this entire technique class fails outright — there is no secondary spoofing trick that defeats a correctly implemented trusted-proxy chain. Don't oversell this technique in a report as universally applicable; it's entirely dependent on a specific, common, but not universal misconfiguration.

---

## Real-World Notes

- The single most reliable "quick win" in bug bounty API testing is trying `X-Forwarded-For: 127.0.0.1` and `X-Forwarded-For: localhost` — some apps have special-cased logic that treats loopback addresses as "internal/trusted" and exempts them from rate limiting entirely, rather than just resetting the counter.
- When an application is behind CloudFront (AWS) rather than Cloudflare, the equivalent edge-set header is `CloudFront-Viewer-Address` — worth testing for the same origin-exposure pattern documented for `CF-Connecting-IP`.
- In real engagements, the XFF bypass frequently works on the LOGIN endpoint specifically but not on other API endpoints in the same application — because login rate limiting is often bolted on separately (e.g. via `express-rate-limit` middleware applied only to `/login`) while general API rate limiting goes through the API gateway layer, which may be configured more strictly. Test each endpoint's rate limit independently; don't assume uniform enforcement across an API surface.
- Document the exact header, exact value pattern, and exact request count in your report — "IP spoofing bypasses rate limiting" without specifics is not reproducible and will bounce back from triage.
