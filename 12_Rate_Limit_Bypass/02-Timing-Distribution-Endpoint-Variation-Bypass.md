# Timing, Account Distribution, and Endpoint Variation Bypass

This file covers three distinct bypass classes that don't depend on header spoofing. Each attacks a different assumption the rate limiter makes: that time windows are exploitable at their boundary, that one account equals one identity, or that a URL string uniquely and consistently identifies one endpoint.

---

## 1. Timing-Based Bypass (Window Boundary Exploitation)

### Mechanism

Recall from the Overview file that fixed-window rate limiters reset their counter at a hard time boundary (e.g. every 60 seconds, aligned to the clock). The limiter does not track a continuously moving window — it tracks "how many requests in THIS window," where "this window" is a discrete bucket like `[12:00:00–12:00:59]`.

**Why this is exploitable:** if you send your full quota of requests in the last second of a window, then immediately send another full quota in the first second of the next window, you've sent double your intended rate in under two seconds — while never technically exceeding the "N requests per window" rule in either individual window.

### Step 1: Identify the Window Type

You cannot apply this technique blindly — you must first determine whether the limiter is fixed-window (exploitable) or sliding-window/token-bucket (not exploitable this way).

**Empirical test procedure:**
1. Send requests until you hit the rate limit (429 or block).
2. Note the exact wall-clock time of the first blocked request.
3. Wait exactly until the next round time boundary that would make sense for the stated limit (e.g. if the limit looks like "60 requests/minute," wait until the next `:00` second mark).
4. Immediately burst requests again at that boundary.
5. **If the burst succeeds in full** → fixed window, aligned to clock boundaries. Exploitable.
6. **If the burst is still partially or fully blocked** → sliding window or token bucket. Not exploitable via this method; move to Section 2 or 3 instead.

**Response header clues (when present):** `X-RateLimit-Reset` or `Retry-After` headers often directly disclose the window's reset timestamp, removing the need for empirical boundary-hunting — always check these headers before assuming you need to guess the boundary.

### Step 2: Exploit the Boundary

Once confirmed as fixed-window:
```
[Window N, last 2 seconds]  → burst full quota
[Window N+1, first 2 seconds] → burst full quota again
```
Repeat at every window boundary for sustained above-limit throughput. In practice this means scripting a burst that fires at a computed offset before each boundary, rather than manually timing it — Turbo Intruder (File 4) is the standard tool for this because it lets you control exact request dispatch timing at the packet level.

### WAF / Gateway Relevance

Largely **not relevant** for this specific technique. This is a logic flaw in the rate limiter's own window implementation, not something a WAF or gateway is positioned to detect or prevent — unless the WAF has its own independent behavioral/velocity detection layered on top (covered in File 3), the window-boundary trick operates entirely below that detection layer's typical granularity (a burst-then-pause pattern can look like normal bursty traffic rather than a sustained attack signature).

---

## 2. Account-Level Distribution Bypass

### Mechanism

When the rate-limit key is the authenticated account/API-key rather than IP address, IP spoofing (File 1) does nothing — the limiter never looked at your IP in the first place. The equivalent bypass is to distribute the same attack across multiple accounts, each of which gets its own fresh quota.

**This matters most for:**
- OTP/2FA brute-forcing (each account gets its own OTP attempt counter)
- Coupon/promo code testing (each account can redeem N failed attempts before lockout)
- API key–gated endpoints where the limit is `requests per key per hour`

### Step 1: Establish Account Creation Cost

Before planning distribution, determine:
- Is account creation free, and how automatable is it? (Email verification required? CAPTCHA on signup? Disposable email domains blocked?)
- Is there a secondary limit on account creation itself (e.g. "5 accounts per IP per day")? If so, this now requires combining Section 2 with File 1's IP rotation — account creation AND the subsequent action both need distinct identities.
- Does the target action (e.g. coupon redemption) require any account "aging" or verification state before it's usable, which would add latency to the attack?

### Step 2: Build the Distribution Pool

A pool of 10-50 accounts is typically sufficient to demonstrate the vulnerability class in a bug bounty / pentest report — you don't need thousands of accounts to prove the underlying flaw, since the finding is "the limit is keyed on account, and accounts are cheap," not "I can scale this to production-breaking volume" (though noting the theoretical scale in your report strengthens impact).

**Automation approach:**
1. Script account registration with a templated email pattern (if the target allows email aliasing via `+` tags, e.g. `user+1@gmail.com` through `user+50@gmail.com`, this defeats email-uniqueness checks trivially while all mail lands in one inbox).
2. Extract each account's session token or API key immediately after registration.
3. Round-robin the target action across the full pool of tokens.

### Step 3: Combine With IP Rotation If Needed

If accounts are ALSO rate-limited by IP at signup (common defense), pair this with File 1's header spoofing during the registration phase specifically, even if the main attack (the actual abuse action) doesn't need IP rotation at all because it's keyed on account identity alone. Testers often miss this — they correctly identify the main endpoint's key as "account-based" and then wrongly conclude IP spoofing is irrelevant to the whole engagement, when it's actually a prerequisite for building the account pool efficiently.

### WAF / Gateway Relevance

**Partial relevance.** A WAF or bot-management layer (e.g. Cloudflare Bot Management, Akamai Bot Manager, PerimeterX) may flag the ACCOUNT CREATION phase as bot-like traffic (many signups from similar request patterns, timing, or fingerprints) even though it has no visibility into "is this the same person abusing account-level rate limits downstream." This is why File 3's fingerprint variation techniques often need to be applied specifically during the account-creation phase of this attack, not necessarily during the main abuse phase.

---

## 3. Endpoint Variation Bypass

### Mechanism

Rate limiters are frequently implemented as middleware attached to a **specific route pattern**, e.g. `app.post('/api/v1/login', rateLimiter, loginHandler)`. The rate limiter's key includes (implicitly or explicitly) the matched route. If the underlying web framework's router treats slightly different URL strings as **different routes** (or fails to normalize them before the rate limiter's route-matching logic runs), each variant gets its own independent counter — even though they all ultimately resolve to the same business logic.

This is fundamentally a **router normalization inconsistency** between the layer that applies the rate limit and the layer that dispatches to the handler.

### 3.1 Case Variation

```
POST /api/v1/login       → counted
POST /api/v1/Login       → separate counter (if routing is case-sensitive at the rate-limit layer, but the underlying web server or framework case-normalizes before reaching the actual handler, e.g. via a case-insensitive filesystem route or a downstream proxy that lowercases paths)
POST /api/v1/LOGIN       → separate counter again
```

**Why this can work:** many rate-limiting solutions are implemented as reverse-proxy-level rules (e.g. NGINX `limit_req_zone` keyed on `$uri`) which are case-sensitive by default, while the application server behind it (especially on case-insensitive filesystem-backed routers, or frameworks with lenient route matching) treats all three as the same login endpoint. The rate limiter sees three different URIs; the application sees one endpoint.

### 3.2 Trailing Slash Variation

```
POST /api/v1/login       → counter A
POST /api/v1/login/      → counter B (if the rate limiter's route match is an exact string, not a normalized-path match)
```

**Why this can work:** Express.js, for instance, by default treats `/login` and `/login/` as equivalent for routing purposes (`strict routing` is off by default) — the handler fires identically for both. But if the rate-limiting middleware was implemented with its own separate route registration (`app.use('/api/v1/login', limiter)` without matching the same strict-routing setting, or a completely separate reverse-proxy rule keyed on exact URI string), the trailing slash creates a second bucket.

### 3.3 Path Parameter / Encoding Variation

```
POST /api/v1/login
POST /api/v1//login        (double slash)
POST /api/v1/./login       (dot-segment)
POST /api/v1/%6cogin       (percent-encoded character, decodes to 'l')
```

**Why this can work:** URL normalization (collapsing `//`, resolving `.` and `..` segments, percent-decoding) is supposed to happen once, consistently, before any routing or rate-limit decision. In practice, it's common for this normalization to happen at the framework/router level but NOT at a separate rate-limiting proxy layer sitting in front of it (or vice versa) — because the two components were built by different teams/vendors with different assumptions about who owns normalization.

### Step-by-Step Testing Procedure

1. Trigger the rate limit on the canonical endpoint (`/api/v1/login`) to establish the baseline threshold.
2. Immediately after hitting the limit, retry the exact same request with ONE variation applied (case change first, since it's the simplest and most commonly overlooked).
3. If the varied request succeeds (200/302, not 429) AND produces the same application behavior (e.g. actually attempts a login, doesn't 404), you've confirmed a distinct counter for that variant.
4. Repeat for each variation type individually — don't combine multiple variations in one test, since you need to isolate which specific normalization gap is present (case-only vs. trailing-slash vs. encoding) for accurate reporting.
5. Confirm the variation doesn't silently change the business logic outcome — some frameworks will accept the varied URL for routing but subtly alter parameter parsing or session handling, which would invalidate the finding (you'd be testing a genuinely different code path, not the same login logic with a bypassed counter).

### WAF / Gateway Relevance

**Direct and central relevance** — this technique exists specifically BECAUSE of an inconsistency between a gateway/proxy-level rate limiter and the application's own router. This is arguably the clearest example in the entire series of a pure WAF/Gateway-layer normalization bug. A gateway or WAF that normalizes paths identically to the backend application (e.g. both use the exact same normalization library, or the gateway delegates entirely to backend-reported canonical paths rather than maintaining its own view) closes this bypass entirely.

---

## Real-World Notes

- Timing-boundary bypass is the hardest of these three to demonstrate cleanly in a report because it requires precise sub-second timing — a burst script with a computed delay is far more convincing evidence than a manual description, so pair this finding with a Turbo Intruder script output (File 4) showing the exact request timestamps straddling the window boundary.
- Account distribution findings are frequently down-triaged by bug bounty programs as "expected behavior — CAPTCHA/email verification is the actual control, not the rate limit" if you don't also demonstrate that account creation itself is trivially automatable. Always include your account-creation bypass method (email aliasing, CAPTCHA absence, etc.) as part of the same report, not as a separate finding.
- Trailing-slash and case-variation bugs are disproportionately common on APIs migrated from an older framework version to a newer one, where the rate-limiting middleware was configured once early on and never revisited when the router's normalization behavior changed in a later framework upgrade — worth specifically testing on any API you know has a versioned history (`/v1/` vs `/v2/` coexisting) since the older version's rate limiter config is often stale.
