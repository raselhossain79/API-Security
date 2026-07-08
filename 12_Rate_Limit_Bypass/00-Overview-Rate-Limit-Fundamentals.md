# API Rate Limit & Bot Protection Bypass — Overview and Fundamentals

## Scope of This Series

This series covers bypassing rate limits and bot protections that **already exist and are actively enforced**. It does not cover discovering endpoints that have no rate limiting at all — that scenario belongs to Topic 10 (Unrestricted Resource Consumption / API4) in the OWASP API Security Top 10 series, since an absent control is a design gap, not a bypass.

Everything here assumes: a limit exists, it is being enforced, and the goal is to defeat the enforcement mechanism itself.

---

## 1. Why Rate Limits Exist

Rate limiting exists to protect three things:

- **Availability** — prevent resource exhaustion from excessive requests (this overlaps with API4 in the OWASP API Top 10)
- **Business logic integrity** — prevent abuse of finite or countable actions (coupon redemption, voting, referral bonuses)
- **Authentication integrity** — slow down credential stuffing, password brute-forcing, and OTP guessing

A rate limit that can be bypassed doesn't just allow "more requests" — it re-enables the exact attack it was deployed to stop. A bypassed login rate limit means brute-forcing is back on the table. A bypassed OTP rate limit means a 4-6 digit code becomes guessable within its validity window.

---

## 2. How Rate Limiting Actually Works (Mechanism-First)

To bypass a rate limit, you need to understand **what the server is counting, and what it is counting it against**. There are two independent variables:

### 2.1 The Counting Key (what identifies "one client")

This is the single most exploitable part of any rate limit implementation. Common keys, in order of how commonly they're weakly implemented:

| Key type | How it's derived | Bypass angle |
|---|---|---|
| Source IP address | `socket.getpeername()` or a trusted proxy header | Header spoofing (Section 1 of this series) |
| Session/Cookie | Session ID in a cookie | Requires session farming, less common bypass target |
| API key / Bearer token | Value of `Authorization` header | Requires multiple keys (account distribution, Section 2) |
| Account ID | Authenticated user identity | Requires multiple accounts (account distribution, Section 2) |
| Combination key | e.g. IP + endpoint, or account + endpoint | Requires bypassing multiple dimensions simultaneously |

**Why this matters:** most real-world rate limiters are keyed on IP address alone, because it requires no authentication state and is cheap to check at the edge (load balancer, CDN, or WAF). This is precisely why IP-spoofing bypass is the highest-value technique in this series — it attacks the cheapest, most commonly (mis)trusted signal.

### 2.2 The Counting Window (the time dimension)

- **Fixed window** — e.g. "100 requests per IP per calendar minute." Resets hard at the minute boundary. This is exploitable at the boundary edge: send 100 requests at 12:00:59, then another 100 at 12:01:00 — 200 requests in under 2 seconds, both technically within their respective windows.
- **Sliding window** — the window recalculates continuously (e.g. "last 60 seconds from now"), removing the hard-edge exploit above. Harder to abuse via timing alone.
- **Sliding window log / leaky bucket / token bucket** — tracks individual request timestamps or a refillable token pool. Most resistant to timing tricks, but still bypassable through counting-key attacks (Section 2.1) since the window logic doesn't matter if the key itself is forgeable.

Identifying which of these three is in use is the first practical step of any rate limit bypass engagement — covered in File 3 (Timing, Distribution, and Endpoint Variation).

### 2.3 The Enforcement Point (where the count is checked)

This is the architectural layer doing the counting, and it determines which bypass class applies:

- **CDN / edge (Cloudflare, Akamai, Fastly)** — usually keys on the CDN's own view of the client IP, which is authoritative and NOT spoofable via headers from outside. `CF-Connecting-IP` is set BY Cloudflare, not read from the client's request headers as trusted input at this layer.
- **API Gateway (Kong, AWS API Gateway, Apigee, NGINX)** — often configurable to trust `X-Forwarded-For` from upstream, and misconfiguration here is the most common root cause of header-spoofing rate limit bypass.
- **Application layer (framework middleware, custom code)** — the application code reads a header (often blindly, following a tutorial that used `request.headers.get('X-Forwarded-For')` without validating the request's actual source), and this is the layer most consistently vulnerable to spoofing.

**The critical insight:** header-based IP spoofing does NOT bypass rate limiting at the CDN/edge layer (the edge sees the real TCP source IP regardless of what headers you send). It bypasses rate limiting at the **application or gateway layer**, when that layer trusts a client-supplied header as if it were the true origin IP. This distinction is why Section 1 of this series spends significant time on WHICH component trusts WHICH header, and why.

---

## 3. Threat Model for This Series

Every technique in this series assumes one of these realistic scenarios:

1. The application is deployed behind a reverse proxy / load balancer, but the application code (not the proxy) does the rate-limit accounting and trusts a forwarded-IP header without re-validating it against the actual upstream peer.
2. The rate limit is keyed per-account or per-API-key, and account creation is free or low-friction enough to make horizontal account distribution viable.
3. The rate limit uses fixed time windows and the tester can determine the window boundary through response headers or empirical timing.
4. A bot-protection layer (WAF, CAPTCHA trigger, behavioral fingerprinting) sits in front of or alongside the rate limiter, and needs to be evaded simultaneously with the rate limit itself.

---

## 4. Is WAF / API Gateway Bypass Relevant to This Topic?

**Yes — but only for a specific subset of techniques, and this needs an honest breakdown rather than a blanket "WAF bypass section" in every file:**

- **Header-based IP spoofing (File 1)**: WAF/Gateway relevance is direct and central. The entire bypass depends on gateway/application misconfiguration in header trust. File 1 covers this as its core content, not as an add-on.
- **Timing/distribution/endpoint variation (File 2)**: WAF/Gateway relevance is partial. Endpoint-variation bypass specifically exploits gateways or app routers that normalize paths inconsistently between the rate-limiter component and the route handler. Timing and account-distribution bypasses are largely WAF-agnostic — they work (or don't) based on the rate limiter's own logic, not on WAF evasion.
- **WAF and bot protection evasion (File 3)**: this IS the WAF-bypass file. It's a full dedicated file rather than a section, because bot-protection evasion (User-Agent rotation, fingerprint variation, timing randomization) is a large enough topic to need its own depth, per your requirements.
- **Turbo Intruder (File 4)**: WAF relevance is operational — the script's concurrency and header rotation settings are what determine whether a WAF-level anomaly detector fires. Covered inline in that file's parameter breakdown.

Rather than force an artificial "WAF Bypass" section into every single file where it would add nothing (e.g. it would be filler in a file about account distribution, where the WAF has no defensive role), each file states plainly whether WAF/gateway defenses are a meaningful factor for that specific technique, and why.

---

## 5. Lab and Practice Environment Mapping (Full Series)

PortSwigger Web Security Academy does not have a lab category literally named "rate limit bypass." The directly relevant labs are spread across the **Authentication** and **Race Conditions** categories, because rate limit bypass is the mechanism, and brute-forcing/business-logic-abuse is the impact demonstrated. This series maps every lab that is genuinely applicable — no filler labs included.

### Apprentice
| Lab | Category | Relevance |
|---|---|---|
| Username enumeration via different responses | Authentication | Establishes brute-force baseline before layering in rate-limit bypass |
| Username enumeration via subtly different responses | Authentication | Same as above, subtler oracle |
| Limit overrun race conditions | Race Conditions | Foundational single-request race window concept, prerequisite for File 2 and File 4 |

### Practitioner
| Lab | Category | Relevance |
|---|---|---|
| Broken brute-force protection, IP block | Authentication | **Direct match.** IP-based lockout bypassed via header manipulation — core lab for File 1 |
| Username enumeration via response timing | Authentication | **Direct match.** Explicitly documented as bypassable via `X-Forwarded-For` spoofing — core lab for File 1 |
| Username enumeration via account lock | Authentication | Account-lock logic flaw; relevant to File 2's distribution concepts |
| Password brute-force via password change | Authentication | Rate-limit-adjacent brute-force scenario on a non-login endpoint |
| Bypassing rate limits via race conditions | Race Conditions | **Direct match, name says it all** — core lab for File 2 and File 4 |
| Multi-endpoint race conditions | Race Conditions | Endpoint-variation-adjacent concept for File 2 |
| Single-endpoint race conditions | Race Conditions | Core Turbo Intruder single-packet concept for File 4 |
| Exploiting time-sensitive vulnerabilities | Race Conditions | Timing-window concept for File 2 |

### Expert
| Lab | Category | Relevance |
|---|---|---|
| Partial construction race conditions | Race Conditions | **Honest gap disclosure:** this lab is about exploiting partially-constructed database state during a race window, not rate-limit bypass directly. It's included here because it's the only Expert-tier lab in the applicable category, and the underlying single-packet/concurrency technique from Turbo Intruder is directly transferable — but the vulnerability class it teaches is adjacent, not identical, to rate limit bypass. Treat it as an advanced-technique lab, not a rate-limit-specific one. |

**Honest gap disclosure:** There is currently no Expert-tier lab that directly targets rate-limit-bypass-for-its-own-sake in the same way the Practitioner "Bypassing rate limits via race conditions" lab does. The Expert tier in this category tests race condition sophistication generally, which is the adjacent skill.

---

## 6. crAPI Supplementary Practice

crAPI (Completely Ridiculous API) is useful here specifically because, unlike PortSwigger labs, it exposes **real Node.js/Python microservice code with actual header-trust misconfigurations**, rather than a black-box lab. Relevant crAPI components:

- The **community post / forgot-password OTP flow** — has a weak rate limit on OTP submission attempts, useful for practicing timing-window and account-distribution bypass together.
- The **coupon/voucher redemption endpoint** in the workshop/service module — a countable business-logic action, good for practicing endpoint-variation bypass against Express.js route matching.
- crAPI is deployed via Docker Compose with source available, so you can inspect the actual middleware doing the rate-limit check — read the code after attacking it to confirm which header or key it trusted. This code-then-confirm workflow isn't available with PortSwigger's black-box labs and is the main reason to run crAPI alongside them.

---

## 7. File Index for This Series

1. **00-Overview-Rate-Limit-Fundamentals.md** (this file)
2. **01-Header-Based-IP-Spoofing-Bypass.md**
3. **02-Timing-Distribution-Endpoint-Variation-Bypass.md**
4. **03-WAF-Bot-Protection-Evasion.md**
5. **04-Turbo-Intruder-Rate-Limit-Bypass.md**
6. **05-Final-Cheatsheet.md**

---

## Real-World Notes

- In bug bounty reports, "rate limit bypass" alone is rarely a payable finding — the payable finding is what the bypass *enables* (account takeover via brute-force, OTP brute-force, financial abuse via coupon farming). Always frame the report around impact, with the bypass as the enabling mechanism.
- The single most common root cause seen in real applications is a rate limiter implemented in application middleware (e.g. `express-rate-limit`, `django-ratelimit`) configured with `keyGenerator` reading `req.headers['x-forwarded-for']` directly, with no corresponding `trust proxy` validation against the actual upstream hop count. This is a copy-paste-from-Stack-Overflow problem, not a sophisticated flaw — expect to find it often.
- Cloud WAFs (AWS WAF, Cloudflare) rate-limit at their own edge using their own IP determination, which is not spoofable this way. The vulnerable target is almost always the origin application's own secondary rate limiting, not the CDN's.
