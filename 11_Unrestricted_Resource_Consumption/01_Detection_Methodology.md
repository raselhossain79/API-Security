# API4:2023 — Detection Methodology

## Detecting Missing or Weak Rate Limiting

This file covers three independent detection approaches. In practice, use all
three — a target can pass one check and fail another (e.g., it may send
`X-RateLimit-*` headers that are purely cosmetic and never actually enforced).

---

## 1. Response-Based Detection (Header Analysis)

### 1.1 What to Look For

When you send a request to an API endpoint, inspect the **response headers**
for rate-limit signaling. These headers are not part of a single universal
standard — different gateways/frameworks emit different sets — so check for
all common variants:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1720252800
Retry-After: 30
RateLimit-Limit: 100
RateLimit-Remaining: 87
RateLimit-Reset: 30
```

**Piece-by-piece breakdown of what each header tells you:**

| Header | Meaning | Why It Matters to an Attacker |
|---|---|---|
| `X-RateLimit-Limit` / `RateLimit-Limit` | Total requests allowed in the current window | Tells you the exact ceiling before you get blocked — plan your attack request count to stay just under it, or confirm the ceiling is high enough to be exploitable |
| `X-RateLimit-Remaining` / `RateLimit-Remaining` | Requests left in the current window | Lets you track consumption in real time without guessing; if this decrements per request but never reaches 0 and blocks, the header is cosmetic (not enforced) |
| `X-RateLimit-Reset` / `RateLimit-Reset` | Timestamp or seconds until the window resets | Tells you exactly when to resume attack traffic after being throttled — turns a "blocked" endpoint into a "scheduled" endpoint |
| `Retry-After` | Seconds (or HTTP date) to wait before retrying, sent on a 429 response | Confirms enforcement is actually happening (this header alone, on its own, is a stronger enforcement signal than the `X-RateLimit-*` set, because it's typically only sent *after* a limit is hit) |

### 1.2 The Critical Distinction: Signaling vs. Enforcement

The single most important thing to verify: **do these headers correlate with
an actual block?**

Test procedure:
1. Send a baseline request. Record `X-RateLimit-Remaining`.
2. Send requests in a loop, decrementing the counter each time.
3. When the counter should reach 0 (based on the `Limit` value), check whether
   the next request actually returns `429 Too Many Requests` (or `403`).
4. If the counter keeps decrementing below what should be possible (e.g., goes
   negative, or the API keeps returning `200 OK` after `Remaining: 0`), the
   header is **decorative only** — the gateway is not actually enforcing
   anything, just reporting a value calculated independently of the real
   request handling path. This is a very common real-world finding: rate
   limit headers are added by a middleware layer that was never wired to an
   actual blocking mechanism.

### 1.3 Endpoints That Send No Headers At All

Absence of any rate-limit headers is not proof of absence of limiting (some
gateways enforce silently), but it is a strong signal to test further,
especially when:
- The endpoint is a POST/PUT/DELETE (state-changing) endpoint — these are
  frequently excluded from gateway-level rate-limit policies that were
  configured with only GET/read traffic in mind.
- The endpoint sits behind a different base path or subdomain than the main
  API (e.g., `api.target.com` has limiting, but `internal-api.target.com` or
  `api.target.com/v1/legacy/*` does not).

### 1.4 Real-World Note

A common finding pattern: the main authentication endpoint
(`/api/v1/auth/login`) has strict, correctly enforced rate limiting because
it was explicitly designed with brute-force in mind. Meanwhile, a
"forgot password" or "resend verification email" endpoint on the *same*
API, built later by a different team, has zero headers and zero enforcement,
because it wasn't perceived as security-sensitive at design time. Always test
every endpoint independently — do not assume uniform policy across an API
just because one endpoint is well-protected.

---

## 2. Timing-Based Detection

Timing-based detection is used when headers are absent or unreliable, and
also to distinguish real enforcement from a WAF/gateway that silently drops
requests without a clean `429`.

### 2.1 Baseline-and-Burst Method

1. **Baseline**: Send 5–10 requests spaced 2–3 seconds apart. Record response
   time for each. This is your "normal" latency profile.
2. **Burst**: Send 50–100 requests as fast as the client allows (no delay
   between them). Record response time and status code for each.
3. **Compare**:
   - If response times during the burst stay consistent with baseline, and
     all return `200`, rate limiting is very likely absent.
   - If response times climb progressively (e.g., request 1 = 80ms, request
     50 = 4000ms) while status stays `200`, this indicates the *backend* is
     under load from your burst (a resource exhaustion symptom itself,
     covered in file `02`), not that a gateway is throttling you.
   - If you see a sudden flat response time increase (e.g., every request
     after request 40 takes exactly 1000ms) with status still `200`, this can
     indicate a **tarpit-style** defense — the gateway is intentionally
     slowing responses instead of rejecting them, to discourage automated
     abuse without breaking legitimate retry logic.

### 2.2 Timing Side-Channel for Detecting Silent Drops

Some gateways silently drop (RST or connection timeout) requests over a
threshold instead of returning `429`. Detect this by:
- Sending requests with a client that logs **connection-level** timing (TCP
  handshake time, TLS handshake time, time-to-first-byte), not just
  HTTP-level response time.
- A sudden shift from "fast TTFB, 200 response" to "connection accepted but
  hangs until client-side timeout" indicates the request is being silently
  queued or dropped at the gateway/load-balancer level, which is a form of
  enforcement that response-header inspection alone would never reveal.

### 2.3 Real-World Note

Timing-based detection is noisy on shared cloud infrastructure — a
legitimate CDN cache miss, cold-start on serverless (AWS Lambda, Azure
Functions) backing an API, or unrelated backend load can all produce timing
variance that looks like throttling. Always correlate timing anomalies with
status codes and, where possible, retest at a different time of day before
concluding a timing pattern is caused by rate-limiting logic specifically.

---

## 3. Behavioral Difference Detection (Rate-Limited vs. Unlimited Endpoints)

This is the most reliable detection method because it doesn't depend on the
target sending honest signals (headers) or having clean timing characteristics
— it directly tests functional behavior.

### 3.1 Method

1. Identify a **known rate-limited reference endpoint** on the same API
   (commonly `/login` or `/auth/token`, since these are almost always
   protected against brute-force by design).
2. Send bursts against the reference endpoint and confirm you *do* get
   blocked (`429`/`403`) at a predictable threshold. This proves the API's
   gateway/infrastructure is *capable* of enforcing limits — ruling out
   "maybe my testing method is wrong" as an explanation for a negative result
   elsewhere.
3. Send the *same burst pattern, same client, same source IP* against your
   target endpoint.
4. If the reference endpoint blocks you but the target endpoint does not,
   this is strong, low-ambiguity evidence that the target endpoint
   specifically lacks rate limiting — not that your testing setup is
   flawed or that some upstream network control is intervening.

### 3.2 Why This Matters for Report Quality

Bug bounty triagers frequently push back on resource consumption reports with
"our WAF handles this" or "you're not sending enough requests." Demonstrating
that a *sibling endpoint on the same infrastructure* enforces limits under
identical test conditions pre-empts that objection — it proves the
capability exists and was simply not applied consistently.

### 3.3 Differential Testing Across HTTP Methods and Parameter Variants

Rate limiting is sometimes bound to a specific route signature rather than
the underlying resource. Test all of the following against the same logical
endpoint:
- Same path, different HTTP method (`GET /api/users/123` limited, but
  `PATCH /api/users/123` unlimited)
- Trailing slash variants (`/api/users` vs `/api/users/`)
- Case variants (`/API/Users` vs `/api/users`) — some gateways match rate
  limit rules case-sensitively while the backend routes case-insensitively
- API version prefix variants (`/v1/users` limited, `/v2/users` not yet
  added to the rate limit policy after a version migration)
- Query string vs path parameter equivalents where the API supports both

### 3.4 Real-World Note

This differential approach is precisely how several real disclosed reports
found that a company's *GraphQL* endpoint had none of the REST API's rate
limiting, because the GraphQL gateway was deployed separately and the
security team's rate-limiting rollout only covered documented REST routes.
Always check whether a target exposes multiple API paradigms (REST,
GraphQL, gRPC-Web, SOAP legacy) and test each independently rather than
assuming a finding on one transfers to the others.

---

## 4. Consolidated Detection Checklist

- [ ] Inspect every endpoint response for `X-RateLimit-*` / `RateLimit-*` /
      `Retry-After` headers
- [ ] Verify header values correlate with actual enforcement (decrement to 0
      → real `429`, not continued `200`)
- [ ] Run baseline-vs-burst timing comparison
- [ ] Check for silent drops via connection-level timing, not just HTTP status
- [ ] Identify a known-protected reference endpoint on the same API
- [ ] Run identical burst against reference vs. target endpoint
- [ ] Test HTTP method, trailing slash, case, and version variants of the
      same logical route
- [ ] Test REST vs GraphQL vs any alternate API paradigm exposed by the same
      backend separately

Proceed to `02_Resource_Exhaustion_Techniques.md` once you've confirmed an
endpoint lacks effective rate limiting, to weaponize that finding into
demonstrable impact.
