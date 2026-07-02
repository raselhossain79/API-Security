# 03 — Credential Stuffing and Brute-Force Testing Methodology for APIs

This file covers how credential-based attack testing against APIs differs methodologically from testing a traditional web login form, including detection techniques and the practical decision between Burp Intruder and Turbo Intruder.

---

## 1. Why API Brute-Force Testing Is Not the Same as Web Form Brute-Forcing

Web form brute-forcing typically targets a single `POST /login` endpoint that returns an HTML page, where success/failure is usually distinguishable by an obvious signal — a redirect, an error banner rendered in the page, or a changed page title. API brute-force testing differs in several important ways:

- **Response signals are structured, not visual.** APIs return JSON/XML with status codes and structured error bodies rather than rendered HTML. Detection has to be built around status codes, JSON field values, and response length rather than "does the page show an error banner."
- **Multiple auth endpoints, not one.** A single API often exposes login, token refresh, API key validation, and OAuth token endpoints separately — each may have independently configured (or missing) rate limiting.
- **Higher achievable request rates.** Without a browser rendering a page between requests, API clients can sustain far higher request-per-second rates, which changes both what's realistic for an attacker to attempt and what defenses need to withstand.
- **Rate limiting is frequently inconsistent between web and API surfaces of the same product.** It's a very common finding that a company hardened their web login form against brute-force (CAPTCHA, progressive delays) but the mobile-app-facing API endpoint performing the same login function has no equivalent protection, because it was built or secured by a different team.

---

## 2. Rate Limit Detection Methodology

### 2.1 Baseline Behavior First

Before attempting any volume testing, send a small number of requests (5–10) with deliberately invalid credentials at a normal human-plausible pace and record baseline response characteristics: status code, response body content, response time, and any rate-limit-related headers.

```
curl -i -s -X POST https://api.target.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"wrongpass1"}'
```

Command breakdown:
- `curl` — HTTP client.
- `-i` — includes response headers in the output (critical here, since rate-limit headers live in the headers, not the body).
- `-s` — silent mode, suppresses the progress meter.
- `-X POST` — sets the method to POST.
- `https://api.target.com/v1/auth/login` — target login endpoint.
- `-H "Content-Type: application/json"` — declares JSON body encoding.
- `-d '{"username":"testuser","password":"wrongpass1"}'` — the deliberately incorrect credential pair used to observe failure-response behavior without risking a lockout on a real account.

Check the response headers for explicit rate-limit signaling, which many APIs (especially those behind API gateways like Kong, AWS API Gateway, or Cloudflare) expose directly:
- `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- `Retry-After`
- A `429 Too Many Requests` status code appearing after a certain volume — note the exact request count at which it first appears.

### 2.2 Escalating Volume to Find the Threshold

Using Burp Intruder (see Section 4 for tool selection reasoning) with a **null payload type** (sends the same request repeatedly with no substitution) against the same endpoint, send requests in batches — 10, then 50, then 100 — pausing between batches to observe whether the threshold is a hard request-count limit or a rate-over-time limit (e.g., "10 requests per minute" behaves differently under a burst of 50 requests sent in 2 seconds than the same 50 spread across 5 minutes).

Record for each batch:
- The exact point (request number) where behavior changes (status code shift, new error message, added delay).
- Whether the limit is keyed to IP address, account/username, or a combination (test by rotating the `X-Forwarded-For` header — see Section 2.4 — while keeping the same username, and vice versa).
- Whether the limit resets on a fixed window (e.g., resets exactly 60 seconds after the first request) or a sliding window.

### 2.3 Response-Based Detection — Differentiating Valid from Invalid Credentials Without an Obvious Error Message

Well-built APIs return an identical generic response (`401 Unauthorized`, generic message) for both "user doesn't exist" and "user exists but wrong password," to prevent username enumeration. Weaker implementations leak a distinguishing signal. Check systematically for:

- **Different status codes** — e.g., `404` for nonexistent user vs. `401` for wrong password.
- **Different response body messages** — e.g., `"User not found"` vs. `"Invalid password"`.
- **Different response times** — a valid username that triggers a password hash comparison (bcrypt, Argon2) will often take measurably longer to respond than a nonexistent username that short-circuits before any hashing occurs. This can be tested at scale using Burp's response-time column in Intruder/Turbo Intruder results, sorted to reveal a timing cluster.
- **Different response lengths** — even a few bytes of difference (e.g., an extra field only present in one response type) is enough to reliably distinguish outcomes at scale.

This response-based detection step is what makes API credential attacks tractable in the first place — it lets you build a two-stage attack: first enumerate valid usernames using the distinguishing signal, then focus brute-force effort only on confirmed-valid usernames rather than wasting requests on invalid ones.

### 2.4 Header Manipulation to Test for IP-Based Rate Limit Bypass

Many rate limiters key on client IP as reported by a proxy header, which can sometimes be spoofed if the API gateway trusts client-supplied headers rather than only the actual TCP connection source:

```
curl -s -X POST https://api.target.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 203.0.113.$((RANDOM % 254 + 1))" \
  -d '{"username":"testuser","password":"wrongpass1"}'
```

Command breakdown:
- `-H "X-Forwarded-For: 203.0.113.$((RANDOM % 254 + 1))"` — injects a spoofed client IP header using a randomized last octet each time this command runs; `$((RANDOM % 254 + 1))` is bash arithmetic generating a pseudo-random number between 1 and 254, producing a different fake source IP per request.
- If the rate limit resets or never triggers because the server trusts this header as the "real" client IP, that's a rate-limit bypass finding — the API gateway or application is misconfigured to trust an untrusted, client-controlled header instead of the actual connection-layer source IP.
- Other headers worth testing the same way depending on the target's infrastructure: `X-Real-IP`, `X-Client-IP`, `True-Client-IP`.

---

## 3. Credential Stuffing Methodology

### 3.1 Distinguishing Credential Stuffing from Brute-Force

Brute-force testing (Section 2) targets a **single account** with many password guesses. Credential stuffing targets **many accounts**, each with **one attempt**, using credential pairs sourced from previous breaches (in real-world attacks) or, for authorized testing, a client-approved test list. This distinction matters because the two attack patterns produce very different traffic signatures and can evade defenses tuned only for one pattern — a system that locks an account after 5 failed attempts on that *specific* account does nothing to stop an attacker trying 1 attempt each against 10,000 different accounts.

### 3.2 Testing Methodology

1. **Confirm scope and get explicit authorization** for credential stuffing testing specifically — this is inherently a higher-impact test than single-account brute-force since it touches many accounts, and should use a client-provided or pre-agreed test account list, never real user data, outside of a fully authorized red-team engagement with a scoped, real credential list.
2. Structure the payload as a list of `username:password` pairs (representing the "stuffing" pattern of one attempt per pair) rather than one username against many passwords.
3. Use Burp Intruder's **Pitchfork** attack type (not Sniper or Cluster Bomb) with two payload positions — username and password — fed from two synchronized lists so each request pairs list entry #1 with list entry #1, entry #2 with entry #2, and so on, rather than testing every combination.
4. Apply the same response-based detection from Section 2.3 to identify which pairs succeeded.

### 3.3 Real-World Framing

Credential stuffing is consistently one of the highest-volume attack classes reported in industry breach reports (e.g., Verizon DBIR year-over-year data), precisely because password reuse across services means a breach at Company A routinely yields working credentials at Company B. From an API testing perspective, this is why testing whether an API's authentication endpoint has stuffing-aware defenses — anomaly detection based on distributed low-and-slow patterns across many accounts, not just per-account lockout — is a meaningfully different (and often overlooked) test from basic brute-force lockout testing.

---

## 4. Tool Selection: Burp Intruder vs. Turbo Intruder

### 4.1 Burp Suite Community Edition Intruder — Capabilities and Limits

Community Edition's Intruder is **rate-limited** (artificially throttled compared to Burp Suite Professional) and lacks the multi-threading of the Pro version. It remains the right tool for:
- Low-volume threshold discovery (Section 2.2's small escalating batches).
- Credential stuffing lists in the low hundreds of pairs, where the throttled rate doesn't meaningfully slow down the test.
- Any scenario where precise, easily-reviewable control over each request (via the GUI payload/position markers) matters more than raw speed.

### 4.2 When Community Edition Intruder Becomes a Bottleneck

Once a test requires either (a) genuinely high request volume — thousands of credential pairs, or a large-scale rate-limit-threshold sweep — or (b) precise control over request timing/concurrency to accurately test race-condition-adjacent rate-limit bypass scenarios, Community Edition's throttling becomes the limiting factor rather than the target's own defenses, which will produce misleading results (you can't tell if a slow response is the target's rate limiting or Burp's own throttling).

### 4.3 Turbo Intruder — When and Why

**Turbo Intruder** is a free, open-source Burp extension (available via the BApp Store) built specifically to remove Community Edition's throttling by sending requests using raw sockets and a custom Python-based request engine, achieving far higher request rates with full concurrency control.

Use Turbo Intruder when:
- Testing needs to establish an accurate, high-volume rate-limit threshold that Community Edition's own throttling would otherwise mask.
- A credential stuffing test list runs into the thousands of pairs and needs to complete in a practical timeframe.
- You need precise control over concurrent connections to test for race-condition-style bypasses (e.g., sending many login attempts in a tight burst to see if a rate limiter that checks-then-increments a counter non-atomically can be raced past its intended threshold).

Basic Turbo Intruder script structure for a credential-pair attack:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=10,
                            requestsPerConnection=100,
                            pipeline=False)

    for pair in open('/path/to/pairs.txt'):
        username, password = pair.strip().split(':')
        engine.queue(target.req, [username, password])

def handleResponse(req, interesting):
    if req.status != 401:
        table.add(req)
```

Script breakdown:
- `def queueRequests(target, wordlists):` — Turbo Intruder's required entry-point function; `target` carries the base request template, `wordlists` are any lists loaded through the GUI (unused here since we load the pair list manually).
- `engine = RequestEngine(...)` — instantiates Turbo Intruder's request engine object, which handles actual socket-level request dispatch.
- `endpoint=target.endpoint` — sets the destination host/port from the request captured in Burp.
- `concurrentConnections=10` — number of simultaneous TCP connections held open; higher values increase throughput but risk tripping connection-count-based defenses rather than the auth logic you intend to test.
- `requestsPerConnection=100` — how many requests are sent per connection before it's recycled, using HTTP keep-alive to avoid the overhead of a new TCP/TLS handshake per request.
- `pipeline=False` — disables HTTP pipelining (sending multiple requests before reading responses); set `True` only against servers confirmed to handle pipelining correctly, since misuse can corrupt response parsing.
- `for pair in open(...)` — reads the credential pair list from disk line by line.
- `username, password = pair.strip().split(':')` — strips the newline and splits each `username:password` line on the colon delimiter.
- `engine.queue(target.req, [username, password])` — queues one request, substituting the two values into the positions marked with `%s` (or numbered markers) in the captured base request template.
- `def handleResponse(req, interesting):` — Turbo Intruder's required callback, invoked once per completed response.
- `if req.status != 401:` — filters for any response that did *not* return the expected "invalid credentials" status, i.e., a potential successful login.
- `table.add(req)` — adds matching requests to Turbo Intruder's results table for manual review, rather than flooding the output with every failed attempt.

### 4.4 Decision Summary

| Scenario | Tool |
|---|---|
| Small threshold-discovery batches (tens of requests) | Intruder (Community Edition) |
| Response-based enumeration on a modest username list | Intruder (Community Edition) |
| Credential stuffing, hundreds of pairs, no urgency | Intruder (Community Edition), accepting slower runtime |
| Credential stuffing, thousands of pairs | Turbo Intruder |
| Accurate rate-limit threshold testing at realistic attacker speed | Turbo Intruder |
| Race-condition-adjacent rate-limit bypass testing | Turbo Intruder (concurrency control required) |

---

## 5. PortSwigger and crAPI Lab Mapping

**PortSwigger (Authentication category, in official difficulty order):**
1. *Username enumeration via different responses* — directly maps to Section 2.3's response-based detection methodology.
2. *2FA broken logic* / *Username enumeration via subtly different responses* — reinforces response-differencing skills for more subtle signal differences.
3. *Broken brute-force protection, IP block* — maps directly to Section 2.4's rate-limit bypass testing via header manipulation.
4. *Username enumeration via response timing* — maps to the timing-based detection technique in Section 2.3.

**Honest gap disclosure:** PortSwigger's brute-force labs are built around a web login form UI, not a raw JSON API endpoint — the underlying logic transfers directly, but the labs don't exercise API-specific concerns like structured JSON error-field differencing, `X-RateLimit-*` header inspection, or credential-stuffing-specific Pitchfork-style pair testing at API scale.

**crAPI modules for this file's gaps:**
- crAPI's login and OTP-verification endpoints are useful for practicing response-based detection against genuine JSON API responses rather than an HTML form.
- crAPI does not include built-in rate limiting on several endpoints by design (as a teaching vulnerability), making it a practical target for confirming Turbo Intruder workflow setup even where threshold-finding itself isn't the point.

## 6. What's Next

File 04 covers authentication bypass techniques — removing auth headers, swapping token formats, HTTP method switching to reach unprotected paths, and the OWASP API2:2023-specific gap of missing re-authentication on sensitive account actions.
