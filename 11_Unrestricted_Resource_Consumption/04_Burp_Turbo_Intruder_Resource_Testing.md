# API4:2023 — Burp Intruder and Turbo Intruder for Resource Testing

This file breaks down every relevant flag/configuration option for using
Burp Suite's built-in Intruder and the Turbo Intruder extension specifically
for resource-exhaustion testing (as opposed to their more common use for
brute-forcing credentials, which is covered in the Broken Authentication
series).

---

## 1. Why Standard Burp Intruder Is Often Insufficient Here

Standard Intruder is single-threaded-by-request-queue by design in most
Community Edition configurations and rate-limits its own send speed based on
the "Number of threads" setting — it is built primarily for accuracy and
control, not raw throughput. For many resource-exhaustion tests (needing
true concurrency, hundreds of requests/second, or precise timing control),
**Turbo Intruder** (a Burp extension, free, available via the BApp Store) is
the correct tool because it uses raw sockets and async I/O to achieve far
higher request rates than standard Intruder can produce. This file covers
both — standard Intruder for controlled/moderate tests and Turbo Intruder
for true throughput/concurrency tests.

---

## 2. Standard Burp Intruder — Configuration Breakdown

### 2.1 Attack Type Selection

Burp Intruder offers four attack types. For resource exhaustion:

- **Sniper**: iterates one payload set through a single position, one
  request at a time. Use this for the **pagination limit abuse** technique
  (file `02`, section 1) — you want to step `limit=` through increasing
  values (100 → 1,000 → 100,000 → 5,000,000) sequentially and record response
  time per step, not fire concurrently.
- **Battering Ram**: same payload inserted into multiple positions
  simultaneously per request. Rarely needed for this vulnerability class
  unless you need to inject the same expensive value into two parameters at
  once (e.g., testing whether both `limit` and a nested `page_size` field in
  a JSON body need to be large simultaneously to trigger cost).
- **Pitchfork**: iterates multiple payload sets in lockstep across multiple
  positions. Useful when testing the file-upload-size technique where you
  vary both `filename` and simulated size markers together in a templated
  request.
- **Cluster Bomb**: all combinations of multiple payload sets. Rarely
  needed here — this is more relevant to credential-stuffing enumeration
  (covered in the Broken Authentication series) than resource exhaustion.

For most of this file's use cases (single-parameter escalation), **Sniper**
is the default correct choice.

### 2.2 Payload Position Markers

In the request editor, wrap the position to be varied with `§` markers:

```
GET /api/v2/orders?limit=§100§&offset=0 HTTP/1.1
Host: api.target.com
```

Breakdown: only the value between the `§` pairs is substituted per attack
iteration — everything else in the request (headers, auth token, other
parameters) stays fixed, isolating the `limit` value as the single
independent variable so any timing change you observe can be attributed to
it specifically.

### 2.3 Payload Type: Numbers

Under the **Payloads** tab, set **Payload type** to `Numbers`:

- **Number range → From**: `100` (a safe/normal baseline value)
- **Number range → To**: `5000000` (the extreme value you want to test up
  to)
- **Step**: e.g., `10x` multiplier via a custom list, or a fixed numeric step
  like `50000` if using linear "From/To/Step" mode — a logarithmic-style
  custom list (`100, 1000, 10000, 100000, 1000000, 5000000`) is usually more
  informative than a linear step, since you want to see the *shape* of the
  time-vs-size curve (linear vs exponential vs plateau) across orders of
  magnitude, not fine-grained detail at one scale.
- **Number format**: `Decimal`, no unnecessary padding — set **Min integer
  digits** to `1` so smaller test values aren't zero-padded into invalid
  parameter values.

### 2.4 Resource Pool Configuration (Critical for This Use Case)

Under **Project options → Resource Pool** (or the attack-specific resource
pool selector in newer Burp versions), this is the single most important
setting for resource-exhaustion testing:

- **Maximum concurrent requests**: set explicitly (default is often shared
  with other Burp tooling). For testing whether an endpoint's cost is
  amplified by *concurrency* (relevant to the expensive-computation
  technique in file `02`, section 4), deliberately set this **higher** than
  default (e.g., 20–30 concurrent) to simulate a burst rather than Burp's
  polite default throttling.
- **Delay between requests**: set to `0` for burst/concurrency testing;
  set to a fixed value (e.g., `1000` ms) when you specifically want
  sequential, spaced-out requests for the Sniper-based escalating-payload-size
  test (section 2.3) where you want clean, isolated timing per request
  rather than overlapping/contending requests skewing your timing data.

### 2.5 Grep - Extract (Timing/Header Correlation)

Under **Settings → Grep - Extract**, add extraction rules for:
- The literal string `X-RateLimit-Remaining:` — this pulls the header value
  into a results-table column so you can watch it decrement (or fail to
  decrement to zero and block, per the detection methodology in file `01`)
  across every request in the attack, without manually opening each response.
- The literal string `Retry-After:` — same purpose, to catch the moment
  (if any) enforcement kicks in.

### 2.6 Reading Results

The Intruder results table's **Response received** and **Response completed**
columns (available via right-click → column configuration if not shown by
default) give you per-request timing in milliseconds. Sort by this column
after the attack completes to immediately identify which payload values
produced the largest timing outliers — this is your primary evidence for
report-writing (screenshot or export this table).

---

## 3. Turbo Intruder — Configuration and Script Breakdown

Turbo Intruder is installed via the BApp Store and invoked by right-clicking
a request → Extensions → Turbo Intruder → "Send to Turbo Intruder". It uses
a Python script (not a GUI form) to define attack behavior, giving far more
control over concurrency and timing than standard Intruder.

### 3.1 Base Script Template for Concurrency-Based Resource Testing

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        requestsPerConnection=1,
        pipeline=False
    )

    for i in range(50):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

**Piece-by-piece flag breakdown:**

- `RequestEngine(...)` — instantiates Turbo Intruder's core send engine,
  which uses raw sockets rather than routing through Burp's normal HTTP
  stack, which is what allows it to bypass standard Intruder's throughput
  ceiling.
- `endpoint=target.endpoint` — pulled automatically from the request you
  sent to Turbo Intruder; specifies the target host/port/TLS settings.
- `concurrentConnections=30` — **the most important parameter for resource
  exhaustion testing**. This sets how many TCP connections are open and
  sending simultaneously. For the expensive-computation-endpoint technique
  (file `02`, section 4), this value directly IS your "how many parallel
  expensive calls" test — set it to match the burst size you want to prove
  causes contention (e.g., 20–50).
- `requestsPerConnection=1` — controls whether each connection sends one
  request and closes, or reuses the connection (HTTP keep-alive) for
  multiple requests. Set to `1` when you want each request to be a fully
  independent new connection (more realistic simulation of many distinct
  clients/users hitting the endpoint simultaneously, rather than one client
  pipelining many requests down a single connection).
- `pipeline=False` — disables HTTP pipelining (sending multiple requests
  without waiting for each response before sending the next on the same
  connection). Keep this `False` for resource-exhaustion tests where you
  want to cleanly measure per-request response time; pipelining muddies
  timing attribution since responses can arrive out of order relative to
  when each request was actually sent.
- `for i in range(50): engine.queue(target.req)` — queues the **identical**
  request 50 times. Note there is no payload substitution here at all
  (unlike section 2's Sniper approach) — for the expensive-computation
  technique specifically, you are not varying a parameter, you are
  replaying the same legitimate maximum-scope request many times
  concurrently, which is the actual attack (see file `02`, section 4.2).
- `handleResponse(req, interesting): table.add(req)` — adds every response
  to Turbo Intruder's results table (viewable in its own tab), giving you
  per-request timing and status code for all 50 concurrent sends.

### 3.2 Script Variant for Escalating Payload Size (Pagination Abuse)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=1,
        pipeline=False
    )

    for limit_value in [100, 1000, 10000, 100000, 1000000, 5000000]:
        engine.queue(target.req, limit_value)

def handleResponse(req, interesting):
    table.add(req)
```

Breakdown of what differs from section 3.1:
- `concurrentConnections=1` — deliberately set to `1`, not high, because
  this script is testing **per-request cost at increasing size**, not
  concurrency contention. You want clean, sequential, non-overlapping
  timing per size step, matching the same rationale as the Sniper "Delay
  between requests" setting in section 2.4.
- `engine.queue(target.req, limit_value)` — the second argument to
  `.queue()` substitutes into the `%s` marker you place manually in the
  base request template before sending to Turbo Intruder, e.g.:
  `GET /api/v2/orders?limit=%s&offset=0 HTTP/1.1` — Turbo Intruder replaces
  `%s` with each `limit_value` in turn across the six queued requests.

### 3.3 Script Variant: Rate-Ramp Detection (Finding the Exact Threshold)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=100,
        pipeline=True
    )

    for i in range(500):
        engine.queue(target.req)

def handleResponse(req, interesting):
    if req.status != 200:
        table.add(req)
    elif interesting:
        table.add(req)
```

Breakdown:
- `requestsPerConnection=100` combined with `pipeline=True` — this is the
  configuration Turbo Intruder's documentation specifically recommends for
  maximum raw throughput (sending many requests down few connections,
  pipelined) — appropriate here because the goal of this script is purely
  "how many total requests can I get through before a `429`/block appears,"
  not clean per-request timing isolation (unlike section 3.2's goal).
- `if req.status != 200: table.add(req)` — a response filter: only add
  non-200 responses to the results table. Since you're firing 500 requests,
  you don't want to manually scroll through 500 rows — this immediately
  surfaces the exact request number where a `429`/`403` first appears
  (if ever), which is your precise rate-limit threshold finding, directly
  supporting the detection methodology in file `01`.

### 3.4 Choosing Between Standard Intruder and Turbo Intruder

| Scenario | Tool |
|---|---|
| Escalating a single parameter's value, sequential, need clean per-step timing | Standard Intruder (Sniper) or Turbo Intruder (low concurrency) |
| True concurrent burst to prove resource contention (expensive-computation abuse) | Turbo Intruder (high `concurrentConnections`) |
| Finding the exact request count where enforcement kicks in (rate-limit threshold mapping) | Turbo Intruder (`pipeline=True`, high `requestsPerConnection`) |
| Third-party spend trigger testing (SMS/email) | Standard Intruder, low count, manual review — **do not use high-concurrency Turbo Intruder scripts for real-money-triggering endpoints** without explicit authorization for the volume being sent (see file `03`, section 4.3 caution) |

---

## 4. WAF / Gateway Considerations When Using These Tools

### 4.1 Detection Signatures Specific to Automated Tooling

- Both tools produce highly uniform request timing/structure compared to
  organic traffic (identical headers in identical order, no natural
  human-driven variance in request spacing) — gateways with TLS/JA3
  fingerprinting or behavioral bot detection can flag this regardless of
  request volume alone.
- Turbo Intruder's raw-socket approach and connection-reuse patterns
  (`requestsPerConnection` > 1) can produce a distinctive connection-level
  fingerprint (e.g., unusual keep-alive request counts per TCP connection)
  that differs from typical browser or standard-client behavior.

### 4.2 Bypass Considerations

- Randomizing header order and injecting benign header variance between
  requests within a Turbo Intruder script (via the script's request-object
  manipulation before `.queue()`) can reduce uniformity-based fingerprinting
  — relevant specifically to tooling-fingerprint detection, not the
  generic IP-based bypass covered in the Rate Limit / Bot Protection Bypass
  series.
- As with prior files, broader evasion (IP rotation, proxy chains,
  distributed source infrastructure) is intentionally not repeated here —
  see the **Rate Limit / Bot Protection Bypass series** for that content.

### 4.3 Real-World Note

In authorized engagements, it's good practice to run an initial low-volume
manual test (5–10 requests via Repeater, not Intruder/Turbo Intruder at all)
before scaling up to confirm the endpoint behaves as expected and you have
the request format correct — running a 500-request Turbo Intruder script
against a malformed request template wastes time and, on a live production
target, can trigger unintended side effects (e.g., 500 duplicate report
generation jobs queued) before you've even confirmed the vulnerability
exists.

---

Proceed to `05_Final_Cheatsheet.md` for the condensed reference version of
this entire series.
