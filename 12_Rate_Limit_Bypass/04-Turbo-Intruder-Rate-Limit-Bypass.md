# Turbo Intruder for Rate Limit Bypass Attacks

## Why Turbo Intruder Instead of Burp Intruder

Standard Burp Intruder is thread-pool based and, even at maximum thread count, introduces enough per-request overhead (each thread manages its own full connection lifecycle) that it cannot reliably deliver the kind of high-concurrency, precisely-timed request bursts that several techniques in this series require:

- **Window-boundary timing (File 2, Section 1)** needs many requests to land within a sub-second burst window — Intruder's threading model can't guarantee this precision.
- **Turbo Intruder's core technique — the single-packet attack** — sends multiple HTTP requests within a single TCP packet (exploiting HTTP/1.1 pipelining or HTTP/2 multiplexing), landing them at the server almost simultaneously, which is what actually demonstrates true race-condition-class rate limit bypasses (as opposed to "just fast," which is what Intruder gives you).

Turbo Intruder is a Burp Suite extension that runs Python-like scripts directly, giving you full control over connection reuse, concurrency, and request construction — this is why it's the standard tool for both race conditions and rate-limit-bypass testing in the PortSwigger labs mapped in this series.

---

## 1. Base Script Structure

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    for letter in wordlists.iterate('rate_limit_bypass_payloads.txt'):
        engine.queue(target.req, letter)

def handleResponse(req, interesting):
    table.add(req)
```

This is the skeleton every Turbo Intruder script extends. Two functions are mandatory:

- `queueRequests(target, wordlists)` — builds the `RequestEngine` and queues every request you want sent
- `handleResponse(req, interesting)` — runs once per received response, used to log/filter results into Turbo Intruder's results table

---

## 2. `RequestEngine` Parameters, Broken Down

```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=1,
    requestsPerConnection=100,
    pipeline=False,
    engine=Engine.BURP2
)
```

| Parameter | Meaning | Why it matters for rate-limit bypass |
|---|---|---|
| `endpoint` | Target URL, taken from `target.endpoint` (the request's actual destination — Turbo Intruder resolves this from the base request loaded into the tool) | Always leave as `target.endpoint` unless deliberately redirecting to a different host (e.g. testing the origin-exposure scenario from File 1, Section 1.4) |
| `concurrentConnections` | Number of simultaneous TCP connections the engine opens | **Set to 1** for single-packet race-condition-style attacks (all requests must go down ONE connection to land near-simultaneously at the server). **Set higher (10-50)** for sustained-throughput rate-limit-bypass testing where you want many parallel streams rather than one burst |
| `requestsPerConnection` | How many requests are sent down each connection before it's closed and a new one opened | For single-packet attacks, this should match (or exceed) the number of requests you're bursting, since re-opening a connection mid-burst destroys the timing precision you're trying to achieve |
| `pipeline` | Whether to use HTTP/1.1 pipelining (`True`) to send multiple requests without waiting for each response before sending the next | **Set `True`** for the classic "last-byte sync" single-packet attack (Section 3). Leave `False` for standard sequential concurrent testing where the response IS needed before proceeding (e.g. checking for a rate-limit-reset confirmation before the next request) |
| `engine` | Which underlying connection engine to use: `Engine.THREADED`, `Engine.BURP2`, or `Engine.HTTP2` | `Engine.BURP2` is the standard default and works for HTTP/1.1 targets. **Use `Engine.HTTP2`** explicitly if the target negotiates HTTP/2 (common on modern APIs behind Cloudflare/CDNs) since HTTP/2's multiplexing changes how the single-packet technique needs to be constructed (see Section 4) |

---

## 3. The Single-Packet Attack (Last-Byte Synchronization)

### Mechanism

TCP allows a request to be split across multiple packets, with the server not processing it until the FINAL byte arrives completing the request. The single-packet attack technique (documented originally by PortSwigger's research team) exploits this: send the first N-1 bytes of MULTIPLE requests down the same connection, holding back the final few bytes of each, then release all the final bytes together in one packet. This forces the server to process all queued requests within microseconds of each other, eliminating the network jitter that would otherwise let a rate limiter or race-condition guard "catch" sequential requests one at a time.

### Full Script for Rate Limit Bypass via Single-Packet Attack

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=30,
        pipeline=False,
        engine=Engine.BURP2
    )

    # Queue 30 identical requests down a single connection
    for i in range(30):
        engine.queue(target.req, gate='race1')

    # Release all queued requests simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Breakdown of the parts unique to this pattern:**

- **`gate='race1'`** — this is the mechanism that implements the "hold back the final bytes" behavior. When a `gate` argument is passed to `engine.queue()`, Turbo Intruder constructs the request but does NOT send its final bytes yet — it holds all gated requests open, waiting.
- **`engine.openGate('race1')`** — this releases every request queued under that gate name simultaneously, in one synchronized burst. This is the line that actually triggers the single-packet effect — all 30 requests' final bytes are released together, forcing near-simultaneous server-side processing.
- **`requestsPerConnection=30`** — must be set to at least the number of gated requests, since Turbo Intruder needs to keep the single connection open long enough to hold and then release all 30 without closing/reopening it mid-sequence.
- **Why `pipeline=False` here specifically:** pipelining and gating are different techniques solving a similar problem — gating is the more precise, purpose-built mechanism for this exact attack, so pipelining is left off to avoid the two mechanisms interfering with each other's timing assumptions.

### Applying This to Rate Limit Bypass Specifically

The above script demonstrates the raw technique. For an actual rate-limit-bypass test (e.g. against a login endpoint with an account-lockout-after-5-attempts rule), the practical application is:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=10,
        pipeline=False,
        engine=Engine.BURP2
    )

    # Send 10 login attempts, all gated to fire simultaneously,
    # testing whether the lockout counter has a race condition
    # that allows more than the intended limit to succeed/register
    for password in wordlists.iterate('candidate_passwords.txt', limit=10):
        engine.queue(target.req, password, gate='login_race')

    engine.openGate('login_race')

def handleResponse(req, interesting):
    # Flag responses that indicate a successful login OR
    # an unexpected non-lockout response, both signal the race succeeded
    if 'Invalid username or password' not in req.response and req.status != 429:
        table.add(req)
```

**Why this demonstrates rate-limit bypass specifically:** if the lockout mechanism reads-then-writes the attempt counter (read current count, check against limit, increment, save) without atomic locking, multiple simultaneous requests can all read the counter BEFORE any of them have written their increment back — meaning all 10 requests see "0 failed attempts so far" and proceed, even though the limit was supposedly 5. This is the exact vulnerability class matched by the PortSwigger "Bypassing rate limits via race conditions" lab.

---

## 4. HTTP/2 Considerations

Modern APIs, especially those behind Cloudflare or other CDNs, frequently negotiate HTTP/2, which multiplexes multiple requests over a single TCP connection natively — this actually makes the single-packet attack EASIER to achieve in some ways (no need to manually hold back TCP-level bytes, since HTTP/2 streams are already independent within one connection), but requires setting `engine=Engine.HTTP2` explicitly, since Turbo Intruder's HTTP/1.1-oriented gating mechanism behaves differently under HTTP/2's frame-based multiplexing.

```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=1,
    engine=Engine.HTTP2
)
```

**Practical note:** confirm the target's negotiated protocol (check the "Protocol" column in Burp's HTTP history, or look for `h2` in the ALPN negotiation) before choosing the engine type — using `Engine.BURP2` (HTTP/1.1 assumptions) against an HTTP/2-only endpoint will produce unreliable timing results that don't reflect the true race window.

---

## 5. Concurrency Settings for Sustained Rate-Limit-Bypass (Non-Race Scenarios)

Not every rate-limit-bypass test is a microsecond race — Files 1 and 2's techniques (header rotation, account distribution, endpoint variation) often need SUSTAINED high-volume request testing rather than a single synchronized burst. For this use case:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,
        requestsPerConnection=1,
        engine=Engine.BURP2,
        maxRetriesPerRequest=0
    )

    for ip in wordlists.iterate('spoofed_ip_list.txt'):
        # Combine File 1's header spoofing with Turbo Intruder's concurrency
        engine.queue(target.req, ip, headers={'X-Forwarded-For': ip})

def handleResponse(req, interesting):
    table.add(req)
```

**Parameter reasoning for this scenario:**

- **`concurrentConnections=20`** — deliberately higher than the single-packet attack's value of 1, since here the goal is parallel throughput across many distinct spoofed identities, not synchronized simultaneity within one identity's request sequence.
- **`requestsPerConnection=1`** — each connection sends one request then closes; this mimics genuinely independent clients better than reusing connections, which matters if the target's infrastructure does any connection-level fingerprinting alongside IP-header inspection.
- **`maxRetriesPerRequest=0`** — disables Turbo Intruder's automatic retry-on-failure behavior, which is important here because a "failure" (429, connection reset) IS the data point you're measuring — you don't want the engine silently retrying and obscuring your actual rate-limit-triggering threshold.

---

## 6. WAF / Gateway Relevance for Turbo Intruder Usage

Relevance here is **operational rather than architectural** — Turbo Intruder itself has no WAF-evasion features built in, but the concurrency and header settings you choose directly determine how much of a bot-detection anomaly signature your traffic produces (per File 3):

- Extremely high `concurrentConnections` values (e.g. 100+) from a single source IP produce an obvious volumetric signature that basic rate-limiting WAF rules will catch regardless of whether your underlying application-layer bypass logic is sound.
- If combining Turbo Intruder with header rotation (File 1) for sustained testing, consider pairing it with the User-Agent rotation approach from File 3 — Turbo Intruder's `headers` parameter in `engine.queue()` can carry additional rotated headers alongside the spoofed IP, e.g. `headers={'X-Forwarded-For': ip, 'User-Agent': random.choice(ua_list)}`.
- For race-condition-style single-packet attacks specifically (Section 3), WAF/bot-detection relevance is LOW — the attack completes in microseconds against a single endpoint, well below the volumetric thresholds most bot-management products are tuned to detect, since it doesn't look like a sustained scraping/brute-force pattern at all.

---

## Real-World Notes

- The single-packet attack technique is sensitive to the tester's own network latency to the target — if you're testing from a location with significant round-trip latency to the target server, the "simultaneity" of the gated release can be undermined by jitter introduced before your packets even reach the server's network. Testing from a cloud VM in a region geographically close to the target infrastructure meaningfully improves reliability of this technique.
- A `requestsPerConnection` mismatch (set too low relative to the number of gated requests) is the most common script bug when adapting this technique — Turbo Intruder will silently open a new connection partway through, which defeats the entire point of the gate mechanism, and the resulting "race" will actually be sequential across two connections without any obvious error message telling you why it didn't work.
- Document your exact script (concurrency settings, gate usage, request count) in any report — race condition and rate-limit-bypass findings involving Turbo Intruder are frequently disputed by triage teams as "couldn't reproduce," and providing the literal script used is the standard way to resolve that dispute.
