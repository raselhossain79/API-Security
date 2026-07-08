# API6:2023 — Turbo Intruder for Business Flow Automation Testing

Burp Intruder is adequate for basic volume checks but cannot realistically simulate the concurrency and timing precision needed to prove real business-flow abuse — Turbo Intruder, which runs as a Jython/Python script directly against a raw socket layer, is the correct tool. This file breaks down the scripts needed for each scenario category, flag by flag.

## 1. Turbo Intruder fundamentals recap

Turbo Intruder scripts define a `queueRequests(target, wordlists)` function (called once to enqueue all requests) and a `handleResponse(req, interesting)` function (called once per response received). The engine handles connection pooling and concurrency independently of your script logic, which is what makes it suitable for high-volume, precisely-timed testing that Intruder's architecture can't match.

Minimal skeleton:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=10,
                            requestsPerConnection=100,
                            pipeline=False)

    for i in range(50):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    table.add(req)
```

## 2. Flag-by-flag: `RequestEngine` configuration

- **`endpoint=target.endpoint`** — the host/port/TLS settings taken from the request you launched Turbo Intruder against. Leave as-is unless testing against a different host than the base request was captured from.
- **`concurrentConnections`** — the number of simultaneous TCP connections held open. This is the primary lever for simulating "many actors hitting the flow at once" (Scenario 1's parallel add-to-cart, Scenario 3's race-condition coupon redemption). For pure volume/rate-limit-threshold testing, moderate values (10–20) are enough. For genuine race-condition-style testing (Scenario 3's simultaneous single-use coupon redemption), this needs to be set so that all queued requests arrive at the server within the same processing window — see section 4 below for the single-packet variant.
- **`requestsPerConnection`** — how many requests are sent down each connection before it's closed and reopened. Higher values (50–100+) improve raw throughput for volume tests. For race-condition tests, this is typically irrelevant since `engine.queue` calls with the `gate` mechanism (section 4) control timing more precisely than connection reuse does.
- **`pipeline`** — whether requests are pipelined (sent back-to-back on the same connection without waiting for each response, HTTP/1.1 style) vs. sent request-response-request-response. `pipeline=False` is the correct default for most business-flow testing since most modern targets are HTTP/2 or don't support true pipelining reliably; leaving this `True` against a target that doesn't actually support it produces misleading results (responses arriving out of order or connections resetting), so verify target support before relying on pipelining for timing-sensitive tests.

## 3. Scenario-specific scripts

### 3.1 Rate limit / velocity threshold discovery (maps to file 3, section 2.1)

Goal: determine the exact count and time window at which throttling kicks in, and whether it's keyed on IP, session, or neither.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=5,
                            requestsPerConnection=1,
                            pipeline=False)

    # Fixed request, repeated — no payload variation needed,
    # this is purely a volume/timing probe against one endpoint.
    for i in range(200):
        engine.queue(target.req)

def handleResponse(req, interesting):
    # Log every response so the full sequence of status codes over
    # time is visible — the goal is finding *where* 200 turns to 429.
    table.add(req)
```

- `concurrentConnections=5` is intentionally modest here — the point of this run is measuring the server's *stated* limit behavior under a realistic single-actor burst, not maximizing raw throughput. Run it once at low concurrency, note where throttling starts, then re-run at higher concurrency to see if the threshold changes (a threshold that only appears at low concurrency but not high concurrency, or vice versa, tells you whether the limiter is connection-based or truly identity-based).
- To test whether the limit is IP-keyed vs. session-keyed, run this exact script twice: once reusing the same session cookie for all 200 requests, once cycling a list of pre-obtained valid session cookies (via a wordlist, see 3.2's payload pattern) while keeping the source IP constant (Turbo Intruder itself doesn't rotate IP — that requires an upstream proxy chain, which is a separate, environment-specific setup).

### 3.2 Coupon/gift-card code enumeration and reuse (maps to Scenario 3)

Goal: sweep a wordlist of candidate codes against the apply-coupon endpoint and flag which ones return a valid-application response.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=15,
                            requestsPerConnection=50,
                            pipeline=False)

    codes = wordlists[0]   # loaded from a file via the Turbo Intruder UI wordlist picker
    for code in codes:
        engine.queue(target.req, code)

def handleResponse(req, interesting):
    # Only surface responses whose body indicates successful application —
    # adjust the string match to the target's actual success message.
    if 'discountApplied' in req.response or '"success":true' in req.response:
        table.add(req)
```

- `target.req` here is the captured `POST /api/cart/apply-coupon` request with the coupon-code value in the body replaced by the Turbo Intruder placeholder `%s` before launching (select the value in the request editor and it auto-inserts the marker).
- `concurrentConnections=15` / `requestsPerConnection=50` balance throughput against not tripping a naive per-IP rate limit mid-sweep — tune down if 429s start appearing before the wordlist is exhausted, since a rate-limited response is a false negative for this test, not a true "code invalid" result.
- `handleResponse`'s filter is what makes a several-thousand-code sweep actually reviewable — without it, `table.add(req)` on every response leaves you manually scanning thousands of rows for the handful of real hits.

### 3.3 Single-use coupon race condition (maps to Scenario 3, race-condition variant)

Goal: fire the same single-use coupon-redemption request many times, all arriving at the server within the same check-then-act window, to determine if the "single-use" enforcement is atomic.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            requestsPerConnection=30,
                            pipeline=False,
                            engine=Engine.THREADED)

    # Gate all requests so none are actually released to the network
    # until every one of them is queued and ready — this is what
    # produces true near-simultaneous arrival rather than a fast loop.
    for i in range(30):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

- **`gate='race1'`** is the key flag for this entire script. Requests queued with a gate are held client-side, fully prepared, and only sent the instant `engine.openGate()` is called for that gate name — this is what makes Turbo Intruder specifically suited for race-condition-style testing where Burp Intruder's per-request-loop model introduces enough timing jitter to miss the vulnerable window.
- **`concurrentConnections=1`** paired with the gate mechanism is the "single-packet attack" pattern: all 30 requests are queued on connections that get released simultaneously, maximizing the chance they land inside the server's check-then-act race window together rather than being serialized by connection setup overhead. (Note this is a simplified single-connection variant; the full last-byte-sync single-packet technique typically pairs this gate approach with HTTP/2 multiplexing over one connection where the target supports it, sending all requests' headers early and releasing only the final byte of each simultaneously — covered in depth in this library's dedicated Race Conditions series.)
- After running, check whether the coupon was successfully applied **more than once** (multiple 200/success responses in the `handleResponse` table) — any count greater than 1 confirms the redemption isn't atomic.

### 3.4 Referral/account farming simulation (maps to Scenario 2)

Goal: script the full register → verify → apply-referral chain across many disposable identities, in an authorized test environment, to prove the per-identity limit doesn't meaningfully cap payout.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=8,
                            requestsPerConnection=10,
                            pipeline=False)

    emails = wordlists[0]  # e.g. testuser+001@yourdomain.test ... +200
    for email in emails:
        engine.queue(target.req, email)

def handleResponse(req, interesting):
    if req.response.status == 200 or req.response.status == 201:
        table.add(req)
```

- This script only covers the registration leg. In practice this scenario needs to be chained across three separate Turbo Intruder runs (register → verify, using values captured from each registration's response or a controlled mailbox → apply-referral), since each step depends on output from the previous one; Turbo Intruder does not natively chain multi-step dependent requests within a single `queueRequests` call in the way a general scripting language would, so each leg is run and its outputs harvested (via `handleResponse` logging to `table`, then exported) before constructing the wordlist for the next leg.
- `concurrentConnections=8` is deliberately conservative for this test — the goal is proving the *ceiling doesn't meaningfully exist*, not maximizing speed; a slower, clearly-attributable test run is also easier to justify and clean up afterward in a shared test environment.

### 3.5 Workflow step-skip fuzzing (maps to file 4)

Goal: automate sending the terminal step of a multi-step flow against many `cartId`/session combinations that only partially completed the sequence, to check consistency of enforcement rather than relying on one manual test.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=5,
                            requestsPerConnection=20,
                            pipeline=False)

    cart_ids = wordlists[0]  # a list of cartIds each stopped at a different step
    for cid in cart_ids:
        engine.queue(target.req, cid)

def handleResponse(req, interesting):
    if 'orderConfirmed' in req.response or '"status":"paid"' in req.response:
        table.add(req)
```

- This is less about raw concurrency and more about **coverage** — the wordlist here is a set of `cartId`s deliberately prepared beforehand (via the manual testing in file 4) to represent different points of incompletion in the flow, so this run is really a scripted regression check confirming the finding is consistent and not a one-off timing fluke.

## 4. General notes on responsible use of these scripts

All scripts above are written for use against systems the tester is explicitly authorized to test — an assigned bug bounty target's test/staging environment, a client engagement's designated scope, or a self-hosted lab like crAPI. Section 3.4 in particular (identity farming) should only ever be run against a controlled mailbox domain the tester owns and an environment where creating bulk test accounts has been explicitly cleared with the target, since even authorized testing of this pattern can trigger fraud-monitoring alerts or incur real operational cost to the target if run carelessly.

## 5. Turbo Intruder relevance to WAF/gateway bypass testing

Two Turbo Intruder features are directly useful when testing against a target with velocity-based bot detection (file 3, section 6):

- **Pacing requests deliberately below a suspected threshold** — insert `time.sleep()` calls or reduce `concurrentConnections` to simulate the "low and slow" bypass approach, then compare success/detection rate against a fast run, to empirically find where the target's velocity threshold actually sits.
- **Header/fingerprint variation per request** — since `engine.queue()` accepts a full request body/header set per call, header values (User-Agent, arbitrarily-ordered custom headers) can be varied per queued request from a wordlist to test whether the target's bot detection is defeated by superficial per-request variation or whether it's correlating on something deeper (TLS fingerprint, which Turbo Intruder does not let you control, since that requires a lower-level client than Burp's request engine).
