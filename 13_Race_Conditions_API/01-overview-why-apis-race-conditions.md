# 1. Why APIs Are Especially Prone to Race Conditions

## Prerequisite

This file assumes you already understand the core race condition mechanism: TOCTOU
(time-of-check to time-of-use), the race window, sub-states, and the single-packet
attack technique for lining up parallel requests. That mechanism is covered in full in
the general **Race Conditions** series in the web application security notes. This
file does not repeat that explanation — it explains why the API surface makes those
same underlying flaws easier to find, easier to trigger, and often more severe.

Nothing about the *underlying* race condition mechanism changes when the target is an
API instead of a web form. What changes is: how much surface exists to attack, how
easy it is to line up parallel requests without browser overhead, and how many
distinct architectural layers can each introduce their own independent race window.

## 1.1 Stateless request handling

### The mechanism

REST and most modern APIs are designed around statelessness: each request is expected
to carry all the information the server needs (typically a bearer token or API key)
rather than relying on server-side session state tied to a cookie. This has a direct
consequence for race condition testing:

- In a cookie-based web app, session-based locking mechanisms (see the general Race
  Conditions series) sometimes serialize requests from the same session automatically
  — for example, PHP's native session handler locks the session file per request,
  meaning two requests using the same session cookie may be processed one at a time
  rather than in parallel, silently defeating your race attempt.
- A bearer-token or API-key authenticated request has no equivalent server-side lock
  by default. Each request is validated independently against the token and then
  handed to a request handler with no assumption that any other request from the same
  principal is currently in flight. This removes an entire class of "accidental"
  serialization that protects some session-based web apps.

**Practical implication:** when you migrate a race condition test from a cookie-
based flow to a token-based API flow, you should expect *fewer* silent defenses.
If a web endpoint resisted your race attempt because of session locking, do not
assume the equivalent API endpoint behind the same business logic will resist it too
— retest it as an independent target.

### Why this matters for detection

Because there is no session file to serialize on, identical requests authenticated
with the same static bearer token sent in parallel are handled by however many worker
threads/processes the backend has available — often much higher concurrency than a
session-locked equivalent. This means the "probe for clues" phase (see general Race
Conditions series) tends to surface collisions more reliably on API endpoints than on
their session-locked web counterparts.

## 1.2 Microservice architectures and distributed state

### The mechanism

A monolithic web app typically reads and writes to a single database inside a single
transaction boundary. A microservice-based API backend usually does not. A single
logical operation — "redeem this coupon", "withdraw from this account" — is commonly
split across:

- An API gateway or BFF (backend-for-frontend) that receives the request.
- A dedicated microservice that owns the business logic (e.g. a `payments-service`).
- One or more additional services it calls synchronously or asynchronously (a
  `ledger-service`, a `notification-service`, a `fraud-service`).
- A cache layer (Redis, Memcached) that may hold a denormalized copy of state used
  for fast reads, updated slightly out of sync with the source-of-truth database.

Each hop between these services is itself a potential race window, independent of the
TOCTOU window inside any single service. Two categories are worth distinguishing:

1. **Distributed check/use split** — the "check" (e.g. balance query) happens against
   one service or cache, and the "use" (e.g. debit) happens against another. If these
   are not wrapped in a distributed transaction or a single atomic operation against
   the same data store, the race window is the entire network round-trip between
   services, not a few milliseconds of in-process logic. This tends to make these race
   windows dramatically wider and easier to win than a single-process TOCTOU flaw.
2. **Eventual consistency windows** — services that communicate via message queues or
   event streams (Kafka, SQS, RabbitMQ) frequently have a gap between "the write was
   accepted" and "all downstream services have processed the resulting event". If a
   security check reads from a service that hasn't yet processed the relevant event,
   you get a race window that can be seconds wide rather than milliseconds — no
   single-packet attack precision required at all.

**Practical implication:** when testing an API for race conditions, map the request
against the underlying architecture where possible (response headers revealing
internal service names, error messages leaking stack traces from a specific service,
timing differences that suggest a network hop). A distributed check/use split often
does not need the single-packet attack — ordinary parallel requests with generous
timing, or even sequential requests spaced by tens or hundreds of milliseconds, can
win the race because the window itself is architecturally wide.

## 1.3 JSON batch and array operations create new race windows

### The mechanism

Traditional web forms submit one operation per request. APIs very commonly accept
arrays or batch objects in a single JSON body, e.g.:

```json
POST /api/v2/coupons/redeem
{
  "coupon_codes": ["SAVE10", "SAVE10", "SAVE10", "SAVE10", "SAVE10"]
}
```

or a batch withdrawal:

```json
POST /api/v2/wallet/batch-withdraw
{
  "withdrawals": [
    { "amount": 100 },
    { "amount": 100 },
    { "amount": 100 }
  ]
}
```

This is a race condition primitive that simply does not exist in a traditional
single-field web form, and it deserves to be treated as its own category, distinct
from both classic limit-overrun races and multi-endpoint races:

- If the backend validates the *aggregate* request once (e.g. "does the user have
  enough balance for the sum of these withdrawals") but then applies each array
  element in a loop that debits the balance individually without re-checking after
  each iteration, you can overrun the limit **within a single HTTP request**, with no
  network-level timing attack required at all. This sidesteps the entire single-
  packet-attack problem space, because there is only one request to send.
- If the backend validates and applies each array element independently but shares
  mutable state (e.g. a coupon "used" flag read at the start of the request and
  written at the end), the loop itself can be a self-contained race condition: each
  iteration reads a not-yet-updated flag before an earlier iteration in the same
  request has committed its write, particularly if iterations run concurrently
  internally (e.g. `Promise.all` in Node.js, parallel streams in Java) rather than
  strictly sequentially.

### Why this is genuinely new, not just "the same TOCTOU flaw with extra steps"

The general Race Conditions series' methodology (predict → probe → prove) assumes
you are trying to line up two or more *separate* requests. Batch/array race testing
inverts this: you are testing whether a *single* request's internal processing loop
is itself safe under its own concurrency, or whether validating once against
aggregate state and applying many times against individual state creates an internal
TOCTOU gap. The "probe for clues" step here is different in practice: instead of
comparing sequential-vs-parallel *request* timing, you compare a request with `N=1`
array elements against a request with `N=20` array elements and look for the limit
being enforced against the aggregate but not against each element.

**Practical implication:** whenever you find an endpoint that accepts an array or a
"batch" field, always test it with duplicate entries (the same coupon code repeated,
the same withdrawal amount repeated) even before you attempt any cross-request race.
This is a lower-effort, higher-reliability test than a network-timing attack and
should be step one whenever a batch-capable endpoint is discovered.

## 1.4 API gateway and WAF interaction

Most production APIs sit behind a gateway (Kong, Apigee, AWS API Gateway, Azure APIM)
or a WAF, and this has direct implications for race testing:

- **Rate limiting at the gateway layer** can introduce queuing delays that desynchronize
  your parallel requests before they ever reach the backend, defeating the single-
  packet attack even though the backend itself has no equivalent defense. Gateway-
  level rate limiting typically operates per API key or per client IP, over a sliding
  window (e.g. token bucket). If your race attempt is intermittently succeeding only
  on the first attempt of a burst and then reliably failing on the rest, suspect
  gateway-level throttling absorbing the timing precision of your subsequent requests,
  not a fixed application-level race defense.
- **Connection multiplexing / reused backend connections** at the gateway can
  sometimes *help* an attacker: if the gateway maintains a warm connection pool to the
  backend, requests may arrive at the backend with less network jitter than a direct
  connection would produce, effectively performing "connection warming" for you (see
  the general Race Conditions series for the connection warming concept).
- **Per-key or per-token concurrency limits** set at the gateway (some payment
  gateways cap concurrent in-flight requests per API key) can silently serialize your
  race attempt. If you suspect this, test with multiple valid API keys/tokens
  belonging to the same underlying account or resource, if your engagement scope and
  authorization permit doing so, to see whether the limit is per-key rather than
  per-resource.

Detecting gateway-induced delay: send a benchmark burst of otherwise harmless GET
requests to a non-state-changing endpoint under the same API key, and compare
response time variance to what you see on the target state-changing endpoint. A flat,
evenly-spaced response time pattern across many parallel requests, distinct from raw
network jitter, is a strong signal of gateway-level queuing rather than backend
processing delay.

## Real-world note

In practice, the highest-severity API race conditions found in bug bounty programs
are rarely the "textbook" single-endpoint TOCTOU flaw. They are almost always one of:
a distributed check/use split across microservices (1.2), or a batch/array endpoint
that validates once and applies many times (1.3). Both require zero specialized
timing tooling to exploit reliably — they are architectural races, not network races.
Prioritize hunting for these two patterns before reaching for Turbo Intruder.

## What's next

File 2 covers race windows that span multiple *sequential* API calls — the check-
balance/withdraw pattern — which is the multi-endpoint race condition concept from
the general series, adapted to the specific mechanics of chained API requests. File 3
covers GraphQL's unique ability to collapse many of these multi-step races into a
single HTTP request via aliased batched mutations.
