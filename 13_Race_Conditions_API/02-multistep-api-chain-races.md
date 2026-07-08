# 2. Multi-Step API Chain Race Conditions

## Prerequisite

This builds directly on the "multi-endpoint race conditions" concept from the general
Race Conditions series — read that section first if you haven't. That series covers
the core idea (aligning race windows across two different endpoints) using a web
shopping-cart example. This file adapts the same concept to a pattern that is far
more common in API contexts specifically: a security-critical operation that is
deliberately split into a **check call** and a **use call**, as two entirely separate
API requests, often with no shared transaction between them.

## 2.1 The mechanism: why chained API calls create a wider race window

Consider a wallet API with two endpoints:

```
GET  /api/v1/wallet/balance
POST /api/v1/wallet/withdraw   { "amount": 500 }
```

A naive client-side flow calls `GET /balance`, checks whether the returned balance is
sufficient, and only then calls `POST /withdraw`. Critically, **the security check
here is often implemented entirely client-side**, or if implemented server-side
inside `POST /withdraw`, it may reference a balance value that was fetched and cached
moments earlier rather than re-read atomically at the moment of debit.

This differs from a single-request TOCTOU flaw in one important way: the race window
is not "however many milliseconds it takes one function to check-then-write inside
one process." It is **the full round-trip time of an entirely separate HTTP
request**, which is orders of magnitude larger. This has two consequences that matter
for exploitation:

1. You frequently do not need the single-packet attack or last-byte synchronization
   at all. Firing multiple `POST /withdraw` requests in ordinary parallel (e.g. a
   simple Python `asyncio.gather` or even several Burp Repeater tabs sent in parallel
   without special synchronization) is often sufficient, because the window is wide.
2. The vulnerability frequently isn't in the debit endpoint's internal processing at
   all — it's in the fact that the balance check happened in a **different request
   entirely**, with no shared lock, no shared transaction, and sometimes no re-
   validation of the balance at withdrawal time beyond a cached or stale value.

## 2.2 Two distinct sub-patterns to test for

### Sub-pattern A: client-trusted check, server-blind use

The check endpoint (`GET /balance`) is purely informational, and the withdraw
endpoint does its own server-side balance validation, but that validation reads and
writes the balance non-atomically (read balance → compute new balance → write new
balance, as three separate operations rather than one atomic decrement).

**How to test:** fire N parallel `POST /withdraw` requests, each requesting an amount
that is individually valid against the starting balance but which collectively
exceeds it (e.g. 10 requests of $500 against a $500 balance). If more than one
succeeds, the withdraw endpoint itself has an internal TOCTOU flaw — this is really a
single-endpoint race condition wearing an API costume, and the general series'
methodology applies directly. This is not the "true" multi-step chain race; it's
included here because it's the first thing to rule out before assuming a chain flaw.

### Sub-pattern B: genuine multi-call chain race

The check and the use are functionally coupled by business logic but not by any
shared lock or transaction — e.g. a "reserve funds" call followed by a separate
"confirm withdrawal" call, common in APIs that split operations into a pending state
and a confirmation state for UX or async processing reasons:

```
POST /api/v1/wallet/reserve   { "amount": 500 }   -> { "reservation_id": "r_123" }
POST /api/v1/wallet/confirm   { "reservation_id": "r_123" }
```

**How to test:** create multiple reservations in parallel against the same balance
before any of them are confirmed, then confirm all of them in parallel. If the
backend only checks available balance at `reserve` time and doesn't re-check at
`confirm` time (or checks it against a cached balance that hasn't yet reflected the
other reservations), you can confirm more reservations than the account can actually
cover. This is the pattern most true "check-balance then withdraw as separate API
requests" real-world races follow.

## 2.3 Practical methodology for API chain races

Adapting the general series' predict/probe/prove methodology specifically for
chained API calls:

**1. Predict potential collisions across the chain, not just within one endpoint.**
Map every multi-call sequence where a `GET` or a "reserve/lock" call precedes a
state-changing call. API documentation (OpenAPI/Swagger specs, if available) is the
fastest way to identify these sequences — look for endpoint pairs described as
"check X" and "commit X", or "create pending Y" and "finalize Y".

**2. Probe by decoupling the client-side ordering assumption.** The client SDK or
front-end almost always calls these endpoints in the "safe" order (check, then use).
Your job is to break that assumption by calling the "use" endpoint multiple times in
parallel, independent of how many times "check" was called, and independent of the
"expected" one-to-one call pattern the client enforces. Tools like Burp Repeater
(grouped tabs, parallel send) or a short async script both work — because the window
is wide, precision synchronization is less critical here than in single-endpoint
races.

**3. Prove impact by quantifying the overrun.** Don't stop at "I confirmed two
reservations that shouldn't both have succeeded" — determine the actual achievable
overrun ratio (e.g. how many parallel confirmations succeed against a single
reservation's worth of balance) to demonstrate severity, since this maps directly to
financial impact in a report.

## 2.4 Idempotency and chain races overlap — but are not the same thing

Chain races and idempotency key abuse (covered in File 4) often appear together in
the same endpoint (e.g. a `POST /withdraw` that accepts an idempotency key), but they
are conceptually distinct:

- A **chain race** exploits the gap *between two different logical calls*
  (reserve → confirm) that reference shared state.
- **Idempotency key abuse** exploits whether *repeated calls to the same logical
  operation*, using the same or manipulated idempotency keys, are correctly
  deduplicated.

Test them independently. A chain race can exist even on an endpoint with airtight
idempotency key enforcement, because idempotency protects against exact retries of
the same operation — it does nothing to protect the separate reserve/confirm
boundary unless the confirm step itself re-validates against current aggregate state.

## 2.5 WAF / API gateway relevance

This is highly relevant here, more so than for single-request races, because:

- **Gateway-level connection reuse across the chain** can actually help you: if your
  reserve and confirm calls, or your parallel confirm calls, are routed through a
  gateway that keeps a warm connection pool to the backend, your parallel requests
  may arrive with less jitter than raw client-to-backend connections would, making
  wide-window chain races even easier to win.
- **Per-endpoint rate limiting** at the gateway is a real obstacle here specifically
  because chain races often require many reserve calls in quick succession to build
  up enough pending reservations to matter. If the gateway throttles `POST /reserve`
  more aggressively than `POST /confirm` (common, since reserve is often seen as the
  "risky" write and confirm as a "housekeeping" call), you may need to spread
  reservation creation over a longer period while still confirming them all in a
  tight parallel burst — detect this by watching for `429` responses specifically on
  the reserve endpoint while confirm remains unthrottled.
- **Idempotency-key-aware API gateways** (some payment gateway products deduplicate
  at the gateway layer using a header like `Idempotency-Key`) can mask or interfere
  with chain race testing if your parallel confirm requests happen to reuse the same
  key by mistake. Always generate a unique idempotency key per logical confirm
  attempt unless you are deliberately testing idempotency key abuse (File 4).

## Real-world note

Reserve/confirm and check/withdraw splits are extremely common in payment
processors, ride-hailing fare authorization flows, and ticketing "hold" mechanisms
(hold a seat, then confirm purchase). The hold-then-confirm pattern in ticketing APIs
is one of the most consistently exploitable chain race patterns in practice, because
holds are cheap to create in bulk and confirmation logic frequently trusts the
existence of a hold record without re-validating remaining inventory at confirm time.
See File 5 for a full walkthrough of this scenario.

## What's next

File 3 covers how GraphQL's batched mutation syntax can collapse an entire chain of
what would be multiple sequential REST calls into a single HTTP request — which
removes network-timing challenges from the equation entirely and is often the more
reliable technique when the target exposes a GraphQL API.
