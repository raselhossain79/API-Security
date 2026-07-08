# 4. Idempotency Key Abuse

## Prerequisite

This assumes the core TOCTOU concept from the general Race Conditions series. This
file is API-specific because idempotency keys are an API design pattern with no
direct equivalent in traditional session-cookie web forms — they exist specifically
to make retried API calls (due to client timeouts, network failures, or mobile app
retry logic) safe, and testing whether that safety mechanism is implemented
correctly is itself a distinct race-condition testing discipline.

## 4.1 What an idempotency key is supposed to do

Payment APIs (Stripe, PayPal, and most in-house payment services model their API
this way) commonly accept a client-generated idempotency key, usually as a header:

```
POST /api/v1/payments/charge
Idempotency-Key: 8f14e45f-ceea-467e-a4f8-e6d3b6a3a9c1
{ "amount": 5000, "currency": "USD", "account_id": "acct_123" }
```

The intended guarantee: if the client sends the same request with the same
idempotency key more than once (e.g. because the client didn't receive a response
and retried), the server should recognize the duplicate and return the **result of
the original operation** rather than performing the charge again. Correct
implementation requires the server to:

1. Check whether the idempotency key has been seen before.
2. If not seen before, atomically mark it as "in progress" or "seen" *before or
   during* performing the operation.
3. Perform the operation exactly once.
4. Store the result, keyed by the idempotency key, for any future duplicate lookups.

Every one of these four steps is a potential TOCTOU sub-state, which is exactly why
this deserves its own race-condition testing methodology rather than being assumed
safe just because a key exists.

## 4.2 The core test: same idempotency key, sent in parallel

This is the single highest-value test in this file. Send N parallel requests
(typically 10-20 is enough) with:

- Identical request body.
- The exact same idempotency key value on every request.
- Sent using the single-packet attack or ordinary tight parallel dispatch (see File 6
  for Turbo Intruder configuration specific to this test).

**What a correct implementation does:** exactly one request performs the charge; all
others return the cached result of the first, with no additional side effect (no
additional charge, no additional email, no additional ledger entry).

**What a vulnerable implementation looks like:** more than one request results in an
actual charge. This happens when step 2 above (marking the key as seen) is not
atomic with respect to the charge operation — e.g. the server checks
`SELECT * FROM idempotency_keys WHERE key = ?` first, finds nothing, proceeds to
charge, and only inserts the idempotency key record into the tracking table *after*
the charge succeeds. Every request arriving inside that gap sees "no record found"
and proceeds independently. This is architecturally identical to the classic
limit-overrun TOCTOU pattern from the general series, just implemented specifically
as an anti-duplication mechanism rather than a balance check.

## 4.3 Secondary test: different idempotency keys, same underlying operation

A subtler defense gap: some implementations correctly deduplicate *identical*
idempotency keys but forget to apply any lock or check across *different* keys that
reference the same underlying resource or operation. Test this by sending parallel
requests that are otherwise identical (same amount, same account, same operation)
but each carrying a distinct, freshly generated idempotency key:

```
Request 1: Idempotency-Key: aaaa..., amount 5000
Request 2: Idempotency-Key: bbbb..., amount 5000
Request 3: Idempotency-Key: cccc..., amount 5000
```

If the underlying business logic (e.g. "this account may only be charged once for
this specific invoice") depends on some other identifier (an invoice ID, an order
ID) rather than the idempotency key itself, and that check has its own TOCTOU gap,
multiple distinct idempotency keys can each independently win the race against that
underlying check — the idempotency key mechanism is functioning exactly as designed
(each key is unique, so each is correctly treated as a new operation) while the
*business logic it wraps* still has a race condition. This distinction matters for
accurate reporting: don't describe this as "broken idempotency" — it's a TOCTOU flaw
in the underlying operation that idempotency keys don't protect against by design,
since they were never meant to prevent legitimately distinct operations.

## 4.4 Tertiary test: idempotency key reuse across different request bodies

Some implementations key their deduplication purely off the `Idempotency-Key` header
value and ignore whether the request body actually matches the original request that
key was first used for. Test by sending the same idempotency key with a *different*
amount or a different target account on the second request:

```
Request 1: Idempotency-Key: xxxx..., amount 100,  account acct_A
Request 2: Idempotency-Key: xxxx..., amount 9999, account acct_B
```

**Correct behavior:** the server should reject the second request outright (a
well-implemented idempotency layer stores a hash of the original request body
alongside the key and rejects mismatched replays with a 422/409-style error) or, at
minimum, still return the result of the original charge rather than processing the
new body. **Vulnerable behavior:** the server treats the key purely as a
deduplication lookup token and processes the mismatched body as if it were the
original request whenever it wins a race against a not-yet-committed prior use of
that key, or — with no race required at all — simply always accepts the new body
under a reused key. This second variant isn't strictly a race condition, but it's a
directly related idempotency-key logic flaw worth documenting alongside the race
findings, since it's discovered via the same testing pass.

## 4.5 Idempotency key format weaknesses that widen the attack surface

Beyond the race tests above, check whether the idempotency key itself is:

- **Client-supplied with no format validation** — if the server accepts arbitrary
  strings, you have full control to test key collisions deliberately, including
  extremely short or empty keys, which sometimes hit different code paths (e.g. an
  empty key might skip the deduplication logic entirely, effectively disabling
  idempotency protection outright — combine this with 4.2's parallel test using an
  empty or omitted key to check for this).
- **Predictable or sequential** — if keys are generated client-side by a mobile app
  using a weak scheme (e.g. timestamp-based), an attacker may be able to predict a
  legitimate user's idempotency key for a not-yet-completed operation and race their
  own request against it before the legitimate key is marked as used, though this
  crosses into a session-hijacking-adjacent scenario dependent on the specific
  application and is worth noting as a finding even without a full working exploit
  chain.

## 4.6 Turbo Intruder note

The single-packet attack is directly applicable to the core test (4.2) and works
identically to a standard limit-overrun race — the only API-specific detail is
ensuring your request template holds the `Idempotency-Key` header constant across
all queued requests rather than randomizing it per request (a common Turbo Intruder
template default is to vary a token per request; for this specific test you must
override that behavior). See File 6 for the full script breakdown, including this
exact configuration point.

## 4.7 WAF / API gateway relevance

- **Some API gateways implement idempotency-key deduplication themselves**, at the
  gateway layer, independent of the backend application (this is a built-in feature
  of some API management products). If a gateway is deduplicating before requests
  even reach the backend, your parallel requests may never reach the application
  layer at all beyond the first — you'll see identical cached responses returned
  directly by the gateway. Detect this by checking response headers for a gateway-
  specific cache/dedup indicator (varies by product, but look for anything like an
  `X-Idempotent-Replayed` or `X-Cache` header that the backend itself wouldn't emit),
  and by checking whether response latency on the "duplicate" responses is
  suspiciously close to zero (a gateway-level cache hit) versus the latency profile
  of an actual backend charge operation.
- **If gateway-level deduplication exists, it does not mean the backend's own
  deduplication logic is safe** — engagements should still test the backend
  directly if it's reachable independent of the gateway (e.g. via a different network
  path, or if gateway bypass is in scope), since relying entirely on gateway-level
  protection with no defense-in-depth at the application layer is itself a finding
  worth noting even if you can't demonstrate the backend flaw directly.
- If no gateway-level deduplication is present, this category of testing is
  unaffected by WAF/gateway behavior beyond the general rate-limiting and connection-
  warming considerations already covered in Files 1 and 2.

## Real-world note

Idempotency key race gaps are one of the highest-severity, most consistently
reportable findings in payment API testing, precisely because the mechanism exists
specifically to prevent duplicate charges — when it fails, the finding directly maps
to "attacker can duplicate a financial transaction," with no additional exploitation
chain required to demonstrate impact.

## What's next

File 5 walks through complete real-world scenarios that combine the techniques from
Files 1-4 — double-spending via payment APIs, coupon races, balance races, and
inventory claim races — as full attack narratives rather than isolated technique
descriptions.
