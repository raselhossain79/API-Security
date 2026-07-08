# 5. Real-World Scenario Walkthroughs

## Prerequisite

This file combines techniques from Files 1-4 into complete attack narratives. Each
scenario states which prior file's technique applies and why, rather than repeating
the underlying mechanism explanation.

## 5.1 Double-spending via concurrent payment API calls

**Setup:** A merchant API exposes `POST /api/v1/payments/charge`, backed by a
microservice that (a) checks the customer's stored balance or credit line, (b)
performs the charge, (c) writes a ledger entry, across three separate internal
service calls with no shared distributed transaction (see File 1, section 1.2).

**Attack:**
1. Recon: identify the balance-check and charge logic are two separate internal
   services by observing distinct latency profiles or partial-failure error messages
   (e.g. a charge succeeding but a ledger-service timeout producing an inconsistent
   response) — a strong signal of a distributed check/use split.
2. Fire 15-20 parallel charge requests for an amount just under the account's actual
   balance, using either the single-packet attack (File 6) if the connection
   supports HTTP/2, or, if the check/use gap is wide (distributed microservice
   architecture typically makes it wide — File 1), ordinary parallel dispatch
   without special synchronization.
3. Verify by checking the account's post-attack balance/ledger against how many
   charge requests returned a success response. A ledger showing more successful
   charges than the starting balance should have permitted confirms double-spend.

**Why this works specifically because it's an API:** a monolithic web checkout would
likely wrap the check-and-charge in one database transaction. The microservice split
described in File 1 is what creates the exploitable gap, and it is a distinctly
API/microservice-architecture phenomenon rather than a classic single-process TOCTOU
bug.

**WAF/gateway note:** payment APIs are frequently the most heavily rate-limited
endpoints behind a gateway. Expect to need the "abusing rate or resource limits"
technique from the general Race Conditions series (deliberately triggering a
gateway-level throttle to introduce a uniform server-side delay that makes the
single-packet attack viable even with an initially-too-tight window) — this is
directly applicable here and worth attempting if a first attempt with 15-20
requests fails to produce a collision.

## 5.2 Coupon / discount code redemption races

**Setup:** `POST /api/v2/cart/apply-coupon { "code": "SAVE20" }`, intended to be
single-use per account.

**Attack (REST path):** classic limit-overrun race per the general series — fire
parallel requests to the same endpoint with the same coupon code. Standard single-
packet attack applies directly; this scenario requires no API-specific adaptation
beyond confirming the endpoint is bearer-token authenticated (File 1, section 1.1) so
there's no session-lock serialization to fight through.

**Attack (GraphQL path, if the store exposes a `redeemCoupon` mutation):** use
aliased batched mutations per File 3 instead of the single-packet attack — this is
the scenario File 3 specifically calls out as the most reliable batching target,
because coupon redemption is low-complexity and fits comfortably under most query
cost limits.

**Attack (batch endpoint path):** if the cart API accepts an array of coupon codes
in one request (File 1, section 1.3), first test with the same code repeated in a
single request before attempting any timing attack at all — this is the lowest-
effort test and should always be tried first.

**Impact quantification:** report the achievable discount stacking ratio (e.g. "20%
discount applied 8 times in a single race burst, reducing a $500 order to $0") rather
than just "coupon reused," since this maps directly to measurable financial loss.

## 5.3 Concurrent account balance modification (non-payment context)

**Setup:** a loyalty points API, in-game currency API, or internal credit system
where `POST /api/v1/points/redeem-reward { "reward_id": "r1" }` deducts points and
grants a reward, without a payment processor's typically stricter idempotency
controls (this is often a *less* mature endpoint than a payment API precisely because
it isn't treated as "financial" by the development team, despite having real value).

**Attack:** the multi-step chain pattern from File 2 frequently applies directly if
the reward system uses a reserve/confirm split (hold the reward, then finalize
redemption) — test both the direct limit-overrun race on `redeem-reward` itself
(File 2, sub-pattern A) and the reserve/confirm gap (File 2, sub-pattern B)
independently.

**Real-world note:** loyalty and gamification APIs are consistently under-defended
relative to payment APIs, because the engineering team's threat model frequently
excludes them from the "this needs idempotency keys and transactional guarantees"
bucket even though the currency has resale value to attackers (e.g. loyalty points
resold on secondary markets). Always test these as seriously as a payment endpoint.

## 5.4 Limited-resource claim races (ticket / inventory APIs)

**Setup:** `POST /api/v1/tickets/{event_id}/reserve { "seat_id": "A12", "quantity": 1 }`,
where a `quantity_available` field is checked and decremented, potentially across a
reserve/confirm split as described in File 2.

**Attack:**
1. Identify whether the reserve step alone decrements available inventory, or
   whether inventory is only decremented at confirm/purchase time (this determines
   whether you're racing the reserve endpoint directly or racing the reserve→confirm
   gap — test both independently, per File 2's sub-pattern distinction).
2. For single, low-inventory items (e.g. quantity_available = 1, a single remaining
   seat or a limited-edition item), fire parallel reserve requests — this is the
   highest-severity variant because a successful race directly translates into
   "multiple customers sold the same physical seat/item," a concrete, easily
   understood business impact.
3. For batch-purchase endpoints that accept a quantity or an array of seat IDs in
   one request (File 1, section 1.3), test whether the aggregate quantity check is
   enforced per-element — e.g. requesting quantity 1 five times in one array against
   a stock of 1.

**GraphQL variant:** ticketing and event platforms increasingly expose GraphQL APIs;
if a `reserveSeat` mutation exists, the aliased batching technique from File 3 is
usually the fastest way to test this, since it lets you attempt many reservations of
the same seat in a single request with clear per-alias success/failure visibility.

**WAF/gateway note:** ticketing platforms under high load (e.g. a popular on-sale
event) frequently have the most aggressive gateway-level rate limiting and queueing
of any scenario in this file, specifically because they expect and defend against
legitimate high-concurrency demand, not just malicious races. Expect connection
warming and rate-limit-abuse techniques (File 1, section 1.4, and the general Race
Conditions series) to be necessary more often here than in any other scenario in this
file.

## 5.5 Cross-scenario testing priority

When time-boxed during an engagement, prioritize in this order, based on typical
reliability and typical severity together:

1. Batch/array endpoint duplicate-element tests (File 1, section 1.3) — lowest
   effort, no timing tooling required, frequently exploitable.
2. GraphQL aliased batch tests on any mutation with single-use or limit-bound
   semantics (File 3) — no network timing tooling required, high reliability.
3. Idempotency key parallel-replay test (File 4, section 4.2) on any payment or
   financial endpoint — highest severity when found.
4. Multi-step chain race testing on reserve/confirm or check/use endpoint pairs
   (File 2) — moderate effort, frequently wide race windows due to microservice
   architecture (File 1, section 1.2).
5. Classic single-endpoint limit-overrun races requiring the single-packet attack
   (general series methodology, File 6 for API-specific Turbo Intruder configuration)
   — reserve for targets where the above haven't already surfaced a finding, since
   this requires the most precise timing and the narrowest windows.

## What's next

File 6 provides the full Turbo Intruder script breakdowns referenced throughout this
series, with API-specific configuration details (bearer token handling, idempotency
key control, gate-based batching) explained flag by flag.
