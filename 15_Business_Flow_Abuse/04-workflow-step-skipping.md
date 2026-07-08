# API6:2023 — Workflow Step Skipping Techniques

This file expands Scenario 5 from file 2 into full testing technique. Workflow step skipping is the sub-category of API6 where the abuse isn't volume/scale, but *sequence* — proving that a multi-step business process can be entered partway through or completed out of order.

## 1. Why multi-step flows are vulnerable by default

Most multi-step API flows are implemented as a set of independent endpoints that share a correlating identifier — a `cartId`, `sessionId`, `applicationId`, `orderId` — passed in the body, a header, or implied by the auth token. The natural (and flawed) implementation pattern is:

```
Step 1 (create cart)     → returns cartId
Step 2 (add address)     → takes cartId, writes address to cart record
Step 3 (add payment)     → takes cartId, writes payment method to cart record
Step 4 (verify payment)  → takes cartId, runs 3DS/fraud check, sets cart.paymentVerified = true
Step 5 (confirm order)   → takes cartId, checks... what, exactly?
```

The vulnerability lives entirely in what Step 5 actually checks. There are three implementations, only one of which is safe:

- **Unsafe — existence check only:** `confirm` checks that a cart with this `cartId` exists and belongs to the caller, then finalizes it. Any step can be skipped entirely.
- **Unsafe — client-trusted flag:** `confirm` checks `cart.paymentVerified === true`, but that flag was set from a value the *client sent* in an earlier request (`POST /step3 {"paymentVerified": true}`) rather than set only by the server after Step 4's verification actually succeeded.
- **Safe:** `confirm` checks a state field that only the server itself ever writes, and only writes after independently confirming with a trusted source (the payment processor's webhook/callback, not a client-supplied field) that verification occurred.

Testing step-skipping is entirely about distinguishing which of these three your target actually implements.

## 2. Step-by-step testing methodology

### 2.1 Map the full flow first

Walk the entire process legitimately once, capturing every request in Burp Proxy history. Note for each step:
- What identifier correlates the steps (`cartId`, session cookie, JWT claim).
- What each step's request body contains.
- What each step's response contains — specifically look for any field describing internal state (`status`, `stage`, `paymentVerified`, `nextStep`) since this often reveals the state machine's actual field names.

### 2.2 Test raw step omission

1. Start a fresh flow. Complete only Step 1 and Step 2.
2. Send Step 5 (`confirm`) directly, skipping Steps 3 and 4, using the `cartId` from Step 1.
3. Observe the response. A `400`/`409` referencing missing payment info is the expected safe behavior. A `200`/order-confirmed response is a full step-skip vulnerability — document the exact request and response.
4. Repeat, skipping only Step 4 (payment added in Step 3, but verification in Step 4 never called). This isolates whether verification specifically — as opposed to payment info generally — is enforced.

### 2.3 Test parameter-driven state manipulation

If raw omission fails (the server does reject a call to `confirm` without seeing prior steps), the next test is whether the *state itself* can be set by the client rather than earned through the real step:

1. Take the Step 3 (`add payment`) request in Repeater. Add or modify fields that look like internal state — `paymentVerified`, `verified`, `status`, `fraudCheckPassed`, `skipVerification`, `isTest`, `bypassFraudCheck`. Even fields not present in the original request are worth adding blind — some backends deserialize into a broader internal object and will happily accept and act on fields the frontend never sends but the backend model still defines.
2. Send Step 5 directly after this modified Step 3, still omitting Step 4 entirely.
3. If the order confirms, the backend is trusting a client-controllable field for a server-side-only decision — a critical finding, since it means payment verification can be unconditionally bypassed.

### 2.4 Test amount/value manipulation alongside step skipping

Combine sequence bypass with value tampering — this is where step-skipping becomes financially serious rather than just a logic curiosity:

1. In Step 3 or wherever the payable amount is set/echoed, modify `amount`, `total`, or `price` fields to a trivial value (`0.01`, `0`, or negative).
2. Proceed through (or skip to) `confirm`.
3. If the confirmed order reflects the tampered amount rather than a server-recalculated total based on the actual cart contents, that's a full payment-bypass finding — the order is fulfilled for a fraction of its real cost, or free.
4. Always test this in combination with skipping Step 4 specifically — many apps correctly recalculate total server-side at the *payment capture* step but not at the *confirm/fulfill* step, meaning capture and fulfillment can be decoupled by skipping straight to confirm.

### 2.5 Test step reordering, not just omission

Some flows are vulnerable to being called out of order rather than having steps dropped entirely:

1. Call Step 4 (verify) before Step 3 (add payment) — does verification run against an empty/default payment method and still set `paymentVerified = true`?
2. Call Step 2 (address) after Step 5 (confirm) on the same `cartId` — can a confirmed order still be mutated?
3. Replay an already-consumed `cartId` from a previous completed order against `confirm` again — is the cart/order marked terminal, or can `confirm` be called repeatedly (potentially re-triggering fulfillment/shipping without a second payment)?

### 2.6 Test cross-flow identifier reuse

If `cartId`/`applicationId` values are predictable or sequential, test whether Step 5 can be called using an ID that belongs to a *different user's* cart that has already passed Steps 1–4 legitimately — this crosses into BOLA/API1 territory but is common to find while step-skip testing, since both bugs stem from the same root cause: the confirm endpoint not properly binding the state check to the authenticated caller.

## 3. What "safe" looks like, for report-writing purposes

When documenting a finding, it's useful to state clearly what the correct behavior would be, since that's what the fix recommendation should describe:

- The state machine should be enforced entirely server-side: each step can only transition the record to the next valid state, previous states are not directly settable by client input, and the `confirm`/`complete` endpoint should independently re-verify (not just read a stored flag for) anything financially critical, such as re-querying the payment processor's own record of the transaction rather than trusting a locally stored boolean.
- Amount/total should always be server-recalculated from the authoritative cart contents at the final step, never read from a client-supplied or even a previously-stored-but-client-influenced field.
- Terminal states (`confirmed`, `shipped`, `cancelled`) should reject any further step calls against that same identifier.

## 4. PortSwigger and crAPI mapping for this specific technique

- **Insufficient workflow validation** (Apprentice) is the direct PortSwigger match for section 2.2 above — practice it first.
- **Excessive trust in client-side controls** and **High-level logic vulnerability** (both Apprentice) map to section 2.3/2.4 — client-trusted flags and amount tampering.
- **Authentication bypass via flawed state machine** (Practitioner) maps to section 2.5 — state reachable through an unintended order of calls.
- None of these PortSwigger labs involve a JSON API request/response cycle the way a real checkout API does — they're HTML-form-driven. For hands-on API-shaped practice of exactly this technique, use **crAPI's shop/order flow**, which has a genuine multi-step, JSON-based order and payment sequence suitable for scripting these tests with Repeater and Turbo Intruder directly against JSON bodies rather than form fields.

## 5. WAF / API Gateway relevance to step skipping specifically

Signature-based WAF rules have essentially no relevance here — there is no injected payload to match. The one gateway-level control that *is* directly relevant is **sequence/state enforcement at the gateway itself**, mentioned in file 3 section 6: some API gateway products can track, per session, which endpoints in a documented flow have been called, and reject calls to a "later" endpoint if an "earlier" required one was never seen for that session. Where this is present, testing it means determining whether the gateway's own session tracking can be reset or evaded (new session token acquisition mid-flow, replaying a session ID from a legitimately-completed flow against a different cart ID, or simply confirming the gateway tracks only presence-of-call rather than the actual step outcome — i.e., does it care that Step 4 was *called*, or that Step 4 *succeeded*). Where this gateway-level control is absent, step-skipping defenses rest entirely on the backend application's own state machine discipline, which is what sections 2.1–2.5 above are testing.
