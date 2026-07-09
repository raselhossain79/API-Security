# Webhook Security — 03: Payload Tampering and Endpoint Enumeration

This file covers two related but distinct problems: what happens when the *content* of a
correctly-delivered (or forged) webhook event can be manipulated to change what action gets
taken, and how to find webhook receiver endpoints in the first place when they aren't
documented. Cross-reference the BOLA, BFLA, and Mass Assignment files in the API series —
payload tampering here is the same "server trusts a client-controlled field it shouldn't"
primitive, applied to a webhook event body instead of a normal API request body.

## 1. The mechanism: why payload tampering works even with a valid signature

File 02 covers proving a request came from the real sender and wasn't altered in transit.
This file covers a separate question that a signature check does not answer: **is the data
inside the payload actually true, independent of the fact that it's correctly formatted and
correctly signed?**

A signature proves *integrity* (nothing changed since signing) and *authenticity* (signed by
someone who knows the secret). It does not prove the *business claim* inside the payload is
still accurate at the moment it's acted on. Two separate failure modes fall out of this:

1. **The receiver trusts fields in the payload that should instead be independently verified
   against the source of truth** — e.g., trusting an `amount` field in a `payment.completed`
   event instead of calling the payment provider's API to confirm the actual charged amount.
   This is a design failure, not a signature failure — even a perfectly signed, perfectly
   fresh event can carry this problem if the *sender itself* allowed that field to be
   attacker-influenced upstream (e.g., a checkout flow where the client sets the amount and
   the payment provider only echoes it back), or if the receiver blindly trusts *any* signed
   sender's data as gospel for a high-stakes decision without a second, independent check.
2. **The receiver, when the signature check is missing or broken (file 02) or when it's
   testing its own permissive receiver as part of scoped testing, can be sent arbitrary
   payloads directly.** Then payload tampering is straightforward: craft any body you want.

In practice, most real-world payload tampering findings are a combination: a receiver
endpoint with weak or absent signature validation (file 02) *plus* business logic that
blindly trusts payload fields (this file) — the two failures compound into full impact.
Test both independently even when one appears solid, because the compound case is where the
real damage is.

## 2. Step-by-step: event type manipulation

Many receivers use a routing pattern where the same endpoint handles many event types,
dispatching based on an `event` or `type` field inside the body:

```json
{"event": "order.created", "data": {"order_id": "ord_123", "amount": 4999}}
```

**Step 1 — Enumerate the full set of event types the receiver might handle**, not just the
ones you've observed. Check API documentation, SDK source code, GraphQL introspection if
applicable, or JavaScript bundles for a full list of possible `event` values — receivers
often implement handlers for far more event types than you'll naturally trigger through
normal usage, including internal/administrative events never meant to be reachable this way
(`account.upgraded`, `refund.approved`, `user.role_changed`).

**Step 2 — Capture one legitimate, correctly-signed (or otherwise acceptable, per file 02's
findings) request, then change only the `event` field**, leaving everything else as
close to plausible as possible:

```json
{"event": "subscription.upgraded", "data": {"customer_id": "cus_1a2b3c4d", "plan": "enterprise"}}
```

**Step 3 — Observe whether the receiver processes the new event type as if it were genuine.**
If the receiver dispatches purely on this field without any correlation back to what
actually happened on the sending platform's side (e.g., without calling back to the
platform's own API to confirm "did `cus_1a2b3c4d` actually get upgraded"), this is a direct
privilege/state escalation: you've turned a `test.ping` event, or any event type you're able
to legitimately trigger and capture, into an arbitrary event of your choosing.

## 3. Step-by-step: amount/value field tampering

The most directly damaging and most commonly seen variant in disclosed reports (see Section
7) — payment, billing, and refund-adjacent fields:

**Step 1 — Capture a legitimate payment or order webhook.**

```json
{"event": "payment.completed", "data": {"order_id": "ord_9f8e", "amount": 4999, "currency": "USD", "status": "paid"}}
```

**Step 2 — Modify the amount, currency, or status field and resend**, testing each field
independently to isolate exactly which ones the receiver trusts blindly:

```json
{"event": "payment.completed", "data": {"order_id": "ord_9f8e", "amount": 1, "currency": "USD", "status": "paid"}}
```

**Step 3 — Check whether the receiver marks the order/account as fully paid based on this
field alone**, rather than querying the payment provider's own API for the *actual* charged
amount associated with that transaction/order ID. If it does, you've turned a $0.01 payment
webhook into full order fulfillment — the exact class of impact repeatedly seen in
disclosed price/amount tampering reports (Section 7), most of which occur in the direct
checkout request rather than a webhook specifically, but the underlying mechanism —
client-influenceable fields driving financial state without independent server-side
verification — is identical, and webhook receivers are exactly as susceptible when they
make the same mistake on the receiving end of an async event instead of the request/response
path of a checkout flow.

**Step 4 — Test negative and boundary values specifically**, since these frequently bypass
simple positive-number assumptions in downstream calculations: negative amounts,
zero, extremely large values (integer overflow), decimal precision tricks (fractional cents
that round favorably), and type confusion (`"amount": "4999"` string vs `4999` number,
`"amount": "4999.00.1"`, or `null`).

## 4. Step-by-step: privilege escalation via payload manipulation

The same mechanism applied to authorization-relevant fields instead of financial ones —
particularly dangerous in identity/SSO/user-lifecycle webhook receivers:

**Step 1 — Identify webhooks tied to identity or account state**: user creation, role
assignment, subscription tier changes, team membership, SSO provisioning (SCIM-adjacent
webhook flows), email verification status.

**Step 2 — Capture a legitimate low-privilege event** (e.g., a new free-tier user signing up
via an OAuth provider, delivered to the receiving app as a `user.created` webhook), and
identify every field that influences the account's resulting privilege level:

```json
{"event": "user.created", "data": {"email": "test@example.com", "role": "member", "plan": "free", "email_verified": true}}
```

**Step 3 — Escalate the relevant fields**: `"role": "admin"`, `"plan": "enterprise"`,
combined with an `email` you actually control so you can log in and confirm the resulting
account state. If the receiver provisions the account directly from these payload fields
without a second authoritative check (querying the identity provider's own API for the
user's actual assigned role, rather than trusting whatever the webhook body claims), this is
full unauthenticated privilege escalation for anyone who can reach the receiver endpoint at
all — which is exactly why this class compounds so severely with the missing-authentication
endpoint problem in Section 5.

## 5. Webhook endpoint enumeration

Everything above assumes you can reach the receiver endpoint. This section covers finding
it — and confirming whether it's protected at all — when it isn't documented or obviously
linked.

**Why unauthenticated receiver endpoints are common:** many webhook receivers are built
under the (flawed) assumption that "nobody will guess this URL," using it as an implicit
secret instead of implementing real signature validation (file 02) or authentication.
This is security-by-obscurity, and it fails as soon as the URL is discoverable by any of the
following.

**Discovery techniques:**

- **Directory/path brute-forcing** against likely webhook paths: `/webhook`, `/webhooks`,
  `/hook`, `/hooks`, `/callback`, `/callbacks`, `/notify`, `/api/webhook`,
  `/integrations/<vendor>/webhook`, `/<vendor-name>/callback` for every third-party
  integration the target is known or suspected to use (payment processor, CI/CD platform,
  messaging platform, CRM). Vendor-specific naming conventions are worth building into a
  custom wordlist — e.g., a target integrating Stripe often has a route literally containing
  `stripe`.
- **JavaScript bundle and API documentation review** for hardcoded receiver paths, especially
  in admin/developer-settings pages that display the webhook URL a customer is supposed to
  register on the third-party platform's side (which necessarily means the path is present
  client-side, in plaintext, for the customer to copy).
- **Third-party platform documentation and public integration guides** — if the target
  publishes "how to integrate with us" documentation for partners, it very often includes the
  literal webhook receiver path as a required setup step, handing you the endpoint directly.
- **Subdomain and path enumeration for dedicated webhook infrastructure** — some
  organizations run webhook receivers on a distinct subdomain (`hooks.example.com`,
  `webhooks-in.example.com`) separate from the main application, sometimes with weaker
  perimeter controls than the primary app because it's treated as "internal machine-to-
  machine traffic only."
- **Historical/archived endpoints** — deprecated webhook receivers from a since-migrated
  integration are frequently left running (nobody decommissions a working endpoint that
  "might still get traffic"), and often receive less security attention than the current,
  actively-maintained one.

**Confirming lack of authentication, once found:**

1. Send a plain `GET` and `POST` with no special headers, an empty or minimal JSON body, and
   observe the response — a generic `401`/`403` suggests some gate exists; a `200`,
   `400 malformed body`, or any response indicating the request was actually *processed*
   (rather than rejected before reaching handler logic) suggests no authentication gate at
   all.
2. If a signature header is expected (file 02), test all of the Section 2 techniques from
   file 02 against this specific endpoint before concluding it's genuinely unauthenticated —
   distinguish "no auth at all" from "auth exists but is broken," since they're reported and
   remediated differently even though testing steps overlap.
3. Once confirmed unauthenticated, this endpoint becomes the direct target for every
   technique in Sections 2–4 of this file, with no need to first defeat a signature check at
   all.

## 6. WAF / API Gateway relevance — mixed, split by sub-technique

Unlike file 02's clear-cut "structurally poor fit," this file has one half that's a
genuinely good WAF/gateway fit and one half that isn't — worth stating plainly rather than
giving a single blanket answer.

**Endpoint enumeration (Section 5) — real detection surface exists:**

- High-volume path brute-forcing against likely wordlists produces a recognizable pattern:
  a burst of requests from one source, high 404 rate, sequential/dictionary-shaped paths.
  Standard WAF/gateway rate-limiting and anomaly detection catches this the same way it
  catches any other directory brute-force, with no webhook-specific tuning required.
- **Realistic bypass considerations**: slow, low-and-slow enumeration below the detection
  threshold; distributing requests across many source IPs; randomizing request timing and
  order rather than sequential wordlist traversal; and — the technique most specific to this
  surface — enumerating via passive sources first (Section 5's JS-bundle/documentation
  review) rather than active brute-forcing at all, which generates no anomalous traffic
  pattern for a WAF to ever see, because you never sent a single guess-request to the target.

**Payload tampering (Sections 2–4) — poor fit, stated directly:**

- A tampered `amount` or `role` field inside an otherwise well-formed, correctly-typed JSON
  body is syntactically indistinguishable from a legitimate value. There is no generic
  signature a WAF can apply here — `"amount": 1` is not inherently more suspicious than
  `"amount": 4999`; both are valid integers in a valid field. Detecting this requires
  understanding the *business meaning* of the field and cross-referencing it against actual
  state elsewhere in the system, which is application-layer logic, not a network-edge
  pattern-match. This is the same reasoning given in file 02 for signature/replay attacks,
  applied here to business-logic fields instead of cryptographic ones — worth recognizing as
  the same underlying limitation showing up a third time across this series: **WAFs are
  built to catch malformed or malicious-looking syntax, not well-formed lies.**
- The one exception worth naming: some API gateways with schema-validation features (OpenAPI
  spec enforcement, JSON Schema validation at the gateway layer) can catch tampering that
  violates a *declared constraint* — e.g., a schema declaring `amount` as a positive integer
  with a maximum value would reject the boundary-value tests in Section 3, Step 4. This is
  real and worth testing for, but it's schema-conformance enforcement, not attack-pattern
  detection, and it only helps when the organization has actually declared and enforced tight
  schema constraints in the first place — loose schemas (`amount: number`, no bounds) provide
  no protection at all.

## 7. PortSwigger lab mapping and honest gap

**Gap stated directly:** as with file 02, PortSwigger has no dedicated webhook payload
trust or webhook enumeration labs. The relevant transferable category is
**Business Logic Vulnerabilities** (Apprentice → Practitioner → Expert), which covers the
exact underlying pattern — trusting client-controllable data for decisions that should be
independently verified — even though none of those labs are framed around webhooks
specifically:

1. **Apprentice** — *Excessive trust in client-side controls* — directly transferable
   mental model for Section 2 (trusting the `event` field) and Section 4 (trusting the
   `role` field).
2. **Apprentice** — *High-level logic vulnerability* — general practice in spotting where an
   application conflates "data present in a request" with "state that's actually true."
3. **Practitioner** — *Insufficient workflow validation* — closely maps to Section 3's amount
   tampering: an application that doesn't re-verify a financial claim against an authoritative
   source before acting on it.
4. **Practitioner** — *Authentication bypass via flawed state machine* — transferable to
   Section 5's endpoint-enumeration-then-direct-access pattern, where reaching a step out of
   its intended sequence (going straight to the receiver endpoint instead of through the
   legitimate sender) bypasses assumed preconditions.
5. **Expert** — *Excessive trust in client-side controls (advanced/chained)* — the closest
   analogue to the compounded case described in Section 1: a missing signature check (file
   02) combined with blind payload trust (this file), chained for full impact, mirrors how
   Expert-tier business logic labs typically require combining two separate weaknesses.

For directory/path enumeration technique practice specifically (Section 5), standard content
discovery methodology (already covered in the API Reconnaissance file in the API series)
applies unchanged — there's nothing webhook-specific about the enumeration mechanics
themselves, only about which wordlist entries are worth prioritizing.

## 8. Real-world notes

- **Zomato/Eternal, HackerOne #403783** — a checkout/payment flow allowed ordering food at a
  negligible price by tampering with fields controlled client-side during the payment
  process. While this specific report is a direct checkout-flow finding rather than a
  webhook, it's included here because it's the clearest illustration available of Section 3's
  exact mechanism (financial fields trusted without independent verification) — the same
  logic error is fully applicable wherever a webhook receiver trusts a payload's `amount` or
  `status` field the same way this checkout flow trusted client-supplied price data.
- **WordPress Mercantile, HackerOne #682344** — near-identical pattern: intercepting the
  checkout request and modifying the price field before it reached the payment gateway,
  allowing purchase at an arbitrary (including effectively zero) price. Again a direct
  request-tampering finding rather than a webhook specifically, but demonstrates the generic
  "modify the financial field, resend, observe no server-side re-verification" methodology
  that Section 3's steps are built from.
- **Rocket.Chat, HackerOne #1886954 (referenced in file 01)** — worth revisiting here too:
  an SSRF reachable *through* a webhook integration illustrates that receiver-side webhook
  endpoints are sometimes doing more than passively recording an event — they can trigger
  further server-side requests based on payload content, meaning payload tampering (this
  file) and SSRF (file 01) are not always cleanly separable in a single real target; test
  whether any payload field you control ends up being used in a subsequent outbound request
  the receiver makes.

## Next

Continue to `04-Webhook-Security-Cheatsheet.md` for a condensed, standalone reference.
