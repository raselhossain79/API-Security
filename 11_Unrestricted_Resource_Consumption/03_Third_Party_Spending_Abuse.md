# API4:2023 — Third-Party Spending Abuse (Denial of Wallet)

This file covers the financial-impact category of Unrestricted Resource
Consumption: APIs that, on each call, trigger a **paid third-party service**
— SMS/OTP delivery, transactional email, payment processing/authorization,
push notification services, or cloud AI/ML inference APIs — with no
rate limiting on the triggering endpoint. Each triggered call has a direct,
measurable monetary cost to the target organization. This is commonly called
**Denial of Wallet (DoW)**, distinct from Denial of Service, because
availability may be completely unaffected while the target simply accrues
billing charges.

---

## 1. The Underlying Flaw

An API endpoint accepts a client-controlled trigger (e.g., "send OTP to this
phone number," "email this invoice," "process a $0.01 authorization to
verify this card") and forwards that trigger to a third-party provider
(Twilio, SendGrid, Stripe, AWS SNS, etc.) without:
- Enforcing a per-user or per-identifier rate limit on how often the trigger
  can be invoked
- Verifying the requester has a legitimate reason to trigger it repeatedly
  for the *same* target identifier (phone number, email, card)
- Capping aggregate cost exposure over time (daily/monthly spend ceiling per
  account or globally)

---

## 2. SMS/OTP Triggering Abuse

### 2.1 Example Request — Piece by Piece

```
POST /api/v1/auth/send-otp HTTP/1.1
Host: api.target.com
Content-Type: application/json

{
  "phone_number": "+14155550100"
}
```

Breakdown:
- `/auth/send-otp` — commonly an **unauthenticated** endpoint by necessity,
  since it's called before login (you need the OTP to log in). This means
  standard "check the user is who they say they are" access controls don't
  apply here at all — anyone can call this for any phone number.
- `"phone_number"` — fully attacker-controlled. The resource being exhausted
  is **the target's SMS gateway budget** — each call typically costs the
  target a small but real fee (commonly a few cents per SMS via providers
  like Twilio) charged to the target's provider account, not the attacker's.
- No CAPTCHA, no per-number cooldown, no per-IP limit: sending this request
  in a loop against the same number (or across a list of enumerated/valid
  numbers) directly converts into repeated billed SMS sends.

### 2.2 Why the API Has No Protection

- OTP/verification flows are frequently built with functional correctness as
  the only success criterion during development ("does the user receive an
  SMS and can they log in with the code") and cost/abuse scenarios aren't
  part of the QA checklist.
- Because the endpoint must work for unauthenticated users, the usual
  per-account rate limiting pattern (tied to a logged-in session/token)
  doesn't apply, and teams sometimes forget to substitute an equivalent
  per-phone-number or per-IP limit in its place.
- Some frameworks and third-party SDKs (Twilio Verify, AWS SNS) make the
  actual send call a single line of code, and it's easy to wire that
  directly to an HTTP endpoint without adding any surrounding throttle
  logic — the "hard part" (SMS delivery integration) got the engineering
  attention; the "easy part" (rate limiting) got skipped.

### 2.3 Proving Impact

- Send the request repeatedly (with appropriate authorization/scope for the
  engagement) against a phone number you control, and count actual SMS
  received to establish a real cost-per-request baseline you can cite (e.g.,
  "Twilio's published SMS pricing for this destination country is
  approximately $X per message; 100 requests in this test = approximately
  $X0 in charges to the target, with no functional limit observed").
- Demonstrate the request can be repeated indefinitely (e.g., 200+ times)
  with no lockout, no CAPTCHA challenge appearing, and no HTTP error — this
  proves there is no ceiling, not just a high one.
- Where in scope, demonstrate the same flaw works against **arbitrary**
  phone numbers, not just your own — this shows the impact extends to
  harassment (repeatedly SMS-bombing a third party's number using the
  target's own OTP system) in addition to pure financial cost.

### 2.4 Real-World Note

This exact flaw class is one of the most consistently paid bug bounty
categories in the "API misconfiguration" bucket, precisely because the
financial impact is trivial to quantify and hard for a triager to dismiss —
unlike a theoretical CPU-exhaustion argument, "here is exactly how much this
would cost you at scale" is concrete. However, many programs explicitly cap
how many times you're allowed to trigger this in testing (sometimes 5–10
requests) to avoid actually running up real charges — always check the
program's scope/rules of engagement before demonstrating this at volume.

---

## 3. Transactional Email Abuse

### 3.1 Example Request — Piece by Piece

```
POST /api/v1/invoices/{invoice_id}/resend HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

Breakdown:
- `{invoice_id}` — often an object the requester has legitimate access to
  resend (their own invoice), which is *why* this doesn't get flagged as a
  BOLA issue in isolation — the authorization check on "can this user access
  this invoice" may be entirely correct. The flaw is purely the **absence of
  a resend frequency cap**.
- The resource exhausted is the target's transactional email provider
  quota/cost (SendGrid, AWS SES, Mailgun — billed per email sent past free
  tiers) and, at high volume, potential damage to the target's sender
  reputation/domain deliverability if the pattern looks like spam to
  receiving mail servers.
- Repeating this call in a tight loop against the same invoice ID (or
  iterating across all invoice IDs a user owns) multiplies billed sends with
  zero functional benefit to the requester — there is no legitimate reason
  to resend the same invoice 500 times in a minute.

### 3.2 Why the API Has No Protection

Nearly identical root cause to the SMS case: the endpoint's authorization
logic was reviewed (does this user own this invoice?) but its *rate* was
not, because "resend my invoice" is conceptually framed by developers as an
occasional, user-initiated convenience action, not a security-relevant
action requiring throttling.

### 3.3 Proving Impact

Same methodology as SMS: establish a per-email cost from the provider's
published pricing, multiply by demonstrated achievable request rate, and
present a concrete cost-at-scale figure. Also check whether the "to" address
on the resend is itself attacker-controllable via a parameter (some
poorly-designed resend endpoints accept an override email address) — if so,
this becomes a spam-relay / harassment vector against arbitrary third-party
inboxes using the target's trusted sending domain, which is a materially
more severe finding than pure cost abuse.

---

## 4. Payment Processing Trigger Abuse

### 4.1 Example Request — Piece by Piece

```
POST /api/v1/payment-methods/verify HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "card_number": "4242424242424242",
  "exp_month": "12",
  "exp_year": "2027",
  "cvc": "123"
}
```

Breakdown:
- `/payment-methods/verify` — a common pattern where an API performs a
  small, real authorization hold (often $0.01–$1.00) against a card via a
  payment processor (Stripe, Braintree, Adyen) purely to confirm the card is
  valid before saving it, then voids the authorization.
- Each call to this endpoint triggers a **real request to the payment
  processor**, which typically bills the merchant (the target company) a
  small per-authorization-attempt fee regardless of whether the transaction
  is later voided — this is the resource being exhausted: **per-transaction
  processor fees**, and in some processor pricing models, elevated fees or
  account risk flags triggered by high failed-authorization volume.
- Repeating this call rapidly, especially with varying card numbers
  (potentially as part of a card-testing/carding pattern), can also trigger
  the payment processor's own fraud systems, which may result in the
  **target's merchant account** being flagged, rate-limited, or suspended by
  the processor — an availability impact stacked on top of the direct cost
  impact.

### 4.2 Why the API Has No Protection

- Card verification flows are frequently designed around the payment
  processor's SDK examples, which demonstrate the "happy path" integration
  without built-in application-level throttling — that responsibility is
  left to the integrating team, and is easy to overlook since the processor
  itself doesn't reject the *application's* excessive call volume, only
  flags patterns that look like card testing after the fact.
- Teams sometimes assume the payment processor's own fraud detection will
  "catch" abuse, without realizing the processor's fraud systems protect the
  *processor* and may simply suspend the merchant account rather than
  silently absorbing the abuse — the target still experiences real
  consequences.

### 4.3 Proving Impact — Handle With Care

**This category requires the most caution of anything in this file.**
Repeatedly triggering real payment authorizations, even small ones, against
a real payment processor can:
- Cause real, hard-to-reverse financial charges
- Trigger fraud/risk flags on the target's merchant account with
  consequences extending beyond the test (account review holds, processor
  relationship damage)
- In some jurisdictions and card network rules, generate telemetry that
  looks identical to actual card-testing fraud, which can have consequences
  for the tester if not explicitly authorized

For this specific sub-technique: **do not conduct live volume testing
without explicit, written, specific authorization covering payment
processing endpoints** — most bug bounty program scopes explicitly exclude
payment-endpoint volume testing for exactly this reason, or require
pre-coordination with the program owner before testing. In practice, the
correct approach for this category is frequently to demonstrate the
*absence of a rate limit* using detection methodology from file `01` (a
small number of requests, e.g., 3–5, to confirm no header/behavioral
enforcement exists) and then **stop and report**, describing the
extrapolated impact analytically rather than empirically proving it at
volume.

---

## 5. Cross-Reference: Enumeration-Enabled Spend Amplification

Third-party spend abuse compounds severely when combined with enumeration
(covered in depth via cross-reference below): if an attacker can enumerate a
list of valid phone numbers or email addresses first (e.g., via a
differently-vulnerable endpoint that confirms whether an identifier is
registered), then feed that entire list into an unthrottled OTP/email
trigger endpoint, the cost scales with the size of the target's entire user
base rather than being limited to numbers/addresses the attacker already
had. Always test whether user enumeration (see the **Broken Authentication
series**, and section on enumeration in `01_Detection_Methodology.md`
regarding rate-limit-enabled enumeration) is chainable with a spend-trigger
endpoint discovered here — this chaining is what turns a moderate finding
into a critical one in a report.

---

## 6. WAF / API Gateway Considerations Specific to Spend Abuse

### 6.1 Detection

- Some API gateways and dedicated fraud-prevention layers (e.g., providers
  offering OTP-abuse protection specifically) track **per-destination**
  triggering (same phone number/email targeted repeatedly across many
  source IPs or accounts), not just per-source volume — this is a more
  targeted detection than generic rate limiting, built specifically for this
  abuse pattern.
- Payment processors run their own independent fraud/velocity checks
  (distinct from the target's own API gateway) that can trigger merchant
  account holds — effectively a secondary, out-of-band enforcement layer
  the tester has no visibility into until after the fact.

### 6.2 Bypass Considerations

- Per-destination throttles can sometimes be evaded by varying the
  destination slightly where the provider's normalization is weak (e.g., an
  email endpoint that throttles per exact string match on the email address
  but the receiving mailbox provider treats `user+tag1@domain.com` and
  `user+tag2@domain.com` as the same inbox via plus-addressing) — this
  allows repeated triggering against what is functionally the same
  destination while appearing as distinct destinations to a naive
  per-string throttle.
- As with all bypass discussion in this series, generic infrastructure-level
  bypass (IP rotation, proxy chains) is covered in the **Rate Limit / Bot
  Protection Bypass series** and not repeated here — this section covers
  only bypass considerations unique to per-destination financial-trigger
  throttling.

### 6.3 Real-World Note

Because payment-processor-level fraud detection operates independently of
the target's own application security posture, a target can have a
completely absent application-layer rate limit and still be partially
protected by the processor's own systems — meaning testers sometimes
conclude "no impact" prematurely after only a handful of requests succeed
before the processor intervenes. Report the application-layer absence of
control as the finding regardless of whether an external system happens to
provide incidental protection — that external protection is not something
the target's own API implemented, and it may not exist for OTP/email
triggers routed through providers without built-in velocity checks.

---

## 7. crAPI Supplementary Practice

crAPI includes an OTP-based password reset / account verification flow that
models exactly this category (unthrottled OTP-triggering endpoint) in a
safe, self-contained lab environment where triggering the SMS/email-simulated
flow repeatedly has no real-world financial or reputational consequence.
This is the single most relevant supplementary practice environment for this
file, since PortSwigger Academy has no labs modeling third-party spend
abuse at all (Academy labs generally simulate all backend behavior
in-sandbox with no real external service integration, so there's no
"real money" concept to model). Treat crAPI's OTP challenge as your primary
hands-on practice ground for this entire file.

---

Proceed to `04_Burp_Turbo_Intruder_Resource_Testing.md` for the tooling
breakdown needed to execute the techniques in this file and the previous one
at the volume required to demonstrate impact.
