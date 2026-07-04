# Third-Party Spending Abuse — Unrestricted Resource Consumption

**OWASP API Security Top 10 2023 — API4:2023**

This file covers the subclass of Unrestricted Resource Consumption where the exhausted
resource isn't the target's own server CPU/memory/disk, but a **paid third-party
service's quota**, invoked through the target's API with no cap. This is one of the
clearest cases where API4:2023 is a direct **financial** vulnerability, not just an
availability one — every exploit request in this file has a real, measurable dollar
cost to the victim organization.

---

## 1. The Mechanism

Many APIs integrate paid third-party services to fulfill a feature: sending an SMS OTP
via Twilio/Vonage/AWS SNS, sending a transactional email via SendGrid/Mailgun/SES,
processing a payment or refund check via Stripe/PayPal, performing a geocoding lookup
via Google Maps, or running an inference call against a paid AI API. Each of these
third-party calls costs the API owner money **per call**, billed by the third-party
provider regardless of whether the call was "legitimate" from the API owner's
perspective.

If the API endpoint that triggers one of these calls has **no rate limiting and no
per-user/per-resource cap**, any client who can reach that endpoint can trigger the
paid call an unlimited number of times — directly inflating the API owner's third-party
bill. This is sometimes informally called **"Denial of Wallet"** and is functionally a
billing attack disguised as a normal-looking API request.

**Why this is distinct from file 03's expensive computation abuse:** In file 03, the
exhausted resource is the target's *own* infrastructure (their CPU, their memory). Here,
the exhausted resource is money paid to an *external* vendor — the target's own servers
might barely notice the load (the actual work happens on the third party's infrastructure),
which means classic infrastructure-monitoring alerts (CPU spike, memory spike) may never
fire even while the attack is fully successful. This makes third-party spending abuse
a category that's easy for defenders to miss entirely if they're only watching server
resource metrics, not billing/API-usage metrics.

---

## 2. SMS API Abuse ("SMS Bombing" / SMS Cost Amplification)

### 2.1 Identifying the target endpoint

Common patterns: OTP-based login/registration, phone number verification, "resend code"
buttons, password reset via SMS.

```
POST /api/v1/auth/send-otp HTTP/1.1
Content-Type: application/json

{"phone_number":"+8801XXXXXXXXX"}
```

### 2.2 Baseline request

```bash
curl -s -X POST https://api.target.com/api/v1/auth/send-otp \
  -H "Content-Type: application/json" \
  -d '{"phone_number":"+8801XXXXXXXXX"}'
```

- Confirms the endpoint accepts a phone number and triggers an SMS — typically
  unauthenticated by design, since a user requesting an OTP hasn't logged in yet. This
  is important: **this endpoint is often reachable by anyone, with no authentication
  barrier at all**, which is precisely what makes it dangerous when unrestricted.

### 2.3 Exhaustion loop

```bash
for i in $(seq 1 200); do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    -X POST https://api.target.com/api/v1/auth/send-otp \
    -H "Content-Type: application/json" \
    -d '{"phone_number":"+8801XXXXXXXXX"}'
  sleep 0.2
done
```

Breakdown:

- `-d '{"phone_number":"+8801XXXXXXXXX"}'` — **always use your own test phone number in
  an authorized test, or a designated test number provided by the client/program.**
  Sending 200 unsolicited SMS messages to a real third party's phone number without
  authorization is harassment and almost certainly illegal — this is a hard ethical and
  legal boundary, not just a technical note. In a bug bounty context, most programs
  explicitly require using your own number and stopping after proving the vulnerability
  with a small number of requests (often 3-5), not running the full loop.
- `sleep 0.2` — a small delay between requests; this is not required for the attack to
  work but is often used during testing to avoid tripping a WAF's raw connection-rate
  trigger while still confirming the application-layer rate limit (the OTP-specific
  business logic limit) is absent.
- **What resource is exhausted and why:** Every successful call to this endpoint
  triggers a real, billed SMS send through the underlying provider (Twilio, Vonage, AWS
  SNS, or a regional aggregator). SMS pricing is per-message, commonly USD $0.005–$0.05+
  depending on destination country and provider — 200 messages to a single number in a
  proof-of-concept is already measurable; a real attacker running this unthrottled
  against many numbers, or repeatedly against one, can generate a meaningful bill in
  minutes. In some documented real-world cases, attackers specifically targeted
  **premium-rate or expensive-destination phone numbers** to maximize the per-message
  cost inflicted on the victim.
- **Why the API has no protection:** The OTP-send endpoint is functionally required to
  be reachable by unauthenticated users (you can't require login to request a login
  code), so the *only* available control is a rate limit scoped to the phone number
  and/or the requesting IP — e.g., "max 3 OTP sends per phone number per 10 minutes."
  When this specific business-logic limit is missing (even if generic API-gateway rate
  limiting exists elsewhere), the endpoint is fully exposed. This is a common oversight
  because generic rate limiting is often applied per-IP at the gateway level, while
  this endpoint specifically needs a *per-phone-number* limit, which requires
  application-layer logic the gateway can't provide on its own.

### 2.4 Confirming actual send vs. silent no-op (avoiding false positives)

Before running any volume beyond a handful of requests, confirm the endpoint is
genuinely triggering sends rather than silently rate-limiting server-side while still
returning `200 OK` (some APIs return a generic success response regardless, to avoid
leaking whether the number is registered):

- Use your own authorized test phone number and **count actual received SMS messages**
  against the number of requests sent. If 10 requests are sent and only 3 SMS messages
  arrive, a server-side limit likely already exists (~3 per window) even though the
  HTTP layer returned `200` for all 10 — report the *actual effective limit*, not the
  raw HTTP response pattern, since that's what genuinely matters here.

---

## 3. Email API Abuse

### 3.1 The mechanism

Identical structure to SMS abuse, but against transactional email endpoints —
registration confirmation emails, password reset emails, invoice/receipt emails,
notification emails. Email sending costs are typically lower per-message than SMS, but
providers like SendGrid, Mailgun, and AWS SES still bill per email past free tiers, and
more importantly, **unrestricted email triggering can be used to spam a third party's
inbox** (a harassment vector, separate from and in addition to the cost angle) or to
damage the sending domain's reputation (leading to the legitimate emails being flagged
as spam by mail providers — a serious operational consequence for the business beyond
raw dollar cost).

### 3.2 Exploitation request

```bash
curl -s -X POST https://api.target.com/api/v1/auth/resend-verification \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'
```

- **What resource is exhausted and why:** Each call triggers a billed transactional
  email send. Beyond direct cost, high-volume sends to a single recipient in a short
  window frequently trigger the *recipient's* mail provider (Gmail, Outlook) to flag
  the sending domain as spammy, which can degrade email deliverability for the target's
  **legitimate** transactional emails to all users — a second-order availability impact
  distinct from the direct financial one.
- **Why the API has no protection:** Same root cause as SMS — the endpoint is
  necessarily reachable pre-authentication (you need to resend a verification email to
  someone who isn't verified/logged-in yet), and the missing control is a per-recipient
  rate limit that requires application-layer awareness, not generic infrastructure-level
  throttling.

### 3.3 Responsible testing note

As with SMS testing (section 2.3), only test against your own authorized test email
addresses or ones explicitly designated by the test scope. Confirm the vulnerability
with a small number of requests (typically 3–5 is sufficient to prove absence of a
limit) rather than running large volumes against any real third party's inbox.

---

## 4. Payment API Trigger Abuse

### 4.1 The mechanism

Payment-adjacent endpoints don't need to process a full unauthorized charge to be a
resource-consumption problem — many payment processors **bill per API call**
regardless of outcome, for operations like:

- Card validation/tokenization calls
- Fraud-check / risk-scoring calls (many fraud detection APIs — e.g., providers used
  for card BIN lookups or address verification — charge per lookup)
- Payment intent creation (even if never completed/captured)
- Refund eligibility checks

If an endpoint that triggers one of these calls can be invoked repeatedly with no cap —
for example, a "check if this card is valid" endpoint hit on a checkout page — each
invocation costs the API owner money at the payment processor level, independent of
whether any money actually moves.

### 4.2 Example: card validation endpoint abuse

```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    -X POST https://api.target.com/api/v1/payment/validate-card \
    -H "Authorization: Bearer eyJhbGciOi..." \
    -H "Content-Type: application/json" \
    -d '{"card_number":"4242424242424242","exp_month":"12","exp_year":"2027","cvv":"123"}'
done
```

- `card_number":"4242424242424242"` — a well-known Stripe test-mode card number, used
  here strictly to illustrate the request shape in a documentation/lab context; **never
  submit real card data in a security test under any circumstances**, and always confirm
  the target environment is a designated test/sandbox environment before sending any
  payment-related request at all, not just before sending real card data.
- **What resource is exhausted and why:** Each call is billed by the payment processor
  or fraud-check provider (BIN lookup fees, fraud-score API fees, tokenization fees are
  all real, documented cost lines that payment processors charge merchants). Fifty calls
  in a proof-of-concept is a trivial cost; unrestricted, automated abuse of this endpoint
  at scale is a direct line item on the target's payment processor invoice.
- **Why the API has no protection:** Card validation is often treated by developers as
  a "cheap, side-effect-free check" rather than as an action with a real per-call cost —
  the endpoint gets built with normal functional correctness in mind (does it validate
  the card correctly) without anyone flagging that the underlying processor bills for
  it, so no rate limit gets added.

### 4.3 Reporting note for payment-adjacent findings

Payment API abuse findings should always specify: which specific downstream call is
being triggered (validation vs. charge vs. fraud-check), whether it's billed per-call
by the processor (confirm via the processor's public pricing documentation where
possible, e.g., Stripe's or a fraud-API vendor's published per-call pricing), and the
exact request count used in the proof-of-concept — payment-related findings are treated
with elevated sensitivity by most bug bounty programs and require precise, conservative
documentation.

---

## 5. Generalizing: Any Metered Third-Party Call

The same pattern applies to any API feature that wraps a metered external service:

| Feature | Third-party service commonly used | Billing unit |
|---|---|---|
| SMS OTP / notifications | Twilio, Vonage, AWS SNS | Per message |
| Transactional email | SendGrid, Mailgun, AWS SES | Per email (past free tier) |
| Address/geocoding lookup | Google Maps, Mapbox | Per API call |
| Payment/fraud checks | Stripe, PayPal, dedicated fraud APIs | Per call or per check |
| AI/LLM-powered features | OpenAI, Anthropic, or similar | Per token/per call |
| Identity verification (KYC) | Various KYC providers | Per verification attempt |

**General detection approach for any of these:** identify any endpoint whose backend
logic plausibly calls out to a paid external service, confirm the call actually fires
(not silently no-op'd) using a small number of authorized test requests, then test
whether a per-user/per-resource business-logic rate limit exists independent of any
generic infrastructure-level rate limiting — this application-layer gap is consistently
where these findings live.

---

## 6. Real-World Industry Framing

- **Documented pattern across bug bounty programs:** Unauthenticated or weakly-limited
  SMS OTP endpoints are one of the most consistently reported and paid API4-category
  findings on both HackerOne and Bugcrowd, often labeled "SMS bombing" or "lack of rate
  limiting leading to third-party API cost." Twilio, as an SMS API vendor, publishes its
  own customer-facing guidance specifically warning against building unrestricted
  OTP-trigger endpoints — evidence this is a well-known, recurring class of issue at the
  vendor level, not a hypothetical.
- **"Denial of Wallet" is now a named category** in cloud/serverless security discourse
  alongside classic Denial of Service, specifically because pay-per-use infrastructure
  and pay-per-call third-party APIs turned resource exhaustion into a direct financial
  attack with no need to actually crash anything — the service can stay fully
  operational while the bill grows unboundedly, which paradoxically makes it *less*
  likely to be caught by traditional uptime/availability monitoring.
- **Severity framing for reports:** these findings are usually rated based on (1) cost
  per call to the victim, (2) ease of automation/scale, and (3) whether the endpoint
  requires authentication (unauthenticated third-party-triggering endpoints are
  consistently rated higher, since the attack surface includes literally anyone, not
  just registered users).

---

## 7. PortSwigger and crAPI Coverage

**Honest gap disclosure:** PortSwigger Web Security Academy has **no labs** covering
third-party spending abuse in any form — this attack class is specific to real-world API
integrations with paid external services, which doesn't fit PortSwigger's
self-contained lab model (their labs don't make genuine calls to real, billed external
services, understandably). There is no PortSwigger lab to map here at all for this
category.

**crAPI** similarly does not have a purpose-built third-party-billing-abuse endpoint
(it doesn't integrate real paid SMS/email/payment providers by design, since it's a free
open-source training target). crAPI's OTP/coupon-validation flow (referenced in file 02
section 6) is the closest available hands-on analog — it demonstrates the *absence of
rate limiting on an OTP-adjacent endpoint*, which is the same underlying flaw, even
though crAPI doesn't wire that endpoint to a real billed SMS provider.

**Practical implication:** this category is best learned by (1) understanding the
mechanism and detection approach described in this file, (2) reading public bug bounty
disclosure writeups covering SMS/email cost-amplification findings (many are published
on platforms like HackerOne's public disclosure timeline for programs that allow it),
and (3) applying the detection methodology from file 02 directly against any live,
in-scope target during an authorized engagement, always respecting the request-volume
and authorized-recipient boundaries discussed in sections 2.3, 2.4, and 3.3 of this
file.

---

## 8. What to Carry Forward

File 05 consolidates every technique across files 02–04 into a single quick-reference
cheatsheet.
