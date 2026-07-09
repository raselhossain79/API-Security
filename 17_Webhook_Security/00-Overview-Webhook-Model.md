# Webhook Security — 00: Overview and the Webhook Model

## 1. What a webhook actually is

A webhook is a **server-initiated HTTP request, sent automatically when an event occurs,
to a URL that was configured in advance.** That's the entire concept. Strip away the
marketing language ("real-time integrations," "event-driven automation") and a webhook is
just an outbound HTTP call the application makes to itself's — except "itself" here means
*whatever URL someone configured*, and the call is triggered by *something happening*
rather than by a user clicking a button.

Compare this to a normal API interaction, because the comparison is the whole point:

| | Normal API call | Webhook |
|---|---|---|
| Who initiates the HTTP request | The client (browser, app, script) | The server (the application itself) |
| What triggers it | A user action | An internal event (payment completed, user signed up, order shipped, build finished) |
| Who receives the request | The server | A URL configured by a user/customer/admin |
| Direction relative to the app | Inbound | Outbound |

This inversion is why webhooks need their own testing methodology instead of being folded
into generic API testing. Every vulnerability class in this series traces back to one of
two consequences of that inversion:

1. **The server makes outbound requests to a destination the attacker may control** →
   SSRF (file 01).
2. **The server accepts inbound requests that it must trust are genuinely from the
   originating service, carrying data it must trust is unmodified** → signature bypass,
   replay, payload tampering, endpoint enumeration (files 02–03).

Two different roles, two different attack surfaces, one feature name. Before testing
anything, identify **which side of the webhook you're attacking**: are you the one
registering the webhook URL (so the target's server calls out to *you*, or to wherever you
point it), or are you the one who can send requests *to* a webhook receiver endpoint
(pretending to be the legitimate sender)? Confusing these two roles is the single most
common way testers waste time on this topic.

## 2. Why webhooks exist

Without webhooks, if System B needs to know when something happens in System A, System B
has to **poll** — repeatedly ask "did it happen yet? did it happen yet?" This wastes
resources and introduces latency between the event and System B finding out about it.

Webhooks flip this to a push model: System A tells System B the moment something happens,
because System B registered a URL in advance and said "call this when X occurs." Common
real examples:

- A payment processor calls your server when a payment succeeds or fails (Stripe,
  PayPal, Omise).
- A CI/CD platform calls your server when a build finishes.
- A version control host calls your server when code is pushed (GitLab/GitHub webhooks).
- A messaging platform calls your server when an SMS or call is received (Twilio).
- A SaaS platform calls a customer's Slack/Zapier/custom endpoint when an event fires.

In every case, notice the same shape: **a registration step** (someone configures a
destination URL, sometimes with a shared secret) and **a delivery step** (the event fires,
the platform sends an HTTP request to that URL).

## 3. The registration flow, as raw HTTP

This is what registering a webhook typically looks like at the protocol level. A user
configures, through some UI or API, where events should be delivered:

```
POST /api/v1/account/webhooks HTTP/1.1
Host: app.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "url": "https://receiver.customer-domain.com/hooks/orders",
  "events": ["order.created", "order.shipped", "order.cancelled"],
  "secret": "whsec_8f3a2b1c9d4e5f6a"
}
```

Breaking down what matters in this request:

- **`url`** — this is the field this entire attack surface hinges on. Whatever value goes
  here is where the *application's own server* will later send requests, using the
  application's own network position, IP reputation, and (frequently) internal DNS
  resolution. If this field isn't restricted to public, non-internal, non-redirecting
  destinations, you have SSRF (file 01).
- **`events`** — an allow-list of event types the customer wants delivered. Relevant later
  because event-type manipulation on the receiving side (file 03) depends on whether the
  receiver trusts the event type as declared in the payload rather than independently
  verifying it.
- **`secret`** — a value used to compute a signature over each delivered payload so the
  receiver can verify the request really came from the platform and wasn't forged or
  altered in transit. This is the foundation of file 02.
- **`Authorization`** — note this authenticates the *registration* request (proving you're
  allowed to configure a webhook on this account). It has nothing to do with authenticating
  the *delivery* requests that will be sent later — that's a completely separate trust
  relationship, secured (or not) by the signature mechanism above.

## 4. The delivery flow, as raw HTTP

When `order.created` fires, the platform's server sends a request *to* the registered URL:

```
POST /hooks/orders HTTP/1.1
Host: receiver.customer-domain.com
Content-Type: application/json
User-Agent: Example-Platform-Webhooks/1.0
X-Webhook-Signature: sha256=7f9c8a3e1b6d4f2a0c5e8b1d3f6a9c2e...
X-Webhook-Timestamp: 1751980800
X-Webhook-Id: evt_3f8a9b2c

{
  "event": "order.created",
  "data": {
    "order_id": "ord_9f8e7d6c",
    "amount": 4999,
    "currency": "USD",
    "customer_id": "cus_1a2b3c4d"
  }
}
```

Breaking down the response side:

- **`X-Webhook-Signature`** — an HMAC computed by the platform over the request body (and
  often the timestamp) using the shared secret from registration. The receiver is supposed
  to recompute this and compare it before trusting the payload. If it doesn't, or compares
  it insecurely, that's file 02.
- **`X-Webhook-Timestamp`** — meant to let the receiver reject requests that are too old,
  which is the primary defense against replaying a captured request later. Its *absence*,
  or the receiver's failure to check it, is also file 02.
- **`X-Webhook-Id`** — an event identifier, ideally used by the receiver to deduplicate —
  reject a second delivery carrying an ID already processed. This is the second, often
  stronger, defense against replay, and its absence is equally relevant to file 02.
- **The body itself (`data`)** — whatever fields are here are what actually drives business
  logic on the receiving end (crediting an account, marking an order paid, granting a role).
  If the receiver doesn't independently verify the business state these fields imply — e.g.
  actually asking the payment provider "did this order actually get paid $49.99?" rather
  than trusting the number in the payload — that's file 03.
- **The receiving endpoint itself (`/hooks/orders`)** — if this endpoint has no
  authentication at all beyond "hope nobody guesses the URL," and no signature check either,
  anyone who finds it can POST directly to it. That's the endpoint enumeration half of
  file 03.

## 5. The trust model, spelled out

Every webhook vulnerability is a broken trust assumption. Here's the full map:

| Trust assumption | Who's supposed to enforce it | What breaks when it's missing |
|---|---|---|
| "The registered URL points somewhere safe to call" | The platform, at registration time | SSRF (file 01) |
| "This delivery really came from the platform" | The receiver, via signature check | Forged requests (file 02) |
| "This delivery hasn't been seen/processed before" | The receiver, via timestamp/nonce/ID check | Replay attacks (file 02) |
| "The data in this payload reflects true business state" | The receiver, by treating the payload as a *notification* and verifying independently, not as ground truth | Payload tampering (file 03) |
| "Only the legitimate sender knows where to POST" | Security by obscurity is not a control — but many implementations rely on it anyway | Endpoint enumeration (file 03) |

Notice that four of these five assumptions are the **receiver's** responsibility. This is
the most important mental model shift in this whole series: **most webhook vulnerabilities
live on the receiving side, not the sending side.** SSRF (file 01) is the one exception,
where the vulnerable party is the platform doing the registering-and-calling. Everything
else in files 02–03 is about testing *your own, or a target's, webhook receiver endpoint*
for whether it correctly distrusts an inbound request until proven otherwise.

## 6. Why WAF / API Gateway relevance varies sharply across this series

This series treats WAF/API Gateway defenses per-file rather than assuming they matter
uniformly, because they genuinely don't:

- **File 01 (SSRF via registration)** — gateway-level defenses are highly relevant. Many
  API gateways and platforms implement URL allow-listing, DNS resolution checks, and
  redirect-following restrictions specifically to prevent this. This file has a full
  detection/bypass section.
- **File 02 (signature bypass, replay)** — WAF/gateway relevance is **structurally
  limited**, and this is stated explicitly rather than glossed over. A WAF inspects HTTP
  requests for known attack *patterns* (SQLi syntax, XSS payloads, path traversal
  sequences). A missing signature check, a non-constant-time comparison, or a missing
  timestamp/nonce check are not patterns in a request — they are the *absence* of correct
  logic in the receiver's own code. There is no request-level signature for "this
  application forgot to call `hmac.compare_digest()`." Where a gateway *can* help is
  incidentally: rate-limiting delivery endpoints slows down brute-forcing a weak shared
  secret, and some gateways offer built-in webhook-signature-verification middleware as a
  managed feature — but that's the platform doing the receiver's job correctly, not a WAF
  detecting an attack pattern. File 02 covers this distinction explicitly rather than
  including a bypass section that would otherwise be padding.
- **File 03 (payload tampering, endpoint enumeration)** — mixed. Endpoint enumeration
  (directory/path brute-forcing to find receiver URLs) is a classic pattern WAFs do detect
  (high-volume 404-generating requests, known wordlist signatures) — so that half gets a
  real detection/bypass discussion. Payload tampering (changing `amount` or `event_type` in
  a JSON body that's otherwise well-formed and correctly signed-or-not) produces a request
  that is syntactically indistinguishable from a legitimate one — there's no field a WAF can
  flag as "this JSON key's value looks malicious" without understanding your business logic,
  which is outside a generic WAF's scope. File 03 states this plainly for that subsection.

The pattern to notice: **WAF/gateway defenses are effective against attacks that have a
recognizable request-level signature. They are structurally ineffective against attacks that
are actually authorization or business-logic failures wearing a well-formed HTTP request.**
Most of this series falls into the second category, which is exactly why it's an
under-tested surface — it doesn't trip the defenses people assume are watching.

## 7. PortSwigger coverage — the honest picture

PortSwigger Web Security Academy has **no dedicated "Webhooks" topic category**. This is
stated here once, up front, rather than repeated apologetically in every file. What exists
instead:

- The **SSRF** topic category (Apprentice → Practitioner → Expert) is directly applicable
  to file 01 — webhook URL registration is just one specific vector into generic SSRF, and
  every technique in that category (basic SSRF, blind SSRF, bypassing filters via
  obfuscation/DNS rebinding/open redirects) transfers directly.
- There is **no lab environment for HMAC webhook signature verification, replay protection,
  or webhook payload trust** anywhere in the Academy. This is a genuine, structural gap —
  not a case of not looking hard enough.
- Because of that gap, files 02 and 03 lean on **real, disclosed HackerOne reports** as the
  practical worked examples instead, each with an explanation of the underlying mechanism
  it demonstrates, not just a citation.
- crAPI (Completely Ridiculous API), already used as a supplementary practice target in the
  API series, has basic webhook-adjacent functionality in some versions and is worth
  standing up locally to get hands-on signature/replay practice that PortSwigger can't
  currently provide.

## 8. Real-world note

The clearest illustration of why the sending/receiving distinction in Section 5 matters
comes from Omise's payment platform (HackerOne report #508459, disclosed 2019). Omise
correctly blocked webhook URLs pointing directly at internal addresses — a registration-side
control. But their outbound HTTP client silently followed HTTP redirects, including a
`303 See Other`, and the *destination of the redirect* was never re-validated against the
same block list. A webhook URL could point to an attacker-controlled server that responded
with a 303 redirecting to `169.254.169.254` — AWS's instance metadata address — and the
platform's server followed it, retrieved AWS credentials, and delivered them straight back
to the attacker as the "webhook response." One correct control (block internal IPs at
registration) plus one missing control (don't blindly follow redirects) combined into a full
credential leak. This exact chain is the subject of file 01, Section 4.

## Next

Continue to `01-SSRF-via-Webhook-Registration.md` for the full step-by-step registration-side
attack.
