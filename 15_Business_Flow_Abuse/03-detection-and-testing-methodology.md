# API6:2023 — Detection and Testing Methodology

This file covers how to identify candidate business flows during recon, how to systematically test whether automation controls are actually present, and where to practice.

## 1. Recon phase: mapping business-critical flows

Before any automation testing, walk the API surface (Swagger/OpenAPI spec, Postman collection, or manually mapped via proxy history from using the app normally) and flag every endpoint that touches:

- Anything with a **quantity or stock** field (`/cart`, `/inventory`, `/reservations`, `/tickets`).
- Anything that **creates an identity** (`/register`, `/signup`, `/invite/accept`).
- Anything that **moves value** (`/coupons`, `/giftcards`, `/referrals`, `/wallet`, `/payouts`, `/rewards`).
- Anything that **advances a multi-step process** (checkout steps, KYC/verification steps, onboarding wizards).
- Anything that **aggregates opinion** (`/vote`, `/rating`, `/review`, `/like`).

For each flagged endpoint, record: is it authenticated or anonymous, what identifies the "actor" from the API's point of view (session cookie, JWT `sub`, API key, nothing), and what — if anything — currently limits repeat calls.

## 2. Probing for missing automation controls

For each candidate flow, run this checklist. This is the practical core of API6 testing.

### 2.1 Rate limiting presence and type

1. Send the same request 20–50 times in rapid succession (Burp Repeater's "send group in sequence" or a simple Turbo Intruder run, see file 5).
2. Record whether you get throttled (429, or a soft failure), and if so, at what count and what the reset window is.
3. **Critical distinction:** does the limit key on IP, on session/account, or on neither? Test by rotating only the session/account while keeping IP constant, and vice versa. Flat per-IP limits are trivially bypassed with a proxy pool; flat per-account limits are trivially bypassed by farming accounts (Scenario 2). A control that only checks one dimension is a control that only stops the laziest attacker.
4. Test whether the limit is a **hard count** ("max 100 requests/hour") or **behavioral/velocity-based** ("requests arriving faster than X per second, or in a pattern inconsistent with human timing, are flagged regardless of total count"). Hard counts are defeated by distributing load across many identities; velocity-based controls are harder to defeat because they look at the *shape* of the traffic, not just the total.

### 2.2 CAPTCHA / proof-of-work presence

1. Identify whether the sensitive step (checkout submit, registration submit, vote submit, coupon apply) requires a CAPTCHA/challenge token in the request body.
2. If present, test whether the **token is actually validated server-side** or just checked for presence/format. Submit the request with an empty string, a reused token from a prior solve, or a token copied from a different session. A shocking number of implementations only check "is this field non-empty" rather than round-tripping to the CAPTCHA provider's verification API.
3. Check whether the CAPTCHA gate is on *every* call in the flow or only the first-visible one (e.g., present on the web form's initial page load but the underlying `POST /api/checkout/complete` endpoint itself has no server-side check at all — meaning a script that skips the UI and calls the API directly never encounters it).

### 2.3 Step-sequence enforcement

Covered in full in file 4. As a detection-phase check: does the flow's final/sensitive endpoint (`confirm`, `complete`, `finalize`) verify a server-side state flag that can only have been set by successfully completing the prior step, or does it just check that a session/cart ID exists in some prior state?

### 2.4 Identity cost analysis

For flows gated behind "one per account" or "one per verified identity" (referrals, coupons, votes), determine the actual cost of creating a new qualifying identity:

- Is email verification required? Is it checkable via plus-addressing or disposable-email services?
- Is phone/SMS verification required? Is there a bypass (VOIP numbers, SMS-verification-bypass services, or a client-side-only check)?
- Is any KYC/document check involved, or is "verified" purely "responded to an automated challenge"?

If the cost of a new qualifying identity is near-zero, any "per identity" limit is not a meaningful control regardless of how strictly it's enforced.

### 2.5 Response differential analysis (for enumeration-class flows)

For login/register/reset endpoints specifically:

1. Send requests for a known-valid identifier and a known-invalid one.
2. Diff status code, response body (character-by-character, not just visually), response headers, and response timing (average over 20+ requests to smooth network jitter).
3. Any consistent difference is an enumeration oracle regardless of how "safe" each individual message looks.

## 3. Testing tools and workflow

- **Burp Proxy / Repeater** — manual walkthrough of the flow to map every request and understand the intended sequence and parameters.
- **Burp Intruder** — sufficient for basic volume/rate-limit probing at low-to-moderate concurrency and for coupon-code enumeration sweeps.
- **Turbo Intruder** — required for realistic scale/timing simulation of actual business-flow abuse (see file 5 for the full breakdown); Burp Intruder's connection handling isn't built for the high, precisely-timed concurrency needed to accurately test race-condition-adjacent scenarios like coupon double-redemption or inventory-hold abuse.
- **A disposable-identity harness** — for testing referral/coupon/voting flows honestly, you need a way to generate N test accounts through the app's real registration + verification flow (using a mailinator-style catch-all inbox you control, in an authorized test environment) to prove the "per-identity" limit doesn't actually stop scaled abuse.

## 4. PortSwigger Web Security Academy mapping

Stated once in file 1 and repeated here in full for reference: **PortSwigger's Business logic vulnerabilities labs teach the underlying reasoning about flawed process assumptions, but none of them are built around scripted, multi-request, automation-at-scale abuse of an API flow.** They are single-actor logic flaws. Work through them in this order for the conceptual foundation, with the gap noted explicitly for each tier.

| Order | Difficulty | Lab | What it teaches that transfers to API6 | Gap vs. real API6 |
|---|---|---|---|---|
| 1 | Apprentice | Excessive trust in client-side controls | Client-supplied values (price, quantity, flags) should never be trusted server-side — directly relevant to Scenario 5's `paymentVerified` flag manipulation | Single request, no automation/scale dimension |
| 2 | Apprentice | High-level logic vulnerability | Purchasing workflow can be manipulated via a parameter the app assumes is fixed (quantity) | Same as above — one session, one exploit, no volume |
| 3 | Apprentice | Low-level logic flaw | Requires using Intruder/Turbo Intruder to iterate a purchase parameter — closest lab to this series' tooling focus | Iteration here defeats input validation, not a business-scale/identity limit |
| 4 | Apprentice | Inconsistent handling of exceptional input | Unexpected input types breaking an assumed-safe workflow step | Not automation-related at all; useful for step-skipping mindset (file 4) only |
| 5 | Apprentice | Insufficient workflow validation | Directly relevant — sequence steps can be skipped or reordered because the server doesn't verify prior-step completion | This is the single closest PortSwigger lab to Scenario 5 / file 4's entire subject |
| 6 | Practitioner | Authentication bypass via flawed state machine | State machine reasoning — an endpoint trusts a state it shouldn't | Directly transfers to step-sequence enforcement testing (2.3 above) |
| 7 | Practitioner | Flawed enforcement of business rules | A business rule ("can't do X after Y") enforced client-side or inconsistently | Conceptually identical to "one coupon per order" / "one referral per identity" reasoning in Scenario 3/2 |
| 8 | Practitioner | Infinite money logic flaw | Combining multiple minor logic gaps into unbounded value extraction — same shape as coupon stacking (Scenario 3) | Single session again; real coupon stacking abuse also needs identity/velocity scale to matter at business level |
| 9 | Practitioner | Authentication bypass via encryption oracle | Technically a crypto/JWT-adjacent lab classed under business logic — limited direct relevance to API6 | Essentially unrelated to business-flow automation; included for completeness of the category, not recommended as priority |
| 10 | Expert | Weak isolation on dual-use endpoint | An endpoint doing double duty across trust boundaries — relevant lens for flows that serve both step 3 and step 4's purpose insecurely | No automation/volume component |
| 11 | Expert | Inconsistent security controls | Security control applied on one path but not an equivalent path to the same functionality — directly useful for finding the "UI has CAPTCHA, raw API doesn't" gap (2.2 above) | Still a single-session logic test, not a scale test |

**Priority order for this specific vulnerability class:** labs 5, 1, 2, 3, 7, 11 give the highest transfer value. Labs 4, 6, 8, 9, 10 are worth completing for well-roundedness but teach comparatively less that's specific to API6.

## 5. crAPI mapping — supplementary practice for the automation/scale dimension

Since PortSwigger has no lab that requires actual scripted, scaled abuse, **crAPI (Completely Ridiculous API)** is the supplementary target for that missing dimension:

- **Shop / coupon endpoints** (`/workshop/api/shop/apply_coupon`) — directly practice coupon brute-forcing and reuse-across-accounts, closing the gap Scenario 3 describes.
- **Community/forum endpoints** — practice enumeration and mass-content-manipulation patterns relevant to Scenario 6's voting/rating reasoning.
- **Mechanic/vehicle assignment flows** — practice sequence and step-trust issues relevant to file 4, with the advantage over PortSwigger's labs that crAPI is a full API (JSON request/response, no HTML form scaffolding), so scripting against it with Turbo Intruder is a closer rehearsal of real-world API6 testing than a PortSwigger lab's browser-driven flow.

Use PortSwigger for the conceptual foundation in the order above, then move to crAPI to actually script volume-based abuse against the coupon and account flows — that's the step PortSwigger's lab format cannot provide.

## 6. WAF / API Gateway detection and bypass considerations

As established in file 1, signature matching is not the relevant mental model here. What gateways and bot-management layers actually look for, and what's realistic to test against:

**Typical detection methods:**
- Velocity anomaly detection on a per-endpoint basis (this session/IP/device is calling this specific sensitive endpoint far more often than the population baseline).
- Device/browser fingerprinting (canvas fingerprint, TLS/JA3 fingerprint, header ordering) to correlate requests across rotated cookies/IPs that a naive script wouldn't think to vary.
- CAPTCHA/challenge injection triggered dynamically once velocity or fingerprint anomaly crosses a threshold, rather than being present on every request unconditionally (harder for an attacker to detect during initial recon, since low-volume manual testing never triggers it).
- Sequence/state enforcement at the gateway layer itself (some API gateways can be configured to reject a call to a "later" endpoint in a documented flow if the gateway's own session tracking never saw the "earlier" endpoint called first for that session) — this is a real, if less common, defense against file 4's step-skipping.

**Realistic bypass considerations (for authorized testing only):**
- Distributing load across a residential/mobile proxy pool defeats pure IP-based velocity checks but not fingerprint-based correlation.
- Randomizing TLS fingerprint, header order, and user-agent per request defeats naive fingerprinting but is defeated in turn by more advanced canvas/behavioral fingerprinting that operates client-side (harder for a headless script to fully spoof).
- "Low and slow" pacing — spreading the abuse across a much longer time window at a rate under the velocity threshold — trades speed for stealth and is often the most effective bypass against threshold-based detection, at the cost of the attack taking hours or days instead of minutes.
- Session/cookie churn combined with fingerprint randomization targets multi-factor correlation systems specifically; a gateway relying on any single signal in isolation is more exploitable than one that scores several signals together.

The practical implication for a tester: when a business flow is protected only by a rate limit and nothing else, that's a real, easily-demonstrated finding. When it's protected by a modern bot-management layer, demonstrating impact convincingly requires actually reasoning through which of the above signals the target layer is likely using and documenting which bypass techniques were and weren't effective — a flat "I sent 500 requests and it worked" report is far weaker evidence than one that shows the reasoning.
