# API6:2023 — Unrestricted Access to Sensitive Business Flows

## 1. What this vulnerability actually is

API6:2023 is not a payload-based vulnerability. There is no injection string, no malformed token, no broken object reference. Every individual HTTP request involved in an API6 exploit is **fully authenticated, fully authorized, and syntactically correct**. The request passes every access control check the API has, because the user genuinely is allowed to do that one action.

The vulnerability exists in the *aggregate*. The API exposes a business process — buy a ticket, create an account, redeem a coupon, cast a vote — and that process has real-world value or a real-world constraint attached to it (limited stock, one coupon per person, one vote per person, a cost to the business per referral bonus paid out). The API enforces *who* can call the endpoint, but it does not enforce *how many times*, *how fast*, or *in what pattern* the endpoint can be called by a single actor. An attacker who can script or automate calls to that endpoint can consume the resource, drain the promotion, or distort the outcome at a scale no human using the UI ever could.

This is why API6 sits apart from access control (API1/API5) and injection categories. Access control asks "is this actor allowed to do this action." API6 asks "is this actor allowed to do this action ten thousand times in three minutes." The API's authorization logic answers the first question correctly every time and has no mechanism to answer the second.

## 2. The core mechanism: why the API allows it

Three conditions almost always have to be true simultaneously for API6 to be exploitable:

1. **The business flow is exposed as a discrete, callable API operation.** Ticket purchase, account signup, coupon redemption, and voting are naturally single-request or short-sequence operations. This is unavoidable — it is literally the API's job to expose them.
2. **The flow has a business-level constraint that lives outside the data model the API validates.** "Only 500 of these tickets exist" is a constraint on the world, not necessarily a constraint the checkout endpoint checks per request. "Each user gets one referral bonus" is a business rule; whether it is enforced depends on whether the backend ties the reward to something that is expensive to fake (a verified identity) or something that is cheap to fake (a new email address, a new session).
3. **The flow lacks a control designed specifically to detect and throttle automation.** This is the actual gap that API6 exploits. Standard input validation, standard authentication, and standard object-level authorization all pass. What is missing is a layer that asks "is this traffic pattern consistent with a human using the front end, or a script driving the API directly." That layer is usually one or more of: CAPTCHA/proof-of-work on the sensitive step, behavioral or velocity-based rate limiting (not just a flat requests-per-minute cap), device/session fingerprinting, and enforcement of the intended multi-step sequence so a flow cannot be replayed or parallelized out of order.

When all three conditions hold, an attacker's automation script becomes functionally indistinguishable, request by request, from a legitimate user — while operating at a volume and speed that breaks the underlying business assumption the flow was designed around.

## 3. Why this differs from rate limiting alone (API4) and from BOLA/BFLA (API1/API5)

These three categories are frequently confused, so the distinction is worth stating explicitly:

- **API4:2023 (Unrestricted Resource Consumption)** is about *infrastructure and cost* — CPU, memory, database load, third-party API billing, storage. The harm is resource exhaustion or financial cost to the API provider from expensive operations. A single actor sending oversized payloads or expensive queries repeatedly is an API4 issue even if no business rule is broken.
- **API1/API5 (BOLA/BFLA)** are about *authorization boundaries* — can actor A read or act on an object or function that belongs to actor B, or that requires a role actor A does not have. The harm is a single unauthorized action against a single object.
- **API6 (Unrestricted Access to Sensitive Business Flows)** is about *business-level abuse through legitimate, authorized, repeated access*. Every single request is authorized. The harm only appears when the same authorized action is performed at scale, out of sequence, or in a coordinated pattern that violates an assumption the business made about how the flow would be used. Inventory scalping, referral farming, and coupon stacking are not authorization failures — they are automation failures.

In practice these categories overlap in real applications (an under-rate-limited checkout endpoint is both an API4 and an API6 concern viewed from different angles), but the fix for API6 specifically is *flow-aware, identity-aware automation detection*, not just a request-per-second cap and not just an object ownership check.

## 4. What "sensitive business flow" means in practice

Not every API endpoint qualifies. A sensitive business flow is one where automation directly translates into real-world harm or real-world value extraction. Common categories used throughout this series:

- **Scarce resource acquisition** — limited-stock purchases, ticket sales, appointment slots, promotional item claims.
- **Financial incentive flows** — referral bonuses, sign-up credits, cashback, affiliate commissions.
- **Discount and value-transfer flows** — coupon codes, gift cards, loyalty points, promo stacking.
- **Identity and account creation flows** — free trials, account enumeration for credential stuffing prep, review/rating account farming.
- **Multi-step transactional flows** — checkout sequences where skipping a step (payment verification, fraud check, identity confirmation) has direct financial consequence.
- **Social proof / reputation flows** — voting, rating, review submission — where volume itself is the thing being manipulated.

Every scenario in file 2 of this series maps to one of these categories.

## 5. Why this is hard to catch with generic testing

Standard security testing tools look for a request that returns an unexpected result — a 200 where a 403 was expected, a payload that triggers an error, a token that should not decode. API6 produces none of these signals on a per-request basis. The 200 response is correct. The object returned is correct. The only signal is *volume and pattern over time*, which requires either scripted testing (Turbo Intruder, covered in file 5) or manual reasoning about the business model, not automated scanning. This is the same reason PortSwigger's own material treats business logic flaws as fundamentally a manual-testing, domain-knowledge problem rather than something a scanner reliably finds.

## 6. On WAF / API Gateway relevance for this specific vulnerability class

A dedicated WAF/API Gateway section is included in every file in this series per the standard convention, but the honest framing needs to be stated once, up front: **WAFs and API gateways are relevant to API6, but not in the same way they are relevant to injection-class vulnerabilities.**

For SQLi, XSS, SSTI, and similar categories, a WAF inspects the *content* of a single request and pattern-matches against known-malicious payload signatures. That model does not apply to API6, because no single request in an API6 attack is malicious — the payload is a normal, well-formed checkout request or signup request. A signature-based WAF has nothing to match against.

What *is* relevant, and what each file's WAF/Gateway section in this series covers, is the **behavioral and identity layer** that modern API gateways and bot-management products sit in front of business flows: velocity-based anomaly detection, device fingerprinting, CAPTCHA/proof-of-work challenge injection, session and IP reputation scoring, and enforcement of expected step sequencing at the gateway level rather than trusting the backend application alone. Bypassing these controls is a legitimate and well-documented testing consideration (residential proxy rotation, fingerprint randomization, distributed low-and-slow timing, session/cookie churn), and it is covered explicitly wherever it applies. The point being made here is simply that "WAF bypass" for API6 means bypassing *behavioral detection*, not evading a *signature match* — a meaningfully different testing mindset than the rest of this note library covers for injection-class vulnerabilities.

## 7. Series structure

| File | Contents |
|---|---|
| 01 | This file — concept, mechanism, terminology |
| 02 | Real-world scenarios, each broken down step by step |
| 03 | Detection and testing methodology |
| 04 | Workflow step skipping techniques |
| 05 | Turbo Intruder for business flow automation testing |
| 06 | Final cheatsheet |

## 8. PortSwigger and crAPI mapping — honest scope statement

This is stated once here and referenced from each subsequent file rather than repeated in full every time.

PortSwigger Web Security Academy's **Business logic vulnerabilities** topic is the closest match available and is mapped across this series in Apprentice → Practitioner → Expert order (see file 3 and file 6 for the full table). It is a genuinely useful training ground for the *reasoning* behind API6 — flawed assumptions about user behavior, trust in client-side state, multi-step process flaws — because that reasoning transfers directly.

However, it needs to be said plainly: **PortSwigger does not have a lab that specifically targets automated-scale abuse of a business flow via direct API calls.** Its business logic labs are single-actor, single-request logic flaws (e.g., manipulating a quantity or price field once). None of them require or reward scripting hundreds of concurrent requests against a scarce resource, which is the actual defining characteristic of API6 in production APIs. This gap is disclosed honestly rather than papered over — where a PortSwigger lab teaches the *underlying flaw category*, that is noted; where the *scale/automation* dimension has no PortSwigger equivalent, that is noted too, and **crAPI** is used to fill it, since crAPI's coupon, shop, and community/forum endpoints were built specifically to exercise unrestricted business flow abuse at the API layer.
