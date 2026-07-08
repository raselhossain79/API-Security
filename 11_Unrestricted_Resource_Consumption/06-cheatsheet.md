# API6:2023 — Unrestricted Access to Sensitive Business Flows: Cheatsheet

Quick-reference summary. See files 01–05 for full explanations.

## Core definition

Every individual request is authenticated, authorized, and valid. The vulnerability only appears in the **aggregate** — the same authorized action performed too many times, too fast, by too many farmed identities, or out of the intended sequence.

## Recognize a candidate flow

- [ ] Touches quantity/stock (cart, inventory, tickets, reservations)
- [ ] Creates an identity (register, invite-accept, guest-token)
- [ ] Moves value (coupon, gift card, referral, wallet, payout)
- [ ] Advances a multi-step process (checkout, KYC, onboarding)
- [ ] Aggregates opinion (vote, rating, review, like)

## Testing checklist

| Check | How | Vulnerable if |
|---|---|---|
| Rate limit presence | Send 20–50 requests fast (Repeater/Turbo Intruder) | No 429/throttle, or threshold trivially high |
| Rate limit key | Rotate session but not IP, then IP but not session | Limit only checks one dimension |
| Limit type | Compare hard-count vs. behavioral response | Only a flat count, no velocity/pattern analysis |
| CAPTCHA presence | Check sensitive endpoint's raw API call, not just the UI form | Token unchecked, absent, or reusable |
| CAPTCHA validation | Submit empty/reused/foreign token | Accepted anyway |
| Identity cost | Test plus-addressing / disposable email / VOIP SMS bypass | New qualifying identity costs near-zero |
| Step sequence | Call terminal step (`confirm`) after skipping intermediate steps | Order/action completes anyway |
| Client-trusted state | Add `verified`/`status`/`paymentVerified`-style fields to an earlier step's body | Terminal step trusts the injected flag |
| Amount tampering | Modify `amount`/`total` mid-flow, then confirm | Confirmed value reflects tampered figure, not server recalculation |
| Enumeration oracle | Diff response body/status/timing for valid vs. invalid identifiers | Any consistent difference |
| Coupon exclusivity | Apply two+ valid codes to one cart | Discounts stack past intended limit |
| Coupon atomicity | Fire single-use code as simultaneous gated Turbo Intruder requests | Redeemed more than once |

## Scenario → root cause quick map

| Scenario | Root cause |
|---|---|
| Ticket/inventory scalping | Per-request quantity cap enforced; per-identity/per-time cap is not |
| Referral farming | Uniqueness check validates format/reachability, not distinct humanity |
| Coupon/gift card stacking | Consumption checked per-account or non-atomically, not globally/atomically |
| Account enumeration | Differential response (message/timing/side-effect) leaks existence |
| Payment flow step-skip | Terminal step checks existence or a client-trusted flag, not a server-verified state transition |
| Voting/rating manipulation | Dedup keyed to cheap-to-fake identifier (token/account), not identity cost |

## Turbo Intruder quick reference

| Use case | Key config |
|---|---|
| Rate-limit threshold discovery | Low-moderate `concurrentConnections`, log every response, watch for 429 onset |
| Coupon/code enumeration | Wordlist-driven `queue()`, filter `handleResponse` to only success matches |
| Race condition / single-use bypass | `gate='name'` on every `queue()` call + `openGate()`, `concurrentConnections=1` |
| Identity farming simulation | Chain 3 separate runs (register → verify → apply), conservative concurrency |
| Step-skip regression check | Wordlist of pre-staged `cartId`s at different completion points |
| Bot-detection threshold probing | Add `time.sleep()` / reduce concurrency to find the "low and slow" line |

## WAF / API Gateway — one-line framing

Signature matching is irrelevant here (no malicious payload exists). What matters is **behavioral/velocity detection, device fingerprinting, dynamic CAPTCHA injection, and gateway-level sequence enforcement** — bypass testing means defeating those signals (proxy rotation, fingerprint randomization, low-and-slow pacing), not evading a regex.

## PortSwigger Business Logic labs — recommended order

1. Excessive trust in client-side controls *(Apprentice)*
2. High-level logic vulnerability *(Apprentice)*
3. Low-level logic flaw *(Apprentice)*
4. Insufficient workflow validation *(Apprentice — closest match to step-skipping)*
5. Inconsistent handling of exceptional input *(Apprentice)*
6. Authentication bypass via flawed state machine *(Practitioner)*
7. Flawed enforcement of business rules *(Practitioner)*
8. Infinite money logic flaw *(Practitioner)*
9. Authentication bypass via encryption oracle *(Practitioner — low relevance, included for completeness)*
10. Weak isolation on dual-use endpoint *(Expert)*
11. Inconsistent security controls *(Expert — useful for finding UI-only CAPTCHA gaps)*

**Honest gap:** none of these labs require scripted, scaled, multi-identity abuse — they're all single-actor logic flaws. Use **crAPI** (shop/coupon endpoints, community/forum endpoints, mechanic/vehicle flow) to practice the actual automation/scale dimension that defines real-world API6.

## Report-writing reminder

For every finding, state explicitly: (1) which business rule was violated, (2) why the API allowed it — i.e., which of the three conditions from file 1 section 2 was missing (automation-detection layer, identity-cost enforcement, or sequence validation), and (3) what the correct server-side control would look like, per file 4 section 3 for step-skip findings specifically.
