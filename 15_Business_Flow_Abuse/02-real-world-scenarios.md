# API6:2023 — Real-World Scenario Breakdown

Each scenario follows the same structure: the business assumption, the API surface involved, the exact step-by-step abuse, the business rule violated, and why the API allows it. This file assumes the concepts from `01-overview-and-concept.md`.

---

## Scenario 1: Ticket and inventory scalping

**Business assumption:** A human buys a limited number of tickets/units through the storefront, so demand naturally self-limits and stock reaches a broad set of real customers.

**API surface:** `GET /api/events/{id}/availability`, `POST /api/cart/add`, `POST /api/checkout/reserve`, `POST /api/checkout/pay`.

**Step-by-step abuse:**
1. Attacker scripts a poller against `GET /api/events/{id}/availability`, hitting it every 200–500ms from the moment tickets go on sale (or continuously beforehand to catch a release).
2. The instant `available > 0`, the script fires parallel `POST /api/cart/add` requests, each using a fresh authenticated session (see Scenario 4 for how those sessions are farmed cheaply) or fresh guest-checkout tokens if the flow allows unauthenticated carts.
3. Each `POST /api/cart/add` request is individually valid — correct event ID, correct quantity within the per-request limit (e.g., "max 4 per order"), correct auth token. The API has no way to know that 200 of these "max 4 per order" requests came from the same operator.
4. Each session proceeds independently through `POST /api/checkout/reserve` and `POST /api/checkout/pay`, using either stolen/prepaid card numbers or a small number of real cards run through many sessions.
5. Reserved inventory is decremented per successful reservation call. Because reservation and payment are asynchronous in many systems, the script also often exploits the reservation-hold window itself — reserving far more stock than it intends to pay for, letting the holds lapse, and re-reserving repeatedly to keep real buyers locked out during the sale window (a denial-of-inventory pattern even without completing purchase).
6. Purchased tickets are resold at markup outside the platform.

**Business rule violated:** "Fair access — a limited number of units per person, released to the broad public." The per-request quantity cap (4 per order) is enforced correctly every single time; the *per-person, per-identity* cap across many orders is not, because the API validates the request, not the requester's history across sessions.

**Why the API allows it:** Object-level and quantity validation happens per request and is stateless with respect to the requester's broader behavior. There is no velocity control tying "distinct sessions/accounts hitting checkout for the same event within a short window" back to a single operator, and no CAPTCHA/proof-of-work gate in front of the add-to-cart or reserve step that would slow down scripted concurrency.

---

## Scenario 2: Referral reward farming

**Business assumption:** A referral bonus (cash, credit, or discount) is paid per genuinely new user brought in by an existing user, so the marketing spend converts to real customer acquisition.

**API surface:** `POST /api/auth/register`, `POST /api/referrals/apply`, `GET /api/wallet/balance`.

**Step-by-step abuse:**
1. Attacker obtains a large pool of disposable identities. This is typically the cheap part: email plus-addressing (`user+1@gmail.com`, `user+2@gmail.com`, all delivering to one inbox), disposable-email API services, or SMS-verification bypass services for phone-verified signups.
2. For each identity, the script calls `POST /api/auth/register` with the referral code embedded (either in the request body or a `?ref=` query parameter carried into the registration call).
3. If the platform requires email/SMS verification before the referral bonus posts, the script automates that too — reading the disposable inbox via API/IMAP, or extracting the OTP/verification link programmatically, then calling the verification endpoint.
4. Each registration is a fully valid, unique account by every check the API performs: unique email, unique username, valid-format payload, verified via the same channel the API trusts.
5. `POST /api/referrals/apply` (or equivalent logic triggered automatically on verified signup) pays out the referral bonus to the referring account for every one of these accounts.
6. Script repeats at whatever pace the disposable-identity pipeline supports — often hundreds to thousands of accounts, each earning a small referral bonus that aggregates into a large payout, or each unlocking a "sign up and get $X" new-user bonus directly.

**Business rule violated:** "One referral bonus per genuinely distinct new customer." The API's uniqueness check (unique email, unique verified phone) is real and correctly enforced — the flaw is that "unique" and "genuinely distinct human" are not the same thing, and the API has no signal that ties multiple registrations back to one operator (shared device fingerprint, shared IP range, shared underlying phone/email pattern, timing correlation).

**Why the API allows it:** Identity verification is checked for *format and channel validity* (is this a real, reachable email/phone that responded to a challenge) rather than *uniqueness of the human behind it*. There is no device/session fingerprinting tying registrations together, no rate limit on registrations-per-IP-per-hour that would be tight enough to matter, and no anomaly detection on referral payout velocity (e.g., "this referral code has been applied 40 times in the last hour").

---

## Scenario 3: Gift card and coupon stacking abuse

**Business assumption:** A coupon or gift card code is single-use, or a customer's order can only benefit from a bounded number of promotional discounts, protecting margin.

**API surface:** `POST /api/cart/apply-coupon`, `POST /api/checkout/redeem-giftcard`, `POST /api/checkout/complete`.

**Step-by-step abuse — coupon code enumeration and reuse:**
1. If coupon codes follow a predictable pattern (sequential, low-entropy, or leaked in a marketing email to a subset of users), the attacker scripts `POST /api/cart/apply-coupon` across a range of guessed codes to discover valid, unredeemed ones.
2. Even for a *known* single-use code, the attacker tests whether "single-use" is enforced per code (correct) or per code-per-account (incorrect) by applying the same code across many of the disposable accounts from Scenario 2. If the backend marks a code as consumed only against the account, not globally, the same code is reused across every farmed account.
3. **Stacking check:** the script applies multiple different valid coupon codes to the same cart in sequence within one session — `POST /api/cart/apply-coupon` called three times with three different codes before `POST /api/checkout/complete`. If the endpoint appends each discount rather than replacing the prior one or checking a "one promo per order" business rule, the discounts stack, sometimes past 100% of order value.
4. **Race condition variant:** the same single-use code is submitted as many near-simultaneous parallel requests (see the race-condition angle covered in the companion race-conditions series) so that multiple redemptions land inside the same check-then-act window before the first one is marked consumed.
5. Gift card balance abuse follows the same pattern against `POST /api/checkout/redeem-giftcard` — if partial redemptions don't atomically decrement balance server-side before responding, replaying the redemption call can draw down more value than the card holds.

**Business rule violated:** "This discount value is bounded and single-use." Coupon/gift-card *format and existence* validation passes every time; the *consumption/exclusivity* rule is what fails, either because it's checked per-account instead of globally, because stacking multiple valid discounts was never explicitly disallowed at the business-rule level, or because the check-then-decrement isn't atomic.

**Why the API allows it:** Promotion logic is frequently built additively (each valid code found → apply its discount) rather than with an explicit "one promotion slot per order, mutually exclusive" business rule enforced server-side. Enumeration succeeds because there's no lockout or CAPTCHA after N failed/successful coupon-apply attempts in a short window.

---

## Scenario 4: Account enumeration at scale

**Business assumption:** Individual signup, login, and password-reset requests reveal nothing to an outside party about which specific emails/usernames are registered.

**API surface:** `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/password-reset`.

**Step-by-step abuse:**
1. Attacker takes a large candidate list (a leaked email breach corpus, a generated list of common usernames, or a target company's employee email pattern).
2. Script sends each candidate through the endpoint that leaks the signal most cheaply. Common leak points: `POST /api/auth/register` returning "email already in use" vs. a generic success/failure; `POST /api/auth/login` returning a distinguishable error for "wrong password" vs. "no such account"; `POST /api/auth/password-reset` always returning 200 but taking a measurably different response time or triggering an email only for valid accounts.
3. Each individual request is completely legitimate-looking — a user is, after all, allowed to attempt to register or reset a password for an email they claim is theirs. There's no per-request violation.
4. The script simply logs the differential response (status code, response body message, response time, or side effect such as an email being sent) for each of the thousands of candidates.
5. Output is a confirmed list of valid registered accounts, which then feeds a targeted credential-stuffing or phishing campaign — dramatically higher success rate than blind stuffing because every target is confirmed to exist.

**Business rule violated:** "Whether a given email/username is a registered account should not be discoverable by an outside party." No single request breaks this; the differential across thousands of requests does.

**Why the API allows it:** The enumeration signal (message differences, timing differences, side-effect differences) is a byproduct of normal, necessary UX behavior (telling a real user their email is taken, or that their password was wrong) that developers rarely think to make constant-time and constant-response across the valid/invalid branches. There's also usually no meaningful rate limit or CAPTCHA on registration/login/reset attempts scoped broadly enough (per-IP and per-target-list) to make scripting thousands of checks impractical.

---

## Scenario 5: Payment flow bypass via workflow step skipping

**Business assumption:** A checkout is a sequence — cart → address → payment method → payment verification (3-D Secure / fraud check) → order confirmation — and each step's output is required input validated by the next.

**API surface:** `POST /api/checkout/step1-cart`, `POST /api/checkout/step2-address`, `POST /api/checkout/step3-payment`, `POST /api/checkout/step4-verify`, `POST /api/checkout/confirm`.

This scenario is expanded in full technical depth in `04-workflow-step-skipping.md`. Summary of the abuse pattern:

**Step-by-step abuse:**
1. Attacker completes step 1 and step 2 legitimately (or replays a captured legitimate request) to obtain a valid `cartId`/`sessionId` in a known state.
2. Attacker inspects, via proxy history, what parameters `step4-verify` and `confirm` actually check before marking the order as paid — commonly a `paymentVerified: true` flag, a `fraudCheckStatus`, or a `3dsCompleted` boolean set by step 4.
3. Attacker sends `POST /api/checkout/confirm` directly, either omitting the call to `step4-verify` entirely, or calling `step3-payment` with a manipulated body that sets `paymentVerified: true` / `amount: 0.01` / `skipVerification: true` client-side, trusting the backend to just store what it's told.
4. If the backend's order-state machine is implemented as "does the confirm endpoint find a cart in *any* prior-step state and just finalize it" rather than "does the confirm endpoint verify each prior step's state transition actually occurred server-side," the order completes without payment verification ever running, or with a client-supplied amount instead of the actual cart total.
5. Order is marked fulfilled; goods ship or service is granted with no payment, or with a fraction of the real payment, captured.

**Business rule violated:** "An order cannot be confirmed until payment has been verified for the correct amount." The individual `confirm` call is authorized (the user owns this cart) — the sequence requirement is what's bypassed.

**Why the API allows it:** Multi-step flows are frequently implemented as a set of independent endpoints sharing a session/cart ID, with each endpoint trusting that "if you have a valid session, you've presumably gone through the earlier steps via the UI." The backend doesn't maintain and check an explicit state machine (`cart.status` must be `payment_pending` before `confirm` will transition it to `paid`, and `payment_pending` can only be reached by a server-verified callback from the payment processor, never a client-set flag).

---

## Scenario 6: Voting or rating manipulation

**Business assumption:** Each real user contributes one vote/rating, so the aggregate reflects genuine sentiment.

**API surface:** `POST /api/polls/{id}/vote`, `POST /api/products/{id}/rating`, `GET /api/auth/session` (or a guest/anonymous voting token issuance endpoint).

**Step-by-step abuse:**
1. If voting requires authentication, attacker combines this with Scenario 2's account-farming pipeline: create N accounts, verify each cheaply, use each to cast exactly one vote — individually indistinguishable from N real users.
2. If voting is anonymous/session-based (common for public polls and product ratings to reduce friction), the attacker instead scripts repeated calls to whatever "new anonymous voter" issuance looks like — often just clearing cookies / requesting a fresh guest token from `GET /api/auth/guest-token` before each `POST /api/polls/{id}/vote` call — since a fresh token is trivial to obtain and the vote endpoint only checks "does this token exist and has it voted on this poll," not "is this a new human."
3. Script rotates IP (data-center proxies or residential proxy pools) alongside token/cookie rotation if the target has IP-based vote deduplication, since that's often the *only* dedup control present.
4. Votes/ratings are submitted at whatever rate the infrastructure allows — thousands per hour is typical for an unthrottled endpoint — skewing the result or, for product ratings, either inflating a product's own score or brigading a competitor's down to 1 star.

**Business rule violated:** "One vote/rating per real, distinct participant." The API correctly enforces "one vote per token/account," but token/account issuance is cheap and unlimited, so the rule that actually matters — one per human — is never checked at all.

**Why the API allows it:** Deduplication is implemented against the identifier that's cheapest for the API to check (session token, account ID, sometimes IP) rather than one that's expensive for an attacker to fake. There's no CAPTCHA on vote/rating submission, no device fingerprinting, and often no velocity check on "votes originating from newly created sessions/accounts within a short time window."

---

## Common thread across all six scenarios

In every case above: authentication succeeded, authorization succeeded (the actor was allowed to perform *that* action on *that* resource), and input validation succeeded (the payload was well-formed). The failure is always the same shape — **the API has no concept of "this actor, across time and across sessions, has already done this too many times, too fast, or out of the expected sequence."** That is precisely the gap file 3 (detection methodology) and file 4 (step-skipping technique) are built to test for.
