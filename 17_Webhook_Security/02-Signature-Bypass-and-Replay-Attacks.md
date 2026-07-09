# Webhook Security — 02: Signature Bypass and Replay Attacks

This file covers the receiver side of the trust model from file 00: testing whether a
webhook *receiver* endpoint correctly verifies that an inbound request genuinely came from
the claimed sender, hasn't been tampered with, and hasn't been seen before. Cross-reference
the Cryptographic Failures and JWT Attacks files in the web application series for the
underlying HMAC/signature concepts — this file applies them specifically to webhook
delivery.

## 1. What the signature is actually protecting against — mechanism first

When a platform delivers a webhook, it computes an HMAC (Hash-based Message Authentication
Code) over the request body using a secret that both the platform and the receiver know
(exchanged at registration time — see file 00, Section 3). It sends that HMAC in a header
alongside the request:

```
X-Webhook-Signature: sha256=7f9c8a3e1b6d4f2a0c5e8b1d3f6a9c2e8d1b4f7a0c3e6b9d2f5a8c1e4b7d0a3f
```

On the receiving end, the correct verification logic is:

```python
import hmac

def verify(request_body: bytes, secret: bytes, received_signature: str) -> bool:
    prefix, received_digest = received_signature.split("=", 1)
    expected_digest = hmac.new(secret, request_body, "sha256").hexdigest()
    return hmac.compare_digest(expected_digest, received_digest)
```

Piece by piece, what each part is defending against:

- **`hmac.new(secret, request_body, "sha256")`** — recomputing the HMAC over the *exact
  bytes received*. This is what proves the body wasn't modified in transit and was produced
  by someone who knows `secret`. Without this step entirely, *anyone* who discovers the
  receiver's URL can POST an arbitrary body and have it processed as if it came from the
  legitimate platform — this is "missing signature validation," Section 2 below.
- **`secret`** — a value that must be unguessable and never exposed. If it's weak, short,
  predictable, or leaked, an attacker can compute valid signatures for arbitrary payloads of
  their own choosing, which is strictly worse than a missing check, because it also
  defeats naive "did *a* signature header exist" checks — Section 4 below.
  covers testing for this.
- **`hmac.compare_digest(...)`** — comparing the computed and received digests in
  **constant time**, meaning the comparison takes the same amount of time regardless of how
  many leading bytes match. Using a normal `==` string comparison instead leaks *how many
  characters matched before the first mismatch* through response timing, letting an
  attacker recover the correct signature byte-by-byte without ever knowing the secret —
  Section 3 below covers this.

What the signature does **not** protect against, which is exactly the gap file 03 covers:
the signature proves the body wasn't altered and came from someone who knows the secret —
it says nothing about whether the *business claims inside* that correctly-signed body are
still true by the time they're acted on, or whether the same correctly-signed body is being
submitted more than once (that's what Sections 5–6 of this file, replay, cover).

## 2. Testing for missing signature validation

This is the single highest-value, lowest-effort test on any webhook receiver, and should
always be tried first.

**Step 1 — Capture a legitimate delivery.** Trigger a real webhook event and capture the
full request (Burp Proxy history, or your own listener if you control the receiver you're
testing). Note every header present, especially any that look signature-related
(`X-Webhook-Signature`, `X-Hub-Signature-256`, `Stripe-Signature`, `X-Twilio-Signature`, etc.
— naming varies by platform but the pattern is consistent).

**Step 2 — Resend with the signature header stripped entirely.**

```
POST /hooks/orders HTTP/1.1
Host: receiver.example.com
Content-Type: application/json

{"event":"order.paid","data":{"order_id":"ord_123","amount":9999}}
```

If this is processed identically to a signed request (same success response, same
downstream effect — check application state, not just the HTTP response code), the receiver
performs **no signature validation at all**. This means anyone who discovers the endpoint
can forge arbitrary events. This exact failure mode — a receiver that skips signature
verification entirely and derives authorization decisions (like which user sent a message)
directly from attacker-controlled body fields — is documented plainly in the Twilio-webhook
finding referenced in Section 8 below: the code path for handling inbound webhook data ran
immediately, with a comment literally marking where signature validation should have been,
and used a client-supplied field for downstream authorization.

**Step 3 — If Step 2 fails, try altering the body while keeping the original signature.**
Change one field (increment `amount`, change `event` type) but leave
`X-Webhook-Signature` exactly as captured. If this is accepted, the receiver has a signature
header check present in code but isn't actually verifying it against the body — a common
mistake when a `TODO` stub returns `true` unconditionally, or when the check is present but
short-circuited by another code path (e.g., a debug/test flag).

**Step 4 — If a signature is enforced, check *how* it's derived.** Some implementations sign
only specific fields rather than the full body, or sign the body but not the headers/query
string. If you can identify which parts are excluded from the signed content, modify only
those parts — the signature will still validate because it was never computed over them.

## 3. Timing attack on signature comparison

This applies only when Step 2/3 above show a signature check genuinely exists and rejects
tampered/missing signatures — the question here is whether the *comparison itself* is
constant-time.

**Why the vulnerability exists:** a naive comparison (`==` in most languages, or a
byte-by-byte loop with early exit) returns as soon as it finds the first mismatched byte.
That means a correct guess for the first byte of the digest takes measurably longer to
reject than an incorrect one, because the comparison got one byte further before bailing
out. Repeating this across all 64 hex characters of a SHA-256 digest, one position at a
time, recovers the entire valid signature for a *chosen* payload — without ever learning the
secret itself, and without needing to brute-force the full keyspace.

**Step-by-step:**

1. Choose a fixed request body you want to forge a valid signature for.
2. For the first hex character position, send 16 requests (one per possible hex digit
   `0`–`f`) with a signature guess like `0000...0` through `f000...0`, all other characters
   held at a placeholder.
3. Measure response time for each of the 16 attempts, ideally averaging many repeated
   requests per candidate to smooth out network jitter — this is the same statistical
   approach used against any timing side channel and is the main practical obstacle (real
   network noise routinely swamps a single-request timing difference).
4. The candidate with the measurably longer average response time is (probabilistically)
   the correct character at that position, because the comparison got one byte further
   before returning false.
5. Fix that character, move to the next position, repeat. This is a linear-time attack (64
   positions × 16 guesses × N repetitions for noise reduction) rather than the exponential
   cost of guessing the whole digest at once.

**Practical caveats to document honestly when reporting this:** real-world network jitter
often makes this attack far noisier than the clean theoretical model suggests, especially
over the internet rather than a local network — this is precisely why HMAC libraries and
platform documentation call out `hmac.compare_digest` / `Rack::Utils.secure_compare`
specifically, rather than leaving developers to reason about timing themselves (see Section
8's HackerOne API documentation reference, which states this exact recommendation and names
the exact reason: a non-constant-time comparison "could leave the secret vulnerable to a
timing attack"). Demonstrating this in a report typically requires either a local timing
harness with many repetitions, or acknowledging it as a theoretical-but-real finding backed
by code review showing `==` in place of a constant-time function, since fully exploiting it
remotely over a noisy network is often impractical within test-engagement time constraints.

## 4. Weak secret brute-forcing

Independent of how the comparison is implemented, the secret itself can simply be weak.

**What to test:**

- **Short/low-entropy secrets** — if the platform lets *users* set their own webhook secret
  (rather than generating one cryptographically), users often choose short, memorable, or
  reused strings. Brute-force offline once you have one valid (body, signature) pair to
  check candidates against:

```python
import hmac, itertools, string

known_body = b'{"event":"ping"}'
known_sig = "a1b2c3..."  # captured from a real delivery

for candidate in wordlist:  # common secrets, company name variants, leaked-credential lists
    guess = hmac.new(candidate.encode(), known_body, "sha256").hexdigest()
    if hmac.compare_digest(guess, known_sig):
        print("Secret found:", candidate)
        break
```

- **Default/placeholder secrets** — check documentation, SDK examples, and default
  configuration files for a shipped default secret (`"changeme"`, `"webhook_secret"`,
  framework-generated placeholder values) that a deployment never rotated.
- **Secret reuse across environments** — a secret leaked in a staging environment,
  a public GitHub repo's `.env.example` accidentally containing a real value, or a
  client-side JS bundle that embeds a "secret" meant to be server-only, is often reused
  unchanged in production.
- **Secret length/algorithm downgrade** — if the registration API accepts a `secret` field
  with no minimum-length enforcement, register an intentionally short/weak one yourself
  during testing to confirm whether the platform enforces any minimum at all — this is a
  finding on the *platform* even if you can't brute-force any specific customer's secret.

Once a secret is recovered (by any of the above), you can forge arbitrary, correctly-signed
webhook events — this is strictly worse than the missing-validation case in Section 2,
because it also defeats any monitoring that specifically checks "was a valid-looking
signature present," and is the natural escalation path once you have one captured
(body, signature) pair to test candidates against offline, without needing to send further
requests to the target at all.

## 5. What replay protection is defending against

Even a perfectly verified signature only proves a request was genuinely produced once, by
someone who knows the secret, over that exact body. It says nothing about **how many times**
that exact request is allowed to be processed. If an attacker captures one legitimate,
correctly-signed webhook delivery — through a compromised network position, a logging
system, browser history on a shared machine, or simply because the delivery log itself is
exposed — replaying that identical request should not be able to trigger the action a second
time.

The two standard defenses, both introduced in file 00, Section 4:

- **Timestamp checking** — the receiver rejects any request whose `X-Webhook-Timestamp` is
  older than a small tolerance window (commonly 5 minutes), regardless of signature
  validity. This bounds the *time* window during which a captured request can be replayed,
  but does nothing to prevent replay *within* that window.
- **Nonce/event-ID deduplication** — the receiver tracks event IDs (`X-Webhook-Id`) it has
  already processed (in a database, cache, or set) and rejects any repeat, permanently. This
  is the only defense that actually closes the gap the timestamp window leaves open.

## 6. Testing for replay protection

**Step 1 — Capture one legitimate, correctly-signed delivery in full**, headers and body
exactly as sent.

**Step 2 — Resend it completely unmodified, immediately.** If the action fires again
(check application state — a second order confirmation, a second credit to an account, a
second privilege grant — not just the HTTP status code, which may return `200` either way
even if the app internally deduplicates and no-ops), the receiver has **no replay protection
at all**.

**Step 3 — If immediate replay is blocked, test the timestamp tolerance window.** Wait
progressively longer intervals (1 minute, 4 minutes, 6 minutes, 10 minutes) and resend the
identical captured request each time, to find the exact tolerance boundary and confirm
whether it's timestamp-based rejection specifically (vs. event-ID deduplication) causing the
block. A wide tolerance window (some implementations use hours, for account for clock skew
tolerance chosen too generously) still leaves a meaningful replay window.

**Step 4 — Test event-ID deduplication independently of timestamp.** Take a captured
request and modify *only* the timestamp header to be current, while recomputing nothing else
(leave the original signature, event ID, and body untouched — the signature won't validate
against a re-signed timestamp unless the timestamp is part of the signed content, so this
specifically tests whether the receiver checks the ID against a "already processed" store
independent of, or as well as, the timestamp/signature checks). If the request is still
accepted, the receiver relies on timestamp alone with no ID-based deduplication, meaning any
replay sent within the tolerance window before that timestamp naturally expires succeeds
unconditionally.

**Step 5 — Test for race-condition replay (parallel, not sequential).** Even where
event-ID deduplication exists, test whether it's implemented with proper locking. Fire
several copies of the same captured request in parallel (Burp Intruder or Turbo Intruder
with a null payload set, or a simple concurrent script) rather than sequentially. If the
"already processed" check-and-mark isn't atomic, multiple concurrent identical requests can
each pass the "have I seen this ID" check before any of them finishes marking it as seen —
a TOCTOU race identical in shape to any other race-condition vulnerability, applied here to
replay deduplication specifically. Cross-reference the API Race Conditions file in the API
series for the general parallel-request technique.

## 7. WAF / API Gateway relevance — explicit limitation, stated directly

As established in file 00, Section 6, this vulnerability class is **structurally poor fit
for WAF/gateway detection**, and that's worth restating concretely here rather than
including a padded bypass section that wouldn't reflect reality:

- A missing signature check is the *absence* of application logic. There is no request
  pattern to match against — the malicious request (Section 2, Step 2) is, at the HTTP
  level, identical in shape to a completely benign request that just happens to lack a
  header the *legitimate* sender would have included. A WAF can't know what headers a
  legitimate delivery "should" have without being taught the specific platform's signing
  scheme, which is receiver-application-specific configuration, not a generic attack
  signature.
- A non-constant-time comparison is a property of *server-side code execution time*. It's
  invisible in the request entirely; it can only be observed by measuring response timing
  across many requests, which a WAF inspecting individual requests has no mechanism to
  reason about.
- A replayed request is, by definition, byte-for-byte identical to a request that was
  already accepted as legitimate. There's no signature to distinguish "this is a replay" at
  the WAF layer — the *only* thing that can tell them apart is server-side state (has this
  exact event ID been seen before), which lives in the application, not the network edge.

**Where infrastructure does help, legitimately:** rate limiting at the gateway layer slows
down the brute-force in Section 4 and the parallel-race test in Section 6, Step 5 — but this
is a generic rate-limiting control, not something specific to detecting signature or replay
attacks, and a patient or distributed attacker (or a legitimate low-and-slow test) works
around simple per-IP rate limiting the same way it does for any other rate-limited endpoint
(see the API Rate Limit / Bot Protection Bypass file in the API series). Some managed API
gateways also now offer built-in "verify HMAC signature" middleware as a configurable
feature — when present and correctly configured, this closes Section 2's gap entirely, but
that's the gateway *doing the receiver's job correctly on the receiver's behalf*, not the
gateway detecting an attack pattern. Testing whether that middleware is present, and whether
it's actually enabled on the specific endpoint you're testing (it's easy to enable it
globally but miss one route), is a more useful question than looking for a signature-based
bypass, because there isn't one to look for.

## 8. PortSwigger lab mapping and real-world notes

**Honest gap, stated directly:** PortSwigger Web Security Academy has no labs on HMAC
webhook signature verification, timing attacks on MAC comparison, or webhook replay
protection. The closest adjacent PortSwigger material is general authentication-bypass and
API-testing methodology labs, which build the right instincts (test what happens when you
remove or tamper with a trust mechanism) but don't exercise this specific mechanism. Because
of this gap, real disclosed reports and primary documentation carry more of the practical
weight in this file than in file 01.

- **HackerOne's own webhook API documentation** explicitly recommends constant-time
  comparison functions (`hmac.compare_digest` in Python, `Rack::Utils.secure_compare` in
  Ruby) specifically to prevent timing attacks against the shared secret, and shows the
  correct verification pattern this file's Section 1 example is based on — a rare case of a
  platform documenting the exact mechanism (and exact defense) covered in Sections 1 and 3
  in its own public developer docs, worth reading directly for the canonical explanation.
- **A documented open-source agent gateway (2026)** shipped an inbound Twilio SMS webhook
  handler that skipped `X-Twilio-Signature` verification entirely — the code contained an
  explicit comment marking where the check should have been — and used a client-controlled
  `From` field directly for downstream authorization, letting any network-reachable sender
  impersonate an authorized phone number. This demonstrates Section 2 and also demonstrates
  file 03's payload-trust problem simultaneously: even had a signature existed, trusting the
  *content* of a signed field for authorization decisions without independent verification
  is a separate failure this file's Section 1 explicitly flags as outside what a signature
  alone protects against.
- **WakaTime, HackerOne #3120790 (2025)** — while framed as session/login-response replay
  rather than a webhook specifically, this report demonstrates the same core mechanism
  Section 6 tests for: a captured, legitimate authentication response was replayable
  indefinitely because server-side invalidation only occurred on password change, not on
  any time or single-use basis. The same "capture once, replay indefinitely because nothing
  server-side tracks prior use" pattern applies directly to under-protected webhook
  deliveries.
- **RBKmoney/TransferWise, HackerOne #996540** — an Apple Pay payment cryptogram replay
  finding, illustrating the same principle at the payment-protocol layer one level below
  webhooks: a cryptographically signed payment token, without server-side single-use
  enforcement, could be resubmitted. Useful as a reminder that replay protection has to be
  enforced at every layer that processes a signed artifact, not just the outermost one.

## Next

Continue to `03-Payload-Tampering-and-Endpoint-Enumeration.md` for attacks on what's
*inside* the payload, and on discovering receiver endpoints in the first place.
