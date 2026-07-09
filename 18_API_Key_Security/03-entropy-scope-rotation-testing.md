# API Key Security Testing — Entropy, Scope, and Rotation Gap Testing

This file covers what to do with an API key once you have one — whether you
found it leaked (File 2), were issued one legitimately as a low-privilege test
account, or are testing whether the *generation process itself* is predictable
enough to guess additional valid keys without ever finding a leaked one.

## Part A — Entropy and Predictability Testing

### A.1 Mechanism

A well-generated API key is drawn from a cryptographically secure random number
generator (CSPRNG) with enough bits of entropy that brute-forcing or guessing a
valid key is computationally infeasible. Predictability testing exists because
not every implementation does this — common failure patterns:

- **Sequential keys** — `key_00001`, `key_00002`. Often a legacy system where
  keys were originally just auto-incrementing database IDs with a prefix, never
  migrated to random generation.
- **Timestamp-based keys** — the key (or a component of it) is derived from
  `time()` at issuance, sometimes combined with a weak hash. If you know
  roughly *when* a key was issued (e.g., from an account creation timestamp
  visible elsewhere in the app), the search space collapses dramatically.
- **Low-entropy random generation** — using a non-cryptographic PRNG (like a
  standard `rand()` call instead of a CSPRNG), or generating a
  reasonable-*looking* length key but from a small effective alphabet or with a
  predictable seed (e.g., seeded from server start time, or from
  `microtime()` in PHP without a secure random source layered on top).
- **Insufficient length** — even with a proper CSPRNG, a key that's only 6-8
  characters from a small alphabet has a small enough keyspace to be
  brute-forceable outright, independent of any predictability flaw in *how*
  it was generated.

### A.2 Manual Testing Workflow

**Step 1 — collect a sample.** You need multiple keys to detect a pattern.
Realistic ways to get a sample legitimately during an authorized engagement:
create several test accounts and note the keys issued to each, or request
key regeneration multiple times on one account if the platform allows it, and
record each value with its issuance order/timestamp.

**Step 2 — visual/structural inspection first.** Line up the samples and look
for:
- Any part of the string that's constant or changes in an obviously
  incrementing way.
- Whether the length is consistent — inconsistent length across samples that
  are supposedly the same key type can itself be informative (suggests
  variable-length encoding of variable-length source data, like a timestamp).
- Whether any substring correlates with something you already know (account
  creation time, username, sequential account ID).

**Step 3 — formal entropy calculation.** For a string that looks random but you
want to quantify, calculate Shannon entropy per character:

```
python3 -c "
import math, collections
s = 'PASTE_KEY_HERE'
counts = collections.Counter(s)
length = len(s)
entropy = -sum((c/length) * math.log2(c/length) for c in counts.values())
print(f'Length: {length}')
print(f'Shannon entropy: {entropy:.3f} bits/char')
print(f'Estimated total entropy: {entropy*length:.1f} bits')
"
```
- `python3 -c "..."` — runs an inline Python snippet without creating a file,
  fine for a one-off calculation.
- `collections.Counter(s)` — builds a frequency count of each character in the
  key, which is what the Shannon entropy formula needs (the probability of each
  symbol).
- `-sum((c/length) * math.log2(c/length) for c in counts.values())` — this is
  the Shannon entropy formula itself: for each character's observed frequency
  `c/length`, multiply by `log2` of that frequency, sum them, and negate — the
  standard information-theoretic measure of unpredictability per symbol, in
  bits.
- `entropy*length` — multiplies per-character entropy by string length to
  estimate total bits of entropy in the whole key, useful for a rough
  brute-force feasibility comparison (a well-formed 32-char hex key should be
  in the range of ~128 bits if truly random from a 16-symbol alphabet at 4 bits
  each; a key that scores far below that per-character rate against its
  apparent alphabet size is a red flag, since Shannon entropy on a *single*
  sample can't prove randomness, but a low score is still informative, and low
  scores across *multiple* samples compared to each other are more reliable
  than judging one key in isolation).

**Important caveat on Shannon entropy:** this measures the distribution of
characters *within one string*, not whether the generation *process* across
many keys is unpredictable. A key generated as `md5(username)` can have
excellent per-character Shannon entropy (MD5 output looks random) while being
completely predictable if you know the username. **Cross-sample analysis
(Step 2, and Section A.3 below) is more important than single-key entropy
scoring** — don't let a high Shannon entropy score on one key give false
confidence; always try to get multiple samples.

### A.3 Testing for Sequential/Timestamp Patterns Directly

If Step 2 suggested a sequential or timestamp pattern, test the hypothesis
directly rather than just theorizing:

```
for i in $(seq -f "%05g" 1 20); do
  curl -s -o /dev/null -w "%{http_code} key_${i}\n" \
    -H "X-API-Key: key_${i}" https://target.com/api/v1/whoami
done
```
- `seq -f "%05g" 1 20` — generates the numbers 1 through 20, formatted
  (`-f "%05g"`) as zero-padded 5-digit strings (`00001`, `00002`, ...), matching
  a suspected `key_00001`-style sequential format.
- `-o /dev/null` — discard the response body since we only care about the
  status code for this pass.
- `-w "%{http_code} key_${i}\n"` — print the HTTP status code alongside which
  candidate key produced it, so you can scan the output for any `200` among
  expected `401`/`403` responses.
- `-H "X-API-Key: key_${i}"` — send the candidate key using whatever header
  format the target actually uses (confirmed from File 1/2 recon — don't guess
  this, use the real header name and scheme you've already observed).
- Rate-limit awareness: this is exactly the crossover point flagged in File 1
  — even 20 sequential requests can trip bot/anomaly detection on a
  well-defended target. Keep authorized brute-force testing small and
  deliberate; if you need to test a genuinely large keyspace, that becomes a
  Rate Limit / Bot Protection Bypass engagement (see that series) and should be
  scoped and communicated as such, not run silently as a "quick check."

### A.4 Real-World Note

Sequential/predictable API keys are a recurring finding in older or
internally-built platforms that never went through a security review of their
credential issuance system — common in B2B SaaS products where the "API key"
feature was added later in the product's life as a checkbox feature, by
engineers who copied an existing internal ID-generation pattern rather than
using a dedicated secrets library.

## Part B — Scope and Permission Testing

### B.1 Mechanism

A key's *documented* purpose (e.g., "read-only key for pulling order data")
and its *actual* server-side enforcement are two different things, and the gap
between them is a broken access control problem specific to API keys — the
key equivalent of BFLA (API5) and BOLA (API1), applied to key-based auth
instead of session/JWT-based auth. The root cause is almost always that scope
is tracked at *issuance/documentation* time (a database flag, a dashboard
label) but never actually *checked* against the requested endpoint/action at
request time.

### B.2 Manual Testing Workflow

**Step 1 — establish the documented/expected scope.** Read the provider's own
API docs for what this key type is supposed to be limited to. If it's a
first-party internal API with no public docs, infer expected scope from the
UI context the key was issued in (e.g., a key generated from a "read-only
reporting integration" settings page implies read-only, GET-only expected
behavior).

**Step 2 — test read access outside the documented scope.** Take the key and
call endpoints for resources/features it should have no reason to touch:

```
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-API-Key: <key>" \
  https://target.com/api/v1/admin/users
```
- Same `-o`/`-w` pattern as before, isolating just the status code.
- The specific endpoint (`/admin/users` here) should be swapped for every
  endpoint you enumerated during API Reconnaissance that's outside this key's
  documented purpose — do this systematically, not just against one guessed
  admin path.

**Step 3 — test write/destructive access even if the key is "read-only."**
This is the highest-value check in this section — a documented read-only key
that actually accepts a `POST`/`PUT`/`DELETE` is a severe finding regardless of
what other scope issues exist:

```
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE \
  -H "X-API-Key: <key>" \
  https://target.com/api/v1/orders/12345
```
- `-X DELETE` — explicitly overrides curl's default GET method. Always confirm
  with the client/engagement rules of engagement before running destructive
  methods against real data — prefer testing against a resource you created
  yourself (your own test order/object) rather than another user's/tenant's
  data, so a positive finding doesn't cause unauthorized data loss.

**Step 4 — test cross-tenant/cross-resource access (the BOLA overlap).** If the
API is multi-tenant, test whether this key — issued for tenant A — can read or
modify tenant B's resources by ID substitution. This is standard BOLA
methodology (see that series for the full technique) applied specifically
through a key-based auth mechanism rather than a session.

**Step 5 — privilege escalation via key substitution.** This is subtly
different from Steps 2-4. Rather than testing what *one* key can reach, test
what happens when you use a lower-privilege key against an endpoint or
operation that's supposed to require a higher-privilege key, specifically
looking for endpoints that check "is *a* valid key present" but not "is *this
specific class* of key present." A concrete pattern to test: if the platform
issues both a publishable/public-tier key and a secret/full-access key (the
Stripe `pk_`/`sk_` split from File 1 is the canonical example of the *correct*
way to do this), test whether the low-tier key works on endpoints that should
require the high-tier one:

```
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer <publishable-tier-key>" \
  -X POST https://target.com/api/v1/charges \
  -d "amount=100&currency=usd"
```
- Tests whether an endpoint that should require the secret/full-access tier
  key (creating a charge) will actually accept the public/limited tier key
  instead — the server-side check being tested is "does this endpoint
  validate key *class*, not just key *validity*."

### B.3 Real-World Note

Scope-confusion findings are common in platforms that added a "restricted" or
"read-only" key tier as a later feature addition — the new key tier gets
correctly rejected on the *obvious* write endpoints (the ones the developer
remembered to update), but an endpoint added afterward, or a less-obvious
bulk-export or admin-adjacent endpoint, gets missed and still accepts any
valid key regardless of tier. This is the single most commonly escalated
severity in API key findings on HackerOne — a "just a leaked key" report
routinely gets escalated from informational/low to critical once the
reporter demonstrates the leaked key had far broader access than its stated
purpose.

## Part C — Rotation Gap Testing

### C.1 Mechanism

"Revoking" or "rotating" a key sounds like a single atomic action but is
frequently implemented as several separate steps across separate systems
(the primary auth database, a cache/CDN layer, a downstream microservice with
its own cached copy of valid keys, a third-party gateway). A rotation gap
exists when any one of those layers doesn't get updated, or gets updated on a
delay, leaving the "old" key still functional somewhere in the chain even
though the dashboard shows it as revoked.

### C.2 Manual Testing Workflow

**Step 1 — obtain an old key you can legitimately test with.** During an
authorized engagement, generate a key, use it to confirm it works, then
explicitly revoke/rotate it through the platform's own UI or API, noting the
exact revocation timestamp.

**Step 2 — immediately retest the old key.**

```
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-API-Key: <revoked-key>" \
  https://target.com/api/v1/whoami
```
- If this returns `200` instead of `401`/`403` immediately after revocation,
  that's a hard rotation-gap finding on its own — no delay needed to prove the
  issue.

**Step 3 — if immediate retest correctly fails, test again after a delay.**
Cache-based rotation gaps often self-resolve after a TTL expires (a few
minutes to a few hours depending on the cache layer), which is a real and
common root cause worth documenting even though it "fixes itself" — a
window during which a revoked key still works is still a legitimate finding,
just with a bounded severity/window rather than a permanent bypass:

```
sleep 300 && curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-API-Key: <revoked-key>" \
  https://target.com/api/v1/whoami
```
- `sleep 300` — pause 5 minutes before retesting, to check whether the key
  becomes invalid only after a cache TTL rather than immediately. Adjust the
  interval and repeat at a few checkpoints (e.g., 1 min, 5 min, 30 min) to
  characterize the actual gap window for the report, rather than a single
  pass/fail check.

**Step 4 — test rotation specifically (new key issued to replace old, rather
than pure revocation).** Confirm the *new* key works, then retest the *old*
key using the same immediate + delayed pattern as Steps 2-3 — some platforms
correctly invalidate on explicit "revoke" but have a separate, buggier code
path for "rotate" that fails to invalidate the predecessor.

### C.3 Real-World Note

Rotation gaps are a common downstream consequence of exactly the kind of
leaked-key incident File 2 covers — an organization discovers a key leaked
(often from a HackerOne report or an automated GitHub secret-scanning alert),
rotates it as their remediation step, and the rotation itself is what gets
tested next by a thorough reporter/pentester, sometimes surfacing a second,
independent finding (the rotation gap) stacked on top of the original leak.
Always retest remediation on a retest engagement rather than trusting a
"fixed" status at face value.

## WAF / API Gateway Relevance for This File

As covered in File 1: scope testing (Part B) and rotation gap testing (Part C)
are both small numbers of well-formed, legitimate-looking authenticated
requests — nothing here is attack-shaped from a WAF's perspective, since the
authorization decision being tested is entirely an application-layer/backend
concern, not a request-pattern concern. Entropy/predictability testing (Part
A) is passive analysis on keys you already have and is likewise irrelevant to
a WAF — **except** Section A.3's direct guessing workflow, which sends
multiple authentication attempts and can trigger rate-limiting or anomaly
detection at volume. That specific sub-case is flagged again here as the
same crossover point noted in File 1: keep manual predictability checks small
and deliberate, and treat any larger-scale key-guessing exercise as a
separate, explicitly-scoped Rate Limit / Bot Protection Bypass engagement
rather than folding it silently into this testing.

## PortSwigger, HackTheBox, and HackerOne Mapping

**PortSwigger (Apprentice → Practitioner → Expert):**
- *Access Control* topic, Apprentice: "Unprotected admin functionality" and
  "User role controlled by request parameter" — the underlying broken access
  control logic transfers directly to Part B's scope testing, even though
  neither lab is API-key-specific.
- *Access Control* topic, Practitioner: "Multi-step process with no access
  control on one step" — conceptually close to Part C's rotation gap testing
  (a process with an inconsistently-enforced step), though the lab itself is
  about a UI wizard flow rather than key rotation.
- *Authentication* topic, Practitioner: "Broken brute-force protection" labs —
  relevant background for Part A.3's guessing workflow and for understanding
  why volume-based key guessing crosses into rate-limit-bypass territory.
- No PortSwigger lab tests entropy/predictability of a generated credential
  directly (Part A), nor key-tier privilege escalation specifically (Part B
  Step 5) — stated honestly; these are covered instead by HackTheBox below.

**HackTheBox (supplementary):**
- API-focused challenges that include a low-privilege/public key and a
  separate high-privilege/secret key as intended design, where the challenge
  goal is escalating from one to the other — directly exercises Part B Step 5.
- Machines with intentionally weak, sequential, or derivable credential
  generation as part of the intended path — directly exercises Part A.

**HackerOne (case study reading):**
- Search Hacktivity for reports combining "leaked key" with "found broader
  scope than expected" — the escalation pattern described in B.3.
- Search for reports specifically about key rotation/revocation failures
  following a prior disclosed leak — demonstrates the C.3 pattern of a
  second finding stacked on remediation of the first.

## Cross-References

- **File 2** — where the key came from in the first place (leakage), before
  you get to this file's testing.
- **File 4** — nuclei templates can automate parts of Part B's scope probing
  across many endpoints at once.
- **BOLA (API1)** and **BFLA (API5)** series — the general broken access
  control patterns that Part B Steps 4-5 are specific instances of.
- **API Rate Limit / Bot Protection Bypass** series — required reading before
  scaling up Part A's guessing workflow beyond a small manual sample.
- **OAuth 2.0** series — for scope testing on delegated tokens, which is a
  related but distinct model from the static-key scope testing in this file.
