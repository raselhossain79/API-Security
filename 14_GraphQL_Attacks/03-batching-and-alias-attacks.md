# Batching and Alias Attacks (Rate-Limit Bypass and Brute Force)

File 3 of 9. Assumes file 1 (aliases mechanic) and file 2 (schema
extraction — you need to know a mutation's exact name and arguments before
you can batch-attack it). This file covers using query batching and field
aliasing to pack many logical operations into one HTTP request, why that
defeats naive rate limiters, and a full step-by-step OTP brute-force
walkthrough.

---

## 1. The core problem this attack exploits

Most rate limiters — whether implemented in application code, at a reverse
proxy, or on a WAF/API gateway — count **HTTP requests**. A typical
REST-style rate limiter logic is: *"if this IP/session sends more than N
requests to this endpoint in T seconds, block it."*

GraphQL breaks the assumption baked into that logic, because **one HTTP
request can legally contain an arbitrary number of operations.** A rate
limiter that counts requests will see "1 request" and let it through, while
the GraphQL server behind it dutifully executes 100 login attempts, 500 OTP
checks, or 1,000 coupon-code guesses from that single request.

This isn't a parser bug or an edge case — it's the direct, intended
consequence of two entirely legitimate GraphQL features working exactly as
designed: **aliasing** (file 1, section 8) and **batching**. Understanding
both mechanically is the whole attack.

---

## 2. Mechanism 1: Aliasing multiple calls to the same mutation

Recall from file 1: normally you can't request the same field twice in one
selection set, because GraphQL wouldn't know how to key two results under
the same field name in the response. Aliases solve this by letting you
rename each call's result key.

Applied to a login mutation:

```graphql
mutation {
  attempt0: login(input: { username: "carlos", password: "123456" }) {
    token
    success
  }
  attempt1: login(input: { username: "carlos", password: "password" }) {
    token
    success
  }
  attempt2: login(input: { username: "carlos", password: "letmein" }) {
    token
    success
  }
}
```

Breakdown:
- `mutation { ... }` — this is one HTTP request, one GraphQL document, one
  `mutation` operation.
- `attempt0:`, `attempt1:`, `attempt2:` — aliases; arbitrary labels you
  invent, purely to let the same `login` field appear three times in one
  selection set.
- Each aliased call has its own independent arguments — a different
  password guess each time.
- `{ token success }` — selection set per call; `success` is what you'll
  grep the response for.

The server resolves all three `login` calls **as part of executing a single
request** — meaning, from the perspective of anything counting HTTP
requests, this was one request. From the perspective of the authentication
backend, three distinct login attempts with three distinct passwords were
made. Scale `attemptN` up to however many aliases the server will tolerate
in one document (often hundreds, sometimes limited by request body size
rather than any operation-count check) and you have a brute-force engine
that fires N guesses per HTTP request against a limiter that only counts
requests.

---

## 3. Mechanism 2: Batching (array-of-operations)

Some GraphQL server implementations additionally support **request-level
batching**: instead of a single `{ query, variables }` object, the client
POSTs a JSON **array** of such objects:

```json
[
  { "query": "mutation { login(input:{username:\"carlos\",password:\"123456\"}){success} }" },
  { "query": "mutation { login(input:{username:\"carlos\",password:\"password\"}){success} }" },
  { "query": "mutation { login(input:{username:\"carlos\",password:\"letmein\"}){success} }" }
]
```

This is functionally similar to aliasing for attack purposes — many logical
operations, one HTTP request — but the two are technically distinct
features and not every server supports both. **Always test both**: some
servers disable array-batching (a known, commonly-documented risk) while
leaving alias-based batching completely open, because aliasing is such a
core part of the query language itself that it can't be disabled without
breaking normal client functionality. This asymmetry is exactly why
aliasing, not array batching, is the more consistently exploitable and more
commonly seen path in real engagements and is the technique the walkthrough
below uses.

---

## 4. Step-by-step walkthrough: OTP brute force via aliasing

**Scenario:** a login flow requires a 4-digit OTP after password
verification. The mutation is:

```graphql
mutation verifyOtp($code: String!) {
  verifyOtp(code: $code) {
    success
    sessionToken
  }
}
```

The endpoint rate-limits to 5 requests per minute per session — enough to
make sequential brute forcing of a 4-digit OTP (10,000 possibilities)
completely impractical the normal way, but not enough to stop this.

### Step 1 — Confirm the mutation and its argument shape

Use introspection (file 2) or observed traffic to confirm `verifyOtp` takes
a single `code: String!` argument and returns an object with a `success`
field you can check. You need the exact field/argument names — guessing
here wastes attempts and may trip anomaly detection.

### Step 2 — Capture a legitimate request as a template

Intercept one real OTP-verification request in Burp Suite. Send it to
Repeater. Confirm it currently uses `variables` for `$code`:

```json
{
  "query": "mutation verifyOtp($code: String!) { verifyOtp(code: $code) { success sessionToken } }",
  "variables": { "code": "0000" },
  "operationName": "verifyOtp"
}
```

### Step 3 — Convert to an aliased, inline-argument batch

You cannot batch this using the `variables` approach as-is, because
`variables` is a single flat object — it can only hold one value per name,
not one value per aliased call. So the conversion has two required changes,
and skipping either one causes the request to fail:

1. **Move the argument inline** on each aliased call instead of using
   `$code`, since each alias needs its own distinct value.
2. **Delete the `variables` object and `operationName` field entirely** —
   leaving a stale `variables`/`operationName` referencing the old
   single-operation structure causes a validation error, because
   `operationName` is only required/valid when there are multiple *named*
   top-level operations in the document, not multiple aliased fields inside
   one operation.

```graphql
mutation {
  guess0000: verifyOtp(code: "0000") { success sessionToken }
  guess0001: verifyOtp(code: "0001") { success sessionToken }
  guess0002: verifyOtp(code: "0002") { success sessionToken }
  guess0003: verifyOtp(code: "0003") { success sessionToken }
}
```

### Step 4 — Generate all aliases programmatically

Manually typing 10,000 aliases is impractical. Generate them with a short
script — this can be run directly in the browser console (as in the
PortSwigger brute-force-protection-bypass lab methodology) or with any
scripting language:

```javascript
let query = "mutation {\n";
for (let i = 0; i <= 9999; i++) {
  const code = i.toString().padStart(4, "0");
  query += `  guess${code}: verifyOtp(code: "${code}") { success sessionToken }\n`;
}
query += "}";
console.log(query);
```

Breakdown:
- `padStart(4, "0")` — ensures `7` becomes `"0007"`, matching the OTP's
  fixed 4-digit format.
- The loop body produces one aliased call per possible code, each with a
  unique alias name (`guess0000` through `guess9999`) so the response keys
  don't collide.
- In practice, 10,000 aliases in one request is often too large for a
  single HTTP request (body size limits, execution timeouts) — split into
  batches of a few hundred to a few thousand per request and iterate, still
  a massive reduction in request count compared to one-guess-per-request.

### Step 5 — Send and read the response

Paste the generated query into Repeater's Query panel (deleting stale
`variables`/`operationName` per Step 3), and send. The response mirrors the
aliases:

```json
{
  "data": {
    "guess0000": { "success": false, "sessionToken": null },
    "guess0001": { "success": false, "sessionToken": null },
    "guess0002": { "success": true, "sessionToken": "eyJhbGciOi..." },
    "guess0003": { "success": false, "sessionToken": null }
  }
}
```

Search the response for `"success": true` (Burp's search bar under the
response panel works well for this). The alias name of the matching entry
— `guess0002` here — tells you the correct OTP directly from the key name,
without needing to correlate anything back to which sub-request it was,
because it was never a separate sub-request at all.

### Step 6 — Use the recovered credential/token

Take the `sessionToken` from the successful alias and use it directly, or
if the flow requires a follow-up step, replay the discovered OTP through
the normal single-request flow to complete login cleanly.

---

## 5. Why this defeats the rate limiter specifically

Walk through what the rate limiter actually observed across the whole
attack: **one HTTP POST request** (or a handful, if you split into batches
per Step 4). If the limiter's rule is "5 requests per minute," you are
nowhere near tripping it, regardless of whether that one request contained
1 operation or 5,000. The limiter's unit of measurement (HTTP requests) does
not match the actual unit of cost to the backend (resolver executions), and
that mismatch is the entire vulnerability. This is precisely the
"per-request rate limit" framing from the requirements this file was built
to walk through — the rate limit exists and functions correctly as written,
it's just measuring the wrong thing.

---

## 6. Other realistic targets for the same technique

The OTP example generalizes directly to any resolver where each guess is
cheap to construct and the space of valid answers is checkable from the
response:

- **Password brute force** against a `login` mutation (this is literally
  PortSwigger's own lab scenario for this technique — see file 9).
- **Coupon/promo code guessing** against an `applyCoupon` mutation.
- **Username enumeration** by aliasing a `resetPassword` or `getUser` query
  across a wordlist of candidate usernames/emails and checking for
  differential responses (e.g. one alias returns a user object, others
  return `null`).
- **Invite/referral code brute force** — same shape as coupon guessing.

In all of these, the workflow is the same six steps: confirm the mutation
shape, capture a template, convert to inline aliased calls, generate the
alias set programmatically, send, grep the response for the success
indicator.

---

## 7. WAF / API gateway relevance for this specific vulnerability

Detection methods commonly seen:

- **Alias-count / operation-count limits.** A GraphQL-aware gateway can
  parse the query document (not just measure body size) and reject requests
  whose selection set contains more than N aliased instances of the same
  field, or more than N total top-level fields in one operation. This is
  the most direct and most effective defense against this specific
  technique, because it addresses the actual mismatch described in section
  5 rather than trying to pattern-match the attack.
- **Query cost / complexity scoring.** Some gateways assign a numeric "cost"
  to each field (often configurable per-field by the API developer) and
  reject a document whose total cost across all aliases exceeds a budget.
  This overlaps heavily with the defenses covered in depth in file 4, since
  the same cost-scoring infrastructure defends against both alias-flooding
  and deep-nesting DoS.
- **Body-size limits** as a blunt, indirect control — capping request size
  in bytes incidentally caps how many aliases fit in one request, though a
  sufficiently patient attacker just sends more, smaller batched requests
  instead (Step 4's batching note).

Realistic evasion angles against these defenses:
- **Splitting the alias set across more, smaller requests** to stay under a
  per-request alias-count ceiling, trading request count for request size —
  this reintroduces some exposure to classic request-rate limiting, but
  usually at a far more favorable ratio than one-guess-per-request (e.g. 50
  guesses per request against a 5-requests-per-minute limit still yields
  250 guesses/minute).
- **Varying alias naming patterns and field ordering** between requests if
  the gateway's detection is naively signature-based on the literal
  structure of a known attack payload rather than on a genuine
  operation-count parse.
- **Mixing in decoy/no-op aliased fields** (e.g. aliasing `__typename`
  alongside real guesses) to alter the request's shape/fingerprint if
  detection is tuned narrowly to "many aliases of the exact same sensitive
  field" rather than "many aliases of anything."

A consolidated treatment of GraphQL-specific WAF evasion across every
technique in this series — not just batching — is file 7.

---

## 8. Summary checklist for this file

- [ ] Identify a sensitive mutation/query where guess-and-check applies
      (login, OTP, coupon, invite code, username enumeration).
- [ ] Confirm exact field/argument names via introspection or captured
      traffic.
- [ ] Convert the request from `variables`-based to inline-argument,
      aliased calls; remove stale `variables`/`operationName`.
- [ ] Generate the full alias set programmatically rather than by hand.
- [ ] Split into multiple requests if body size or gateway alias-count
      limits are hit.
- [ ] Grep the response for the success indicator; read the answer directly
      off the matching alias name.
- [ ] Note in your report that the rate limiter counts requests, not
      operations, and recommend operation-count/complexity-based limiting
      as the fix, not just a lower requests-per-minute threshold (which
      this technique defeats regardless of how low it's set).

**Next: file 4 — Depth, Complexity, and DoS Attacks**, covering how deeply
nested queries — a different abuse of the same "one request, many resolver
calls" property — cause server resource exhaustion.
