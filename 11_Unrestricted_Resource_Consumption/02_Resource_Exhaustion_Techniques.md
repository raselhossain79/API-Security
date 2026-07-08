# API4:2023 — Resource Exhaustion Techniques

This file covers four exploitation techniques once you've confirmed an
endpoint lacks effective rate limiting (see `01_Detection_Methodology.md`).
Every example below is broken down piece by piece: what resource is being
exhausted, why the API has no protection against it, and how to prove impact.

---

## 1. Pagination Limit Abuse

### 1.1 The Underlying Flaw

Many list/search endpoints accept a `limit` or `page_size` parameter intended
to cap how many records are returned per call, for legitimate pagination
(e.g., showing 20 results per page in a UI). The flaw occurs when the backend
**trusts the client-supplied limit value with no server-side maximum**, or
validates it only loosely (e.g., rejects negative numbers but not
astronomically large positive ones).

### 1.2 Example Request — Piece by Piece

```
GET /api/v2/orders?limit=5000000&offset=0 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

Breakdown:
- `GET /api/v2/orders` — a legitimate, documented endpoint. Nothing about the
  path itself is abnormal; this is not a hidden or undocumented route.
- `limit=5000000` — the resource being exhausted here is **database query
  execution time and result-set memory**. A well-designed API caps this
  server-side (e.g., "even if you ask for 5,000,000, we return at most 100").
  The vulnerable version passes this value directly into a `LIMIT` clause
  (or ORM equivalent, e.g., `.take(request.limit)` in many ORMs) with no
  clamping.
- `offset=0` — included to confirm the request targets the start of the
  table, maximizing the row count actually available to return (as opposed
  to hitting the end of a smaller table where fewer rows exist regardless of
  the limit requested).
- `Authorization: Bearer ...` — a valid, low-privilege token. This
  demonstrates the attack requires **no elevated access** — any authenticated
  (or in worse cases, unauthenticated) user can trigger it.

### 1.3 Why the API Has No Protection

This typically happens for one of three reasons:
1. The API was built assuming the *client* (a trusted first-party mobile app
   or SPA) would only ever request sane limits, and the backend was never
   defensively coded to also enforce a ceiling — a classic case of confusing
   "the UI won't let you do this" with "the API won't let you do this."
2. The ORM or query builder's default behavior silently accepts any integer
   for a `LIMIT`/`TAKE` clause, and no explicit `min(requested, MAX_ALLOWED)`
   clamp was added.
3. The endpoint was recently added to support an internal admin dashboard
   (which legitimately needs to pull large datasets) and the limit was left
   uncapped for convenience, then that same route was exposed on the
   public-facing API surface without re-review.

### 1.4 Proving Impact

- Time the request. A `limit=5000000` request that takes 8–15 seconds versus
  a `limit=20` request taking 40ms is a measurable, reportable delta.
- Send 5–10 of these requests concurrently (not sequentially) and observe
  overall API latency for *unrelated* endpoints during the burst — this
  demonstrates the shared resource (usually the DB connection pool) is
  starved, affecting other users, not just the requester.
- Where possible and authorized, check whether repeating the request at a
  larger `limit` (e.g., stepping from 100k → 1M → 10M) increases response
  time roughly linearly or worse — this indicates no query-planner-level
  safety net either (no cap on rows scanned).

### 1.5 PortSwigger Lab Mapping

PortSwigger's Web Security Academy does not currently have a lab
specifically modeling uncapped pagination as a distinct exercise — this is
an honest gap. The closest conceptually adjacent lab is under the API
testing topic, which covers exploring API endpoints found via documentation,
useful for the reconnaissance step that leads you to discover pagination
parameters in the first place. There is no Apprentice/Practitioner/Expert
lab chain for this specific technique on PortSwigger; practice this against
crAPI or a personal lab instead (see section 5 below).

---

## 2. File Upload Size Abuse

### 2.1 The Underlying Flaw

Upload endpoints that accept file size or content-length with no
server-enforced maximum (or a maximum enforced only at a layer that doesn't
actually stop the backend from processing the file, e.g., a WAF rule that
blocks the *response* but not before the backend already read the full file
into memory).

### 2.2 Example Request — Piece by Piece

```
POST /api/v1/documents/upload HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: multipart/form-data; boundary=----X
Content-Length: 5368709120

------X
Content-Disposition: form-data; name="file"; filename="report.pdf"
Content-Type: application/pdf

[5 GB of binary data]
------X--
```

Breakdown:
- `Content-Length: 5368709120` — declares a 5 GB body upfront. The resource
  being exhausted is **server-side memory/disk**, specifically whatever
  buffer the backend uses to receive the file before validation.
- `filename="report.pdf"` with `Content-Type: application/pdf` — the
  attacker declares a plausible, allowed file type/extension. This matters
  because many upload validators check extension/MIME type *before* checking
  size, or check size only *after* the full file has already been written to
  a temp location — meaning the exhaustion already occurred by the time the
  size check would reject it.
- The actual byte content can be arbitrary padding (does not need to be a
  valid PDF) unless the backend also performs file-type magic-byte
  validation before accepting the stream — test both a well-formed large PDF
  and a padded/garbage-content large file to identify which validation stage
  triggers first.

### 2.3 Why the API Has No Protection

- Size limits are frequently enforced only at the **web server or reverse
  proxy layer** (e.g., nginx `client_max_body_size`) for the main website,
  while a separately deployed API gateway or serverless function handling
  uploads has a different, much larger, or entirely absent limit — a
  configuration drift issue between components.
  Some cloud API gateways historically had default payload limits in the
  tens of MB, but if the upload is routed through a signed direct-to-storage
  URL flow (common in modern APIs: client requests a pre-signed S3 URL, then
  uploads directly to storage), the API layer's limit doesn't apply to the
  actual upload traffic at all — only the initial URL-request call is
  gated.
- Streaming upload handlers that process the file in chunks may not check
  cumulative size until after the stream completes, especially where the
  validation logic runs in an `on_upload_complete` callback rather than a
  per-chunk check.

### 2.4 Proving Impact

- Escalate file size in stages: 10 MB → 100 MB → 1 GB, recording response
  time and, if you have any visibility (error messages, monitoring dashboard
  access in an authorized internal test), memory/disk usage on repeat calls.
  Concurrent uploads (3–5 in parallel) at a large size more reliably
  demonstrate resource contention than a single large upload, since a single
  request might be handled fine while several in parallel exhaust the shared
  pool.
- Note whether the upload is stored even after later validation rejects it
  (e.g., the file lands in temp storage before a "file too large" error is
  returned) — this is a disk exhaustion vector independent of whether the
  upload is ultimately "accepted."

### 2.5 PortSwigger Lab Mapping

No dedicated PortSwigger lab covers file upload size-based DoS specifically
(their file upload labs focus on file-type/content bypass leading to RCE or
XSS, not resource exhaustion). This is a genuine coverage gap in the
Academy — practice this against crAPI or an authorized test target with
explicit written permission, since large-payload testing against production
systems without authorization risks real service disruption.

---

## 3. Regex Complexity Attacks (ReDoS via API)

### 3.1 The Underlying Flaw

An API endpoint validates or processes user input against a regular
expression that has **catastrophic backtracking** potential — patterns
containing nested quantifiers like `(a+)+`, `(a|a)*`, or `(a*)*` can cause
the regex engine's execution time to grow exponentially with crafted input,
even though the input string itself is short.

### 3.2 Example Request — Piece by Piece

Assume an API validates an email field with a vulnerable pattern such as
`^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$` (nested quantifier on the local
part).

```
POST /api/v1/users/register HTTP/1.1
Host: api.target.com
Content-Type: application/json

{
  "email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
  "password": "Test1234!"
}
```

Breakdown:
- `"email"` field — the injection point. The resource being exhausted is
  **CPU time on the thread/worker processing the regex match**, not memory
  or bandwidth.
- The value: a long run of `a` characters (roughly 40–60 characters is
  often sufficient to demonstrate multi-second delay; length can be tuned
  upward to push toward full unavailability) followed by `!` — a character
  that fails the final part of the pattern (`[a-zA-Z]+$` doesn't match `!`
  because there's no `@domain.tld` suffix at all in this crafted string).
  The trailing invalid character is deliberate: it forces the regex engine
  to **exhaust every possible backtracking combination** of how the `a`
  characters could be grouped by `([a-zA-Z0-9]+)+` before concluding no
  match is possible. If the string matched successfully partway through,
  the engine could short-circuit; forcing a guaranteed *failure* at the end
  is what triggers worst-case backtracking behavior.
- A single request with this payload can take seconds to tens of seconds of
  pure CPU time on a vulnerable pattern, versus sub-millisecond for a normal
  email. Sending even 5–10 of these concurrently against a single-threaded
  or limited-worker-pool backend can exhaust available compute entirely,
  denying service to all users, not just the attacker.

### 3.3 Why the API Has No Protection

- Regex validation is frequently treated as "just input validation" and not
  security-reviewed for algorithmic complexity — the developer's threat
  model was "reject malformed emails," not "reject computationally expensive
  strings."
- Regex patterns are often copy-pasted from Stack Overflow or generated by
  AI tooling without complexity analysis; nested quantifiers are a subtle
  pattern that's easy to introduce accidentally when composing multiple
  smaller patterns together (e.g., combining a "one or more word characters"
  group with an outer "one or more of that group" for no functional reason).
- Rate limiting, even where present, is usually keyed on request *count*,
  not request *cost* — a system can allow "10 requests per second" without
  any awareness that one of those ten requests will consume 30 seconds of
  CPU time, defeating the purpose of the limit entirely.

### 3.4 Proving Impact

- Record wall-clock time for the request across increasing input lengths
  (e.g., 20, 30, 40, 50 repeated characters) and demonstrate exponential (not
  linear) growth — this is the specific signature that proves catastrophic
  backtracking rather than just "the server is generally slow."
- Send the payload concurrently from multiple connections and demonstrate
  that unrelated, lightweight requests to the same API also slow down during
  the attack window — proving the exhaustion is shared-resource, not
  isolated to the attacker's own connection.
- Where the field is used in multiple places (e.g., an email format is
  validated both on registration and on every subsequent profile update
  call), confirm whether the same payload can be re-triggered repeatedly
  against an already-registered account, turning a one-time registration
  bug into a repeatable DoS lever.

### 3.5 PortSwigger Lab Mapping (Apprentice → Practitioner → Expert)

- **Apprentice**: No dedicated ReDoS lab exists on PortSwigger Academy at
  this level.
- **Practitioner**: No dedicated ReDoS lab exists at this level either.
- **Expert**: PortSwigger does not currently publish a lab specifically
  targeting Regular Expression Denial of Service. This is an honest,
  complete gap in Academy coverage for this technique — PortSwigger's
  content focuses heavily on injection and logic flaws rather than
  algorithmic-complexity DoS. For hands-on practice, use a local test
  harness (write a small Express/Flask endpoint using a known-vulnerable
  regex pattern) or crAPI where applicable input validation exists.

---

## 4. Expensive Computation Endpoint Abuse

### 4.1 The Underlying Flaw

Some API endpoints intentionally perform CPU- or I/O-intensive work as part
of their legitimate function — PDF generation, image resizing/thumbnailing,
report exports, data export-to-CSV jobs, password-hashing-heavy operations,
or synchronous third-party data aggregation. If these endpoints are not
rate-limited proportionally to their cost (or not queued asynchronously with
a sane concurrency cap), an attacker can trigger many of them in parallel.

### 4.2 Example Request — Piece by Piece

```
POST /api/v1/reports/generate HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "report_type": "full_account_history",
  "format": "pdf",
  "date_range": {"start": "2015-01-01", "end": "2026-07-06"}
}
```

Breakdown:
- `/reports/generate` — a legitimate feature endpoint, not a hidden one.
  Nothing here is malformed.
- `"report_type": "full_account_history"` and an 11-year `date_range` — the
  attacker deliberately selects the **largest legitimate scope** the
  endpoint's own schema allows, rather than any abnormal value. The resource
  exhausted is **server CPU/memory for report generation and, often,
  synchronous PDF rendering**, plus whatever database query underlies
  pulling 11 years of history in one call.
- The key exploitation move is **concurrency**, not payload manipulation:
  fire this exact same legitimate request 20–50 times in parallel from a
  single account. If the endpoint processes report generation synchronously
  within the request-handling thread (rather than dispatching to a queued
  background job with a concurrency cap), each parallel call competes for
  the same limited worker pool.

### 4.3 Why the API Has No Protection

- The endpoint was likely designed for occasional, single-user, ad hoc use
  (a user exporting their own report a handful of times) and the team never
  modeled what happens if 50 requests hit it in the same second — because
  from a *functional* testing perspective, "does it generate a correct PDF"
  passes fine, and load characteristics were never captured in scope.
- Synchronous processing is often chosen for simplicity (return the file
  directly in the response) instead of asynchronous job-queue processing
  (return a job ID, poll for completion), and rate limiting is rarely
  applied per-endpoint-cost — most gateway configs apply a flat request/sec
  limit across an entire API surface, not aware that this one route is
  10,000x more expensive per call than a simple `GET /profile`.

### 4.4 Proving Impact

- Time a single call to establish baseline cost (e.g., 3–5 seconds for a
  full history PDF).
- Fire 20–50 concurrent calls from the same authenticated session and
  measure: (a) whether all still complete, just slower, or some start
  timing out/erroring; (b) whether unrelated endpoints on the same API
  degrade during the burst.
- If the backend uses autoscaling infrastructure, note that this technique
  can also function as a **cost-abuse** finding distinct from a pure
  availability finding — sustained concurrent triggering of expensive
  compute can materially increase the target's cloud infrastructure bill,
  which is a valid and often high-severity impact framing for a bug bounty
  report, separate from the "site went down" framing.

### 4.5 PortSwigger Lab Mapping

- **Apprentice**: No dedicated lab for computation-cost abuse.
- **Practitioner**: No dedicated lab for computation-cost abuse.
- **Expert**: None currently published.
Honest gap disclosure: PortSwigger Academy has no labs modeling
"expensive-endpoint concurrency abuse" as a distinct technique — their
closest adjacent material covers business logic flaws around workflow
limits (found under the Business Logic Vulnerabilities topic), which
teaches the mindset of "find the endpoint's most expensive legitimate
parameter combination" even though none of those labs frame it explicitly
as a resource-exhaustion / Denial of Wallet exercise. crAPI does not
currently model this specific technique either — this is a technique best
practiced against a personal lab or with explicit client authorization on
a real target's staging environment.

---

## 5. crAPI Supplementary Practice for This File

crAPI (Completely Ridiculous API) is useful here specifically for its
**community/forum post and product endpoints**, which in various crAPI
challenge configurations expose list/pagination parameters with weak or
absent server-side caps, providing a safe environment to practice the
pagination-limit-abuse technique from section 1 without needing client
authorization. crAPI does not currently model ReDoS or expensive-computation
endpoints, and its file upload functionality (profile picture upload) is
more commonly used for content-type/path-traversal exercises than for
size-based exhaustion — treat crAPI as a partial supplement to this file,
not a complete substitute for the gaps noted in sections 2–4.

---

## 6. WAF / API Gateway Detection & Bypass Considerations (Resource Exhaustion Specific)

### 6.1 How Gateways Typically Detect This Pattern

- **Volumetric thresholds**: fixed/sliding window counters per API key, IP,
  or token (e.g., "100 requests/minute per token").
- **Payload-size inspection**: gateways commonly reject requests exceeding a
  configured `Content-Length` before the body is even fully read, when
  configured correctly.
- **Response-time anomaly detection**: some modern gateways (and WAF products
  with behavioral modules) track per-route p95/p99 latency and flag routes or
  clients whose requests cause outlier processing time — this is the
  specific control most relevant to ReDoS and expensive-computation abuse,
  since request *count* alone doesn't reveal these.
- **Query-cost estimation**: primarily seen in GraphQL gateways (query
  complexity/depth scoring) but increasingly appearing in REST gateways
  that inspect known "expensive" query parameters (like `limit`) and apply
  parameter-specific caps rather than a flat per-route limit.

### 6.2 Bypass Considerations Specific to Resource Exhaustion (not generic rate-limit bypass)

- **Splitting cost across parameters**: if a gateway caps `limit` at a
  reasonable value but does not cap `offset` combined with repeated calls,
  an attacker can achieve the same aggregate data-pull cost via many
  moderate-sized paginated calls instead of one oversized one — defeating a
  gateway rule that only pattern-matches on the `limit` parameter's raw
  value, since no single request looks abnormal.
- **Staying under payload-size inspection by using compression**: a gateway
  that inspects `Content-Length` pre-decompression can be bypassed by a
  small gzip/deflate-compressed body that expands to a much larger
  decompressed size server-side (a "decompression bomb" concept) — relevant
  specifically to file-upload and JSON-body resource exhaustion, since the
  gateway's visible request size does not reflect actual processing cost.
- **Distributing expensive-computation calls across time just under
  anomaly-detection windows**: if latency-anomaly detection resets its
  baseline every N minutes, spacing expensive calls just outside the
  detection window (rather than firing all concurrently) can avoid tripping
  the specific behavioral trigger while still accumulating cost/impact over
  a longer test window — this is a timing consideration unique to
  cost-based detection, distinct from the IP-rotation/header-spoofing
  techniques covered in the dedicated Rate Limit / Bot Protection Bypass
  series.
- For all generic bypass mechanics (rotating source IPs, spoofing
  `X-Forwarded-For`, randomizing User-Agent/TLS fingerprints), see the
  **Rate Limit / Bot Protection Bypass series** — not repeated here to avoid
  duplication.

### 6.3 Real-World Note

Query-cost-aware gateways are still relatively immature compared to simple
volumetric rate limiting — in practice, most real-world findings in this
category succeed not because of a clever bypass, but because **no
cost-aware control was configured at all**, only a flat request-count limit
that resource-exhaustion techniques are specifically designed to slip under
(few requests, high cost-per-request). Don't over-invest in bypass technique
before first confirming a cost-aware control actually exists to bypass.

---

Proceed to `03_Third_Party_Spending_Abuse.md` for the Denial-of-Wallet
category of this vulnerability class.
