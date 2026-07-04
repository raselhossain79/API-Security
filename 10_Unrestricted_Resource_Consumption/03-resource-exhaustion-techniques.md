# Resource Exhaustion Techniques — Unrestricted Resource Consumption

**OWASP API Security Top 10 2023 — API4:2023**

This file covers exploitation techniques that exhaust a specific server-side resource
via one request or a small number of requests — distinct from file 02's detection
methodology and distinct from raw high-volume rate-limit bypass. Each technique here
targets a *different finite resource* (memory, disk, CPU, DB), and each section
explicitly states what resource is being exhausted and why the API failed to protect it.

---

## 1. Pagination Limit Abuse

### 1.1 The mechanism

Most list-returning API endpoints (`GET /api/users`, `GET /api/orders`, `GET
/api/transactions`) accept client-supplied pagination parameters — commonly `limit`,
`page_size`, `per_page`, or `count` — to let the client control how many records come
back per request. A correctly built endpoint enforces a **server-side maximum** on this
value regardless of what the client requests (e.g., cap at 100 even if the client asks
for 10,000). When that server-side cap is missing, the client parameter becomes a direct
lever on **database query cost, memory used to build the response object, and network
bandwidth used to transmit it.**

### 1.2 Baseline request

```
GET /api/v1/orders?limit=20&page=1 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
```

- Confirms the endpoint accepts a `limit` parameter and returns a normal, expected
  20-record page.

### 1.3 Exhaustion request

```
GET /api/v1/orders?limit=9999999&page=1 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
```

Breakdown:

- `limit=9999999` — requests nearly 10 million records in a single call. The exact
  number is arbitrary and deliberately absurd; the point of testing with an extreme
  value is to unambiguously prove there is no server-side ceiling at all, rather than a
  ceiling that's merely "higher than expected" (e.g., 500 instead of 100).
- **What resource is exhausted and why:** Three resources are hit simultaneously —
  (1) **database load**, because the underlying query (commonly `SELECT * FROM orders
  LIMIT 9999999`) forces the DB engine to read and prepare far more rows than any
  legitimate UI would ever render, holding a connection and CPU time on the DB server;
  (2) **application memory**, because the API layer typically deserializes the full
  result set into in-memory objects (ORM models, JSON-serializable structures) before
  writing the response, so memory usage scales linearly with record count; (3) **network
  bandwidth**, because the resulting JSON response could be hundreds of MB to GBs,
  consumed both server-side (egress) and client-side.
- **Why the API has no protection:** The developer implemented pagination as a
  *client convenience feature* (letting the frontend choose page size) without treating
  the parameter as untrusted input requiring server-side validation — a direct parallel
  to trusting any other client-supplied value without a bounds check.

### 1.4 Escalating to data exfiltration (chaining with BOLA)

```
GET /api/v1/orders?limit=9999999&page=1&user_id=* HTTP/1.1
```

- If the endpoint additionally fails to scope results to the authenticated user (a BOLA
  flaw, API1:2023), an unbounded `limit` turns a per-user information leak into a
  **full-table dump of every user's data in one request.** This is why pagination abuse
  and BOLA are so frequently chained in real bug bounty reports — the resource
  consumption flaw is what turns a scoped leak into a mass leak.
- Cross-reference the BOLA notes for the authorization-bypass half of this chain.

### 1.5 Alternate vector: negative or zero page size

```
GET /api/v1/orders?limit=-1 HTTP/1.1
```

- **What it does:** Some frameworks interpret `limit=-1` or `limit=0` as "no limit" at
  the ORM/query-builder level (a common convention in libraries like Sequelize, Django
  ORM, or raw SQL query builders where `-1` or absence of `LIMIT` is treated as
  "return everything").
- **Why it works when it works:** The application's input validation may check "is
  `limit` a positive integer under some sane bound," but forget to explicitly reject
  negative or zero values, which some ORMs then interpret as an unlimited-results
  instruction — an edge case the developer didn't anticipate.

### 1.6 Detecting the cap even when one silently exists

```
for L in 10 100 500 1000 5000 10000 50000 100000; do
  echo -n "limit=$L: "
  curl -s -o /dev/null -w "%{http_code} %{size_download} bytes %{time_total}s\n" \
    -H "Authorization: Bearer eyJhbGciOi..." \
    "https://api.target.com/api/v1/orders?limit=$L"
done
```

- Sweeps a range of `limit` values and records response size and time for each.
- **What you're looking for:** If response size stops growing proportionally past a
  certain value (e.g., it grows linearly up to `limit=500` then plateaus), the server
  is silently applying a cap even though it didn't reject the larger request outright —
  useful for confirming a *soft* cap exists, which is a materially different (better)
  finding than no cap at all, and should be reported accurately rather than overstated.

---

## 2. File Upload Size Abuse

### 2.1 The mechanism

File upload endpoints consume **disk space, memory (during upload buffering/processing),
and CPU (during any server-side processing like virus scanning, thumbnail generation,
or format conversion)**. Without an enforced maximum file size — checked *before* the
file is fully read into memory or written to disk — a client can submit an arbitrarily
large file and consume all three resources in a single request.

### 2.2 Baseline request

```
POST /api/v1/upload/avatar HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="avatar.jpg"
Content-Type: image/jpeg

[normal-sized JPEG bytes]
------WebKitFormBoundary--
```

### 2.3 Generating and sending an oversized file

```bash
# Generate a 2 GB file of null bytes
dd if=/dev/zero of=huge_avatar.jpg bs=1M count=2048

curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" \
  -X POST https://api.target.com/api/v1/upload/avatar \
  -H "Authorization: Bearer eyJhbGciOi..." \
  -F "file=@huge_avatar.jpg;type=image/jpeg"
```

Breakdown:

- `dd if=/dev/zero of=huge_avatar.jpg bs=1M count=2048` — `if=/dev/zero` reads from the
  null-byte device as the input source (fast, doesn't touch disk I/O for reading), `bs=1M`
  sets block size to 1 MB per write, `count=2048` writes 2048 blocks, producing exactly a
  2 GB file. Using `/dev/zero` instead of a real image is deliberate — the file's content
  is irrelevant to this test; only its size matters, and this generates it near-instantly
  without needing a real 2 GB image on hand.
- `-F "file=@huge_avatar.jpg;type=image/jpeg"` — curl's multipart form upload syntax;
  `@` tells curl to read the file from disk rather than treat the string literally, and
  `type=image/jpeg` sets the MIME type in the multipart header to match what a real
  avatar upload would send (relevant because some validation checks Content-Type before
  size, and you want to confirm the size check specifically, not accidentally trip a
  content-type filter instead).
- **What resource is exhausted and why:** If the server reads the entire multipart body
  into memory before checking size (common in frameworks that buffer the whole request
  body by default rather than streaming it), a single 2 GB upload can spike server
  memory by 2 GB+ per concurrent request — a handful of parallel uploads from one
  attacker can exhaust available RAM on a modestly provisioned instance. If the server
  streams to disk without a size check, repeated large uploads exhaust disk space
  instead, potentially crashing the service for all users once the disk fills.
- **Why the API has no protection:** The size limit, if any, is often enforced at the
  *application* logic layer (e.g., "check `file.size` after upload completes") rather
  than at the **web server / reverse proxy layer** (e.g., nginx's `client_max_body_size`,
  or the API gateway's request size limit) — meaning the expensive read/buffer/write
  work has already happened by the time the application-layer check runs and rejects it.
  A correct implementation rejects oversized uploads at the earliest possible layer,
  before the bytes are fully received.

### 2.4 Testing whether the cap is enforced early or late (timing signal)

```bash
for SIZE_MB in 1 10 50 100 500 1000; do
  dd if=/dev/zero of=test_$SIZE_MB.bin bs=1M count=$SIZE_MB 2>/dev/null
  echo -n "Size ${SIZE_MB}MB: "
  curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" \
    -X POST https://api.target.com/api/v1/upload/avatar \
    -H "Authorization: Bearer eyJhbGciOi..." \
    -F "file=@test_$SIZE_MB.bin"
  rm test_$SIZE_MB.bin
done
```

- **What you're looking for:** If rejection time scales up proportionally with file size
  (e.g., a 1000MB file takes ~10x longer to get rejected than a 100MB file), the server
  is reading the full body before rejecting it — the resource exhaustion already
  happened even though the end result is a rejection. A properly early-enforced cap
  rejects a 1MB file and a 1000MB file in roughly the same (fast) time, because it's
  checking `Content-Length` before reading the body at all.

---

## 3. Regex Complexity Attacks (ReDoS)

### 3.1 The mechanism

Many backtracking regex engines (used by default in most mainstream languages —
Python's `re`, JavaScript's native regex engine, Java's `Pattern`, PHP's PCRE) can
exhibit **exponential or high-polynomial time complexity** on certain crafted inputs
against certain vulnerable regex patterns — commonly patterns with **nested quantifiers**
or **ambiguous alternation** (e.g., `(a+)+$`, `(a|a)*$`, `([a-zA-Z]+)*$`). This is
"Regular Expression Denial of Service" (ReDoS). API endpoints that run user-supplied
input through such a pattern — validation regexes on email fields, username fields,
search inputs — become a **CPU exhaustion** vector: one crafted string can pin a single
CPU core at 100% for seconds, minutes, or effectively forever, using nothing but a
normal-looking API request.

### 3.2 Identifying a candidate endpoint

Look for any endpoint that performs regex-based validation or matching on user input,
commonly:

- Email/username format validation on registration
- Search/filter endpoints that use user input as (or within) a regex pattern
- Input sanitization/validation middleware applied broadly across many endpoints

### 3.3 Constructing the payload

```python
# Classic ReDoS trigger pattern for nested-quantifier vulnerable regexes
# e.g. vulnerable pattern: ^([a-zA-Z]+)*$
payload = "a" * 30 + "!"
```

- **What it does:** A string of 30 repeated `a` characters followed by one character
  (`!`) that does **not** match the pattern, forcing the regex engine to fail the match
  — but only after exhaustively trying every possible way to partition the 30 `a`
  characters among the nested groups first.
- **Why it works:** Against a pattern like `^([a-zA-Z]+)*$`, the outer `*` combined with
  the inner `+` creates ambiguity — there are exponentially many ways to split "aaaa...a"
  into one-or-more groups of one-or-more letters. A backtracking engine tries all of
  them before concluding failure. Each additional character in the input roughly
  **doubles** the number of combinations to try, so 30 characters isn't a large input,
  but it's enough to cause a multi-second-to-multi-minute hang depending on the exact
  pattern and engine.

### 3.4 Sending the payload as an API request

```bash
curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" \
  -X POST https://api.target.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$(python3 -c 'print("a"*35+"!")')\",\"password\":\"Test1234!\"}"
```

Breakdown:

- `$(python3 -c 'print("a"*35+"!")')` — generates the ReDoS payload inline (35 `a`
  characters plus a non-matching trailing character) and substitutes it directly into
  the JSON body via bash command substitution.
- **What resource is exhausted and why:** A single HTTP thread/worker handling this
  request pins one CPU core at 100% for as long as the regex backtracking runs. In a
  synchronous, thread-per-request server model, this can exhaust the available worker
  thread pool if a few requests like this arrive concurrently — each one occupies a
  worker indefinitely, and once all workers are stuck, the API stops responding to
  *any* client, not just the attacker. This is a full denial-of-service from a handful
  of small, individually-innocuous-looking requests.
- **Why the API has no protection:** The developer wrote a validation regex without
  auditing it for catastrophic backtracking (a subtle mistake — vulnerable patterns
  often look completely reasonable at a glance) and the runtime uses a backtracking
  regex engine with no per-match timeout configured. Non-backtracking engines (like
  Google's RE2, or Rust's `regex` crate) are immune to this class of attack by design,
  which is why "switch to RE2" is a standard remediation recommendation.

### 3.5 Measuring severity — escalating input length

```bash
for LEN in 20 25 30 35 40; do
  PAYLOAD=$(python3 -c "print('a'*$LEN+'!')")
  echo -n "Length $LEN: "
  curl -s -o /dev/null -w "%{time_total}s\n" \
    -X POST https://api.target.com/api/v1/register \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$PAYLOAD\",\"password\":\"Test1234!\"}"
done
```

- **What you're looking for:** Response time roughly doubling with each +1 to +5 added
  characters is the signature of exponential backtracking — this curve, not any single
  slow response, is what proves it's a genuine ReDoS rather than ordinary server load or
  network latency. Include this timing curve in a report as the primary evidence.

---

## 4. Expensive Computation Endpoint Abuse

### 4.1 The mechanism

Some API endpoints intentionally perform heavy server-side work per request — PDF/report
generation, image resizing or format conversion, data export, complex aggregate
calculations, ML/AI inference calls. These are legitimate features, but if they're
reachable with **no rate limiting and no queueing**, an attacker can trigger many of
them concurrently and exhaust CPU, memory, or downstream compute resources — including,
in cloud environments, driving up the target's compute bill directly.

### 4.2 Identifying candidate endpoints

Look for endpoint names/paths suggesting heavy work: `/api/v1/report/generate`,
`/api/v1/export`, `/api/v1/image/resize`, `/api/v1/analytics/recalculate`,
`/api/v1/pdf/create`. Confirm via response time on a single baseline request — anything
consistently taking multiple seconds is a candidate.

### 4.3 Baseline single request

```bash
curl -s -o /dev/null -w "%{time_total}s\n" \
  -X POST https://api.target.com/api/v1/report/generate \
  -H "Authorization: Bearer eyJhbGciOi..." \
  -H "Content-Type: application/json" \
  -d '{"report_type":"full_year","format":"pdf"}'
```

- Establishes that this single request already takes, for example, 4 seconds — a
  meaningful compute cost per call, and therefore a meaningful target for concurrency
  abuse.

### 4.4 Concurrent exhaustion request

```bash
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "Request $i: %{time_total}s\n" \
    -X POST https://api.target.com/api/v1/report/generate \
    -H "Authorization: Bearer eyJhbGciOi..." \
    -H "Content-Type: application/json" \
    -d '{"report_type":"full_year","format":"pdf"}' &
done
wait
```

Breakdown:

- `for i in $(seq 1 30); do ... & done` — the trailing `&` backgrounds each `curl` call,
  so all 30 requests fire **concurrently** rather than sequentially, which is the point:
  sequential requests to a slow endpoint just take a long time in total, but concurrent
  requests stack the CPU/memory load simultaneously, which is what actually exhausts a
  shared resource pool.
- `wait` — blocks the script until all backgrounded `curl` processes complete, so you
  can observe every request's completion time once the burst finishes.
- **What resource is exhausted and why:** 30 simultaneous PDF-generation jobs (or image
  processing, or aggregate DB calculations) compete for the same finite CPU cores and
  memory on the API server (or a shared job-processing backend). If each job normally
  takes 4 seconds running alone, running 30 concurrently on limited hardware can push
  each one's completion time to 30+ seconds or cause timeouts/crashes, and can degrade
  or fully deny the same endpoint for every other legitimate user during the attack
  window.
- **Why the API has no protection:** The endpoint was built assuming normal usage
  patterns (one user occasionally generating one report) without considering that
  nothing stops the same authenticated user — or, if the endpoint is reachable
  unauthenticated, anyone — from firing many requests concurrently. The fix pattern
  (queueing the job asynchronously with a per-user concurrent-job cap, rather than
  processing synchronously per request) is a standard, well-documented remediation for
  this exact issue.

### 4.5 Real-world framing

This is the exact mechanism behind **"Denial of Wallet"** attacks against serverless/
auto-scaling APIs: cloud functions (AWS Lambda, GCP Cloud Functions) that back an
expensive endpoint will auto-scale to handle a concurrency spike like the one in 4.4,
meaning the attack doesn't just slow the service down — it directly and measurably
increases the target's cloud compute bill for every concurrent invocation, which is why
this category is increasingly treated as a **financial risk**, not purely an
availability risk, in modern cloud-native API security assessments.

---

## 5. PortSwigger Lab Mapping (Progression Order)

As noted in file 02, PortSwigger Web Security Academy has **no dedicated labs** for
pagination abuse, file upload size abuse, ReDoS, or expensive computation endpoint
abuse — these are gaps in PortSwigger's catalog for this OWASP category. The closest
adjacent labs, in PortSwigger's progression order, are:

| Order | Lab | Relevance |
|---|---|---|
| 1 | *File upload vulnerabilities* → "Remote code execution via web shell upload" | Same upload endpoint surface, though focused on RCE rather than size-based DoS — useful for understanding upload validation flow generally |
| 2 | *Business logic vulnerabilities* → "Insufficient workflow validation" | General pattern of missing server-side limits on repeated/expensive actions |

**Honest gap disclosure:** For pagination abuse, ReDoS, and expensive computation
endpoint abuse specifically, there is no PortSwigger lab equivalent as of this writing.
Practice these against **crAPI** (section 6) or a deliberately built local test harness
(e.g., a small Flask/Express app with an intentionally vulnerable regex or unpaginated
endpoint) rather than expecting PortSwigger coverage.

---

## 6. crAPI Reference

- **crAPI's product listing and order history endpoints** are unpaginated or weakly
  paginated by design in some versions, making them a direct practice target for
  section 1 (pagination limit abuse).
- **crAPI's community/forum image upload feature** is a practice target for section 2
  (file upload size abuse) in a legal, intentionally vulnerable environment.
- For ReDoS (section 3) and expensive computation abuse (section 4), crAPI does not
  have a purpose-built vulnerable endpoint as of this writing — this is a genuine gap
  in crAPI's coverage as well, not just PortSwigger's, and is worth noting when
  documenting available practice environments for this category.

---

## 7. What to Carry Forward

File 04 covers the closely related but distinct category of **third-party spending
abuse** — where the exhausted "resource" is a paid external service's quota/dollar cost
rather than the API's own server-side compute.
