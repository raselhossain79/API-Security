# REST API Testing Methodology — 05: Response Differential Analysis

## Mechanism: why differential comparison finds what single requests don't

Every technique in Files 02–04 (method variation, version variation, content-type variation) produces a *single* interesting response in isolation. The actual vulnerability — an authorization gap, an information leak — is almost never visible in one response alone. It's visible **only when you place two responses side by side and the difference between them shouldn't exist.**

This is the core discipline of differential analysis: hold every variable constant except one, change that one variable, and treat any unexplained difference in the response as a lead worth investigating. The "one variable" is usually one of:

- **Role/privilege** (same endpoint, low-privilege token vs. high-privilege token vs. no token)
- **Content-type** (same logical request, different `Content-Type` header — direct continuation of File 04)
- **Parameter value** (same endpoint, a value that should be rejected vs. one that should be accepted, or two values that should return identically-shaped-but-different data)

Without a recorded baseline (File 01, Step 4), you have nothing to diff against — this is why baseline establishment isn't optional groundwork, it's the literal first half of every comparison in this file.

## Step-by-step, piece by piece

### A. Role-based differential

**Step 1 — Send the identical request under three roles: unauthenticated, low-privilege, high-privilege.**

```
GET /api/orders/1001 HTTP/1.1
Host: api.target.com
(no Authorization header)
```
```
GET /api/orders/1001 HTTP/1.1
Authorization: Bearer <low-privilege-token>
```
```
GET /api/orders/1001 HTTP/1.1
Authorization: Bearer <high-privilege-token>
```

What each response tells you, field by field:
- **Status code difference** — unauthenticated returning `200` where you expected `401` is the most severe and most obvious finding; don't assume this is already covered just because it seems too obvious — it's exactly the kind of gap that's easy for developers to introduce on a single overlooked route.
- **Response body field differences** — if the low-privilege and high-privilege responses return a *different set of JSON fields* for the same resource ID, examine whether the extra fields returned to the high-privilege caller are ever exposed to the low-privilege caller through a *different* endpoint or method (this is a broken-access-control pattern, not merely a display-layer choice) — cross-reference your broken access control series for exploitation depth once you've located the discrepancy here.
- **Response body field *presence* vs *value***: sometimes a field is present in both responses but only populated with real data for the higher-privilege caller and returns `null`/empty for the lower-privilege caller — this is a *correct* differential (the control works) and you should note it as such rather than flag it, so you don't waste further testing time on a false lead. Differential analysis exists to find where controls are inconsistent, not to flag every observed difference as a bug.

**Step 2 — Vary the resource ID under a single role, not just the role under a single ID.**

```
GET /api/orders/1001 HTTP/1.1
Authorization: Bearer <user-A-token>
```
```
GET /api/orders/1002 HTTP/1.1
Authorization: Bearer <user-A-token>
```

What this tests: whether User A's token can retrieve Order 1002 (assuming it belongs to a different user) at all — this is the object-level authorization check (full BOLA exploitation techniques are covered in your dedicated BOLA/API1 series; this step is about using differential comparison specifically to *notice* the gap before pivoting into that series' deeper exploitation methodology).

### B. Content-type differential (direct extension of File 04)

Send the same logical request as JSON and as XML under the *same* role, and diff specifically for:

- **Field count/shape differences in the response** — an XML response occasionally includes internal/debug fields a JSON serializer strips by convention (different serialization libraries handling the same internal object differently).
- **Error verbosity differences** — as covered in File 04 Step 5, but now formalized as a deliberate diff rather than an incidental observation.

### C. Parameter-value differential

**Step 1 — Boundary-value pairs.**

```
GET /api/reports?user_id=1001 HTTP/1.1
```
```
GET /api/reports?user_id=1001'  HTTP/1.1
```

What this tests: comparing a clean baseline against a single-character injection probe is the standard technique for detecting SQL/NoSQL/command injection signal (full exploitation belongs in your dedicated injection series) — but the *differential* framing matters here specifically: don't just look at whether the second request errors, compare *exactly what changed* (status code, response time, response body length, error message content) against the first, one field at a time.

**Step 2 — Type-confusion pairs.**

```
{"user_id": 1001}
```
vs.
```
{"user_id": "1001"}
```
vs.
```
{"user_id": ["1001"]}
```

What this tests: whether the backend's type coercion behaves identically across a number, a numeric string, and an array containing that string — inconsistent handling here is a common source of authorization or validation bypass in loosely-typed backend languages (this pairs directly with array/type-confusion fuzzing covered in more depth in File 06).

**Step 3 — Enumerated parameter differential (systematic sweep, not spot-check).**

For any parameter with a small, guessable value space (a `status` field, a `role` field, a `tier` field), send the full plausible range and diff responses across the entire set rather than testing one or two values:

```
GET /api/orders?status=pending
GET /api/orders?status=processing
GET /api/orders?status=admin_review
GET /api/orders?status=internal
```

What this tests: internal/administrative status values that were never meant to be client-selectable sometimes still work if the backend performs no allowlist validation on the parameter — the "internal-only" values are frequently never seen in any UI, meaning passive recon alone would never surface them; this only comes from systematically enumerating the value space and diffing the result set returned for each.

## Building a repeatable differential workflow in Burp

- Use **Burp Repeater's tab-grouping** (introduced in File 01 setup) to keep every variant of a single logical request adjacent, so you can flip between tabs and diff visually rather than hunting through unrelated history.
- For larger comparison sets, export responses and use a text diff tool, or use **Burp's built-in "Compare" feature** (right-click two items in history → Compare) to get a structured visual diff of headers and body rather than eyeballing raw JSON.
- Record every differential result — including "no difference found, control is consistent" — in your working notes. A clean diff is evidence the control works and prevents you (or a teammate) from re-testing the same pair later in the engagement.

## WAF / API Gateway relevance for this file

Differential analysis itself is a **comparison methodology performed on responses you've already received** — it isn't a distinct request pattern that a WAF or gateway inspects and blocks, so there is no dedicated WAF detection/bypass mechanism specific to "differential analysis" as a technique. What *is* WAF/gateway-relevant is the traffic pattern generated while gathering the pairs to compare:

- Running the full parameter-value sweep in Step C.3 rapidly against the same endpoint can trip volumetric rate-limiting or scanning-signature detection identically to the method/content-type sweeps in Files 02 and 04 — the same pacing guidance applies (throttle Intruder threads, add delay, avoid single-burst sweeps against a monitored target).
- Where a WAF returns a **different block page or error format** depending on which rule matched, this is itself useful differential signal — a generic `403` for one payload category vs. a distinct block-page template for another can help you fingerprint which specific WAF rule triggered, informing which bypass techniques from Files 02/04/06 are worth trying next.

---

## PortSwigger lab mapping

**Honest gap disclosure:** PortSwigger does not have a lab built around "response differential analysis" as a named, standalone mechanic — it's a general testing discipline applied across many of PortSwigger's vulnerability categories rather than a category itself. The technique is exercised, not taught in isolation, inside labs from other topics you've already built series for:

| Related lab (from other topics, not this one) | Difficulty | Transferable skill |
|---|---|---|
| Labs in your Broken Access Control (A01) series involving user-ID comparison across accounts | Apprentice–Practitioner | Direct precedent for the role/resource-ID differential (Section A) |
| Labs in your Broken Authentication (API2) series involving response-based username enumeration | Apprentice | Direct precedent for using response differences (not just status codes) to infer backend logic |

There is no gap-filling needed *within the API testing topic specifically* here, because this file's technique is a cross-cutting methodology rather than a vulnerability class PortSwigger scopes a dedicated lab around — the skill transfers in from labs you've already mapped elsewhere in your library, which is the honest and accurate way to represent this rather than forcing an artificial API-testing-topic lab reference that doesn't exist.

### crAPI supplementary practice

- crAPI's shop/community services expose the same order/resource ID pattern used in Section A above across multiple simulated users — this is a stronger practice ground for role-based differential analysis specifically because crAPI ships with multiple pre-seeded user accounts of differing privilege, letting you build the full three-way (unauthenticated/low/high) comparison directly rather than needing separate lab instances per role.

---

## What's next

File 06 goes one level deeper than differential value pairs — systematic parameter fuzzing methodology specific to JSON body structure, nested objects, array injection, and hidden parameter discovery.
