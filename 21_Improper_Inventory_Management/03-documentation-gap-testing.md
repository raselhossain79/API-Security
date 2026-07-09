# API9:2023 — File 3: API Documentation vs. Reality Mismatch Testing

## 1. Core Concept

This file covers a different failure mode from Files 01–02. There, the problem
was *endpoints that shouldn't be reachable at all still being reachable*. Here,
the problem is: **an endpoint is properly documented and intentionally exposed,
but what it actually does no longer matches what the documentation says it
does.** This happens because documentation is written once and rarely maintained
with the same rigor as code — a parameter gets added for a new feature, an
internal refactor changes what an endpoint returns, a security control gets
loosened for a support-desk workaround — and none of it makes it back into the
docs.

**Why this is a genuine security issue and not just a QA issue:** documentation
is frequently the *scope boundary* both testers and defenders use. A security
review that tests "what the docs say the endpoint does" and stops there will
systematically miss capability that exists only in the actual implementation.
This is inventory management applied at the *behavior* level rather than the
*existence* level — you know the endpoint exists, the question is whether you
actually know what it does.

## 2. Step-by-Step Methodology

**Step 1 — Extract the full documented contract for the endpoint.**
From the OpenAPI/Swagger spec, dev portal, or Postman collection, record:
- All documented parameters (query, path, body, header) and their types
- All documented required vs. optional fields
- Documented response schema (every field, every type)
- Documented HTTP methods
- Documented auth/scope requirements
- Documented rate limits and error codes

Treat this as your baseline — everything below is testing for deviation from it.

**Step 2 — Test for undocumented parameters.**
Send the documented request, then systematically add parameters not in the spec
and observe behavior differences:
```
POST /api/v4/users/42/profile
{
  "displayName": "test",
  "isVerified": true,
  "role": "admin",
  "internalFlag": true
}
```
If `displayName` is the only documented field, adding `isVerified`, `role`, or
`internalFlag` and observing that the response reflects the change (or that a
subsequent `GET` shows the field updated) confirms the server accepts
undocumented input — this is functionally a **mass assignment** finding
discovered *through* the documentation-gap lens; full exploitation methodology
is in your Mass Assignment notes, cross-referenced below.

*Signal to watch for even without an obvious privilege field:* any parameter
accepted silently (no `400` for unknown fields) suggests the framework doesn't
enforce a strict schema, meaning **every** undocumented parameter guess is worth
testing systematically, not just obviously sensitive-sounding field names.

**Step 3 — Test for undocumented response fields.**
Compare the actual response body against the documented schema field-by-field.
Any field present in the real response but absent from docs is a signal that:
- The backend model has grown since docs were last updated (common, often
  benign but sometimes leaks internal identifiers, cost/margin data, or
  other-user references)
- The response is inconsistent across different states of the resource — request
  the same endpoint across multiple different resource states (new vs. old
  record, different user roles, different subscription tiers) and diff each
  response against the others, not just against the docs, since undocumented
  fields sometimes only appear conditionally.

**Step 4 — Test undocumented HTTP methods.**
For every documented endpoint, test methods the docs don't mention:
```
OPTIONS /api/v4/users/42
```
Read the `Allow:` response header — this often lists every method the route
handler actually supports, regardless of what's documented. Then directly test
any undocumented method found:
```
DELETE /api/v4/users/42
PATCH /api/v4/users/42
```
A documented "read-only, GET-only" endpoint that silently accepts `DELETE`
because the underlying route handler was built generically (e.g. a framework
auto-generating full CRUD from a model definition, with only `GET` intentionally
surfaced in docs) is one of the highest-value findings in this file — it means
the actual attack surface is broader than the documented API implies across the
entire API, not just this one endpoint, and is worth systematically re-testing
across all documented endpoints once found once.

**Step 5 — Test documented rate limits and error handling for accuracy.**
Send requests at a rate exceeding the documented limit and confirm actual
enforcement. Discrepancies here (docs say 100 req/min, actual enforcement is
looser or absent) tie directly into your **API4 Unrestricted Resource
Consumption** notes — treat this step as the trigger to pull those notes back out
if a mismatch is found.

**Step 6 — Test documented auth/scope requirements for accuracy.**
If docs state an endpoint requires `scope:read:profile`, test with a token
missing that scope, and separately test with an entirely different scope, to
confirm the server actually validates the documented scope rather than merely
checking "is there a valid token at all." This is a targeted, single-endpoint
version of the broader authorization testing covered in your BFLA (API5) and
BOLA (API1) notes — use this step to flag candidates, then pursue full
exploitation there.

**Step 7 — Test documented input validation for completeness.**
Docs frequently state constraints ("`quantity` must be a positive integer") that
the implementation doesn't actually enforce. Test boundary and type violations
directly against the documented constraint:
```
{"quantity": -1}
{"quantity": 0}
{"quantity": "999999999999999999999"}
{"quantity": null}
```
Any accepted value the docs claim is invalid is a documentation-reality mismatch
with direct business-logic implications (negative quantities in an order/refund
flow are a classic real-world abuse case).

## 3. Real-World Notes

- The most consistently valuable finding from this methodology in practice is
  **undocumented methods on framework-auto-generated CRUD endpoints** (Step 4).
  Frameworks like Django REST Framework, Rails, and NestJS with auto-CRUD
  generators default to exposing full CRUD unless a developer explicitly
  restricts it — documentation reflecting "intended" read-only use is extremely
  common, actual restriction is not always applied.
- **Internal API documentation (Postman collections, internal wikis, Confluence
  exports) leaked or found via JS mining (File 02) is often *more* accurate than
  public-facing docs**, but can itself be stale relative to the current
  implementation — never treat any documentation source, public or internal, as
  ground truth. Ground truth is always the live behavior you observe.
- Documentation-reality mismatches are a common source of **false negatives in
  automated API security scanners**, because most scanners test against the
  provided OpenAPI spec exclusively — they will not discover behavior the spec
  doesn't declare. This is precisely why manual testing per this methodology
  remains necessary even when a client has run automated API scanning already;
  it's worth stating this explicitly in engagement scoping conversations.

## 4. WAF / API Gateway Relevance

Documentation-gap testing (this file) sits closer to File 01 than File 02 in
terms of WAF relevance: **most techniques here (parameter addition, method
testing, boundary value testing) do not resemble a brute-force or enumeration
attack pattern and generally will not trigger volumetric or pattern-based WAF
detection.** A single request adding an extra JSON field looks like a normal
request to a WAF/gateway; there's no signature to match and no anomalous rate.

The one exception is **Step 5 (rate limit accuracy testing)**, which by
definition involves sending a burst of requests and will interact with the same
rate-based detection covered in File 02's WAF section — refer there for
detection/bypass considerations rather than duplicating them here.

## 5. PortSwigger Web Security Academy Lab Mapping

| Difficulty | Lab | Relevance |
|---|---|---|
| Apprentice | *Exploiting an API endpoint using documentation* | Establishes the "read docs, test against them" baseline skill this entire file extends |
| Practitioner | *Exploiting a mass assignment vulnerability* | Direct hands-on practice of Step 2 (undocumented parameter acceptance) |
| Practitioner | *Discovering an insecure direct object reference / broken access control via documented vs actual scope* (broken access control lab set) | Practice for Step 6 (auth/scope accuracy testing) |
| Practitioner | *HTTP Verb tampering*-relevant labs (where present within access control lab set) | Direct practice of Step 4 (undocumented method testing) |

**Honest gap disclosure:** PortSwigger does not have a lab explicitly framed
around "compare documented behavior to actual behavior" as a standalone concept
— the underlying skill is distributed across the mass assignment and access
control labs above rather than packaged as its own topic. There is also no lab
specifically modeling documented-vs-actual rate limit testing (Step 5); for that,
rely on your API4 notes and crAPI below.

## 6. crAPI Supplementary Practice

- crAPI's shop and coupon-validation endpoints are documented at a basic level in
  its challenge materials but accept additional undocumented parameters in
  practice — directly usable for Step 2 and Step 7 practice (undocumented
  parameters and unenforced input validation).
- crAPI's vehicle-location and mechanic-workflow APIs are a good target for Step
  6 (scope/auth accuracy testing) since they involve multiple user roles
  (regular user vs. mechanic) with documented intent that doesn't always match
  enforced reality in the challenge design.

## 7. Cross-References

- Step 2 findings (undocumented parameters accepted) → full exploitation in your
  **Mass Assignment** notes.
- Step 5 findings (rate limits not enforced as documented) → your **API4
  Unrestricted Resource Consumption** notes.
- Step 6 findings (scope/auth not enforced as documented) → your **BOLA (API1)**
  and **BFLA (API5)** notes.
- Step 4 findings (undocumented methods, e.g. accepting `DELETE` on a
  "read-only" endpoint) → re-check against **CSRF** and **Broken Access
  Control** notes if the method performs a state change.
