# BOPLA — Broken Object Property Level Authorization
## OWASP API Security Top 10 2023 — API3
### File 1 of 6: Overview and Core Concepts

---

## 1. What BOPLA Is

BOPLA stands for **Broken Object Property Level Authorization**. It is a 2023 addition to
the OWASP API Security Top 10 that formally **merges two vulnerability classes from the
2019 list**:

| 2019 OWASP API Top 10 | 2023 Merge Target |
|---|---|
| API3:2019 — Excessive Data Exposure | **API3:2023 — BOPLA** |
| API6:2019 — Mass Assignment | **API3:2023 — BOPLA** |

OWASP merged these because they are **two sides of the same root cause**: the API fails
to enforce authorization **at the level of individual object properties** (fields), not
just at the level of the object as a whole or the endpoint as a whole.

This distinguishes BOPLA from its sibling vulnerabilities:

- **BOLA (API1)** — can I access *someone else's object* (e.g. `/api/users/124` when I am
  user 123)?
- **BFLA (API5)** — can I call a *function/endpoint* I'm not authorized to use (e.g. an
  admin-only endpoint)?
- **BOPLA (API3)** — even on an object I *am* authorized to access, can I read or write
  **individual properties/fields** I should not be able to?

BOPLA is a property-level authorization failure, not an object-level or function-level one.

---

## 2. The Two Sub-Types

### 2.1 Excessive Data Exposure (read direction)

The API returns **more fields than the client needs or should see**. This typically
happens because the backend serializes an entire internal object (an ORM model, a
database row) directly into the HTTP response, and relies on the **frontend** to decide
which fields to display — rather than the **backend** deciding which fields to send.

Mechanism, in one sentence: the server does the equivalent of `return jsonify(user.__dict__)`
instead of `return jsonify({"id": user.id, "name": user.name})`.

Common exposed fields that shouldn't leave the server:
- Password hashes, password reset tokens, MFA secrets
- Internal/sequential database IDs (useful for enumeration and BOLA chaining)
- Full PII beyond what the UI needs (national ID numbers, DOB, full address)
- Internal flags: `isAdmin`, `role`, `permissions`, `internal_notes`, `risk_score`
- Session tokens or API keys belonging to other flows
- Soft-deleted / draft data that should be filtered out

The critical point for testing: **the UI not displaying a field proves nothing about
whether the API response contains it.** The UI is a rendering choice made in JavaScript,
running entirely client-side, after the full JSON has already arrived in the browser. Any
field present in the raw response is already exposed to the attacker regardless of what
the rendered page shows.

### 2.2 Mass Assignment (write direction)

The API **binds incoming client-supplied fields directly onto an internal object** without
an explicit whitelist of which fields are allowed to be set by that specific caller, in
that specific context. If the attacker adds a field the developer didn't anticipate, and
that field happens to match an internal property name, the framework/ORM will often set
it — silently, because "binding all provided fields" is the *default* behavior of most
web frameworks and ORMs, not an opt-in.

Mechanism, in one sentence: the server does the equivalent of
`user.update(**request.json)` instead of
`user.update(name=request.json["name"], email=request.json["email"])`.

Classic exploitable fields: `isAdmin`, `role`, `is_verified`, `balance`, `credit`,
`account_type`, `permissions`, `price` (on an order line item), `status` (on an
approval workflow).

---

## 3. Why This Happens by Default — The ORM/Framework Root Cause

This is the part worth understanding deeply, because it explains *why* this bug is so
common across unrelated codebases, languages, and frameworks.

Most modern web frameworks and ORMs are built around **convenience-first data binding**.
Their design goal is: "the developer shouldn't have to manually map every JSON field to
every model attribute." So frameworks provide helpers that do this automatically:

- Ruby on Rails (pre-4.0 default, and still available via `Model.new(params)`):
  `ActiveRecord::Base` mass-assigns any hash of attributes passed to `.new()`, `.update()`,
  `.update_attributes()`, unless `attr_accessible` / strong parameters are explicitly used.
- Django REST Framework: a `ModelSerializer` will map every field on the model into the
  serializer unless `fields` (whitelist) or `exclude` (blacklist) is explicitly set — and
  `exclude` is inherently fragile because it forgets to exclude *new* fields added later.
- Spring / Jackson (Java): `@RequestBody User user` deserializes the entire incoming JSON
  body directly onto the `User` entity's setters. Every setter Jackson can find, it will
  call.
- Node.js / Mongoose: `Model.findByIdAndUpdate(id, req.body)` passes the raw request body
  straight into the update operation. Every key in `req.body` becomes a `$set` operation.
- PHP / Eloquent (Laravel): `Model::create($request->all())` or `$model->fill($request->all())`
  will mass-assign any field present in `$fillable` (or all fields if `$guarded` is empty).

The pattern across every one of these: **binding is opt-out, not opt-in, unless the
developer takes an extra step.** The extra step (strong parameters, DTOs, explicit
serializer field lists, `$fillable` arrays, `@JsonIgnore`) is the security control. If a
developer forgets it, adds a new sensitive field to the model later without updating the
whitelist, or copies boilerplate code from an unrelated part of the app, the binding
silently becomes exploitable.

This is also why BOPLA is so persistent across large codebases: a single correctly
whitelisted endpoint proves nothing about a sibling endpoint using the same model. Each
`POST`/`PUT`/`PATCH` handler that touches the same object needs its **own** independent
field-level authorization check.

---

## 4. Why WAF / API Gateway Bypass Is Largely Not Relevant to BOPLA — And Where It Is

This is called out explicitly, per this series' convention of never silently omitting
WAF/gateway considerations.

**Excessive Data Exposure** is a **response-side, semantic authorization defect**. The
HTTP request that triggers it is completely benign — often it is the exact same
`GET /api/users/123` request the legitimate frontend sends. There is no malicious payload,
no anomalous syntax, no injection string for a WAF to pattern-match against. A WAF/API
gateway operates on request inspection (and sometimes response inspection for known
sensitive-data patterns like credit card numbers or SSNs via DLP rules), but it has no way
to know that a `password_hash` field in a 200 OK JSON response is "unauthorized" for this
particular caller — that requires business-logic-aware, schema-level knowledge the gateway
does not have unless it is explicitly configured with **response schema validation /
allow-listing** (which some modern API gateways like Kong, Apigee, or AWS API Gateway with
a defined OpenAPI/JSON Schema response model *can* enforce). Where this is deployed, it is
a legitimate mitigation, not a bypassable WAF signature. **For this sub-type, testing
methodology should not spend effort on WAF evasion — it is the wrong control to look for.**

**Mass Assignment**, by contrast, is a **request-side property injection**, and here
gateway/WAF relevance genuinely exists, so file 4 of this series (filter bypass
techniques) contains a dedicated section on:
- How WAFs/API gateways commonly detect mass assignment attempts (JSON schema/field
  allow-listing at the gateway, known sensitive field-name blocklists, parameter counting
  anomaly detection).
- Realistic bypass considerations (alternate casing, nested objects, array wrapping,
  content-type switching, parameter pollution) that exploit the gap between what the
  gateway inspects and what the backend actually parses.

**CSV/Formula Injection** (file 5) is also request-side (the payload is submitted in a
normal text field) but the "attack" only fires client-side in a spreadsheet application
after export — so gateway relevance there is limited to detecting the *leading formula
characters* (`=`, `+`, `-`, `@`) in submitted field values, which is covered in that file
with honest caveats about false-positive rates on legitimate data (e.g., a user's legal
name starting with a hyphen, or a maths-related comment).

---

## 5. Real-World Framing

BOPLA-class bugs are among the most commonly reported API vulnerabilities in bug bounty
programs, precisely because they require zero exotic tooling — Burp Repeater and a
text editor are sufficient. Representative real-world patterns:

- **T-Mobile API breach (2023)**: an unauthenticated API endpoint exposed full customer
  PII (names, addresses, account numbers) far beyond what the mobile app's UI ever
  rendered — a textbook Excessive Data Exposure case affecting ~37 million accounts.
- **Peloton API (2021)**: the `/api/user/{id}` endpoint returned full profile data
  including private account details for *any* user ID, even when the querying user's
  privacy settings were set to private — again, response over-exposure independent of UI
  rendering.
- Mass assignment has repeatedly surfaced in e-commerce and fintech APIs where a
  `PATCH /api/orders/{id}` or `PATCH /api/account` endpoint accepted attacker-supplied
  `price`, `discount`, `role`, or `balance` fields that the frontend never exposed as
  editable — because the backend trusted "the frontend won't send that field" instead of
  enforcing it server-side.

The common thread: **the vulnerability lives entirely server-side.** The frontend
behaving correctly is irrelevant to whether the API is vulnerable.

---

## 6. crAPI Coverage for This Topic

[crAPI](https://github.com/OWASP/crAPI) (Completely Ridiculous API) is OWASP's
intentionally vulnerable API training application and is used throughout this series as
supplementary practice where PortSwigger's lab coverage has gaps (explained per-file).
Relevant crAPI challenges for BOPLA:

- **Excessive Data Exposure**: the `/identity/api/v2/user/dashboard` and vehicle location
  endpoints return more vehicle/user data than the mobile app UI displays, including
  internal identifiers usable for further BOLA chaining.
- **Mass Assignment**: the community forum "post" and user-profile-update endpoints in
  crAPI accept extra fields (e.g. manipulating a coupon/discount value or a user role
  field on profile update) that are not present in the documented request schema.

Exact endpoint paths can shift between crAPI releases — always confirm against the
version you deploy locally (`docker-compose up` from the official repo) rather than
trusting a fixed path from memory.

---

## 7. What the Rest of This Series Covers

| File | Content |
|---|---|
| 2 | Excessive Data Exposure — testing methodology (response vs UI field comparison, role comparison) |
| 3 | Mass Assignment — testing methodology (systematic field injection across POST/PUT/PATCH) |
| 4 | Mass Assignment — filter bypass techniques (alternate names, nesting, content-type switching) + WAF/gateway detection & bypass |
| 5 | CSV/Formula Injection via data export features (mechanism, safe testing, 2025 CVEs) |
| 6 | Final consolidated cheatsheet |

Continue to **File 2 — Excessive Data Exposure Testing Methodology**.
