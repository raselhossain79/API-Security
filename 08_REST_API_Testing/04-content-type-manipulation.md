# REST API Testing Methodology — Part 4: Content-Type Manipulation

## Series Position

This file assumes Parts 1–3 are complete. This file covers switching `Content-Type` (and, relatedly, `Accept`) between `application/json`, `application/xml`, `text/plain`, and other media types on the *same* endpoint, and explains precisely what behavioral changes each switch is designed to reveal.

---

## Why Content-Type Switching Is a Distinct Attack Surface

Most REST APIs are documented and consumed as JSON-only. But the underlying framework (Spring, ASP.NET, Django REST Framework, Express with body-parser middleware, etc.) very often supports multiple content-type parsers simultaneously, because that capability ships as a framework default rather than something a developer explicitly opts into per-endpoint. The developer builds and tests against JSON because that's what the documented client sends — but the XML parser, the form-urlencoded parser, or the permissive `text/plain`-as-fallback path is frequently still wired up underneath, untested, and unvalidated.

This creates two distinct classes of finding:

1. **Different parsers enforce different validation.** A JSON body might pass through a schema validator; the *same logical data*, sent as XML, might hit an entirely different code path that skips that validator, because the developer only wired validation into the JSON-specific handler.
2. **Some content types enable entirely different vulnerability classes.** XML parsing specifically opens the door to XXE (XML External Entity) injection — a vulnerability class that simply cannot exist if the endpoint only ever accepts JSON. If an endpoint accepts XML at all, it needs the full XXE testing methodology (covered in depth in the dedicated XXE series) applied to it, in addition to the checks in this file.

**Real-world framing:** content-type-switching findings are a frequent surprise in bug bounty programs specifically because they violate the assumption baked into the app's documented behavior — the documentation says "this API accepts JSON," and testers who trust that documentation completely never try anything else. The "spec says JSON" assumption is exactly the assumption this technique is designed to break.

---

## Step 1: Establish Which Content Types the Endpoint Actually Accepts

Do not assume — test directly. Take a baselined `POST`/`PUT`/`PATCH` request from Part 1 and resend it with each candidate `Content-Type`, translating the body into that format.

### 1.1 — Baseline (documented, working)

```
POST /api/v2/users HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
Content-Type: application/json

{"username":"testuser","email":"test@test.com"}
```

### 1.2 — XML Translation

```
POST /api/v2/users HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
Content-Type: application/xml

<?xml version="1.0"?>
<user>
  <username>testuser</username>
  <email>test@test.com</email>
</user>
```

**What this specifically tests:** whether the server has an XML parser wired up for this endpoint at all. Any response other than a clean `415 Unsupported Media Type` — meaning a `200`/`201`/`400`/`500` that shows evidence the body was actually parsed — confirms XML parsing is live. **If confirmed live, this endpoint must now be fully tested for XXE** (external entity injection, billion-laughs/entity-expansion DoS, SSRF-via-XXE) using the dedicated XXE methodology, since this file only covers *detecting* that the surface exists, not exploiting it.

### 1.3 — `text/plain` Translation

```
POST /api/v2/users HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
Content-Type: text/plain

{"username":"testuser","email":"test@test.com"}
```

Note the body content is *identical JSON text* — only the declared `Content-Type` header changed.

**What this specifically tests:** a well-known bypass pattern, particularly relevant to CORS and CSRF defenses. Many frameworks' body-parsing middleware is content-type-gated (only parse-as-JSON if `Content-Type: application/json` is declared) but some frameworks fall back to attempting a JSON parse regardless, or route `text/plain` bodies to a more permissive handler with fewer content-type-specific security checks attached. This specific test also matters enormously for **CSRF**: browsers do not apply CORS preflight requirements to "simple" content types including `text/plain`, meaning a cross-site form can send this exact request without triggering a preflight `OPTIONS` check — if the server accepts and processes a `text/plain`-declared JSON body the same as a proper `application/json` one, you may have just found a CSRF vector on an endpoint the developer assumed was CSRF-safe because "it only accepts JSON, and JSON requires a preflight." (Full CSRF chaining is covered in the dedicated CSRF series — this file's job is confirming the content-type acceptance that makes the chain possible.)

### 1.4 — `application/x-www-form-urlencoded` Translation

```
POST /api/v2/users HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
Content-Type: application/x-www-form-urlencoded

username=testuser&email=test@test.com
```

**What this specifically tests:** identical CSRF-relevant logic to Step 1.3 — `application/x-www-form-urlencoded` is also a CORS "simple" content type, exempt from preflight. It also tests whether the framework's form-parsing middleware (often enabled by default for traditional web-form support even in an API-primary application) exposes a parsing path with different validation than the JSON path — this is especially relevant for nested/array data, since form-encoding nested objects requires a different syntax (`user[email]=test@test.com`) that some parsers handle inconsistently compared to their JSON-parsing equivalent.

### 1.5 — Multipart Form Data

```
POST /api/v2/users HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOi...
Content-Type: multipart/form-data; boundary=----testboundary

------testboundary
Content-Disposition: form-data; name="username"

testuser
------testboundary
Content-Disposition: form-data; name="email"

test@test.com
------testboundary--
```

**What this specifically tests:** whether a multipart parser is wired up on an endpoint that documentation suggests is JSON-only — multipart parsing introduces its own distinct risk surface (file-upload-adjacent handling even on endpoints that don't look like upload endpoints, and multipart-specific parser vulnerabilities in some frameworks/library versions). Confirming multipart acceptance on an unexpected endpoint should prompt applying the File Upload vulnerability series' methodology, since some multipart parsers process file-like parts even when the endpoint's business logic never intended to accept files.

---

## Step 2: Comparing Validation Strictness Across Content Types

Once you've confirmed which content types are accepted (Step 1), the next question is whether **each** parser enforces the **same** validation. This is where actual findings come from — acceptance alone is often benign; validation *inconsistency* between accepted formats is the exploitable part.

### 2.1 — Methodology

Take a payload that is correctly **rejected** when sent as JSON (e.g., a value that fails a length check, a type that fails a schema check, a field that should be immutable), and send the semantically identical payload in each other accepted content type. Any content type that processes it successfully where JSON rejected it is a validation gap.

Example — testing whether a `role` field can be injected despite being blocked in the JSON path:

```
JSON (baseline, correctly rejected):
POST /api/v2/users
Content-Type: application/json
{"username":"testuser","email":"test@test.com","role":"admin"}
→ 400 Bad Request — "role is not a permitted field"
```

```
XML (test):
POST /api/v2/users
Content-Type: application/xml
<user><username>testuser</username><email>test@test.com</email><role>admin</role></user>
→ 201 Created, user created with role=admin
```

**What this specifically tests:** confirms the `role`-field blocklist/allowlist validation was implemented specifically inside the JSON deserialization/schema-validation code path (a very common pattern — validation libraries like `class-validator`, JSON Schema validators, or DTO-based validation in Spring/`.NET` are frequently bound only to the JSON body parser) and was never applied to the XML deserialization path, which may use an entirely different library or a more permissive direct-object-mapping approach. This is a **mass assignment vulnerability reachable specifically via content-type switching** — a direct, practical link to the Mass Assignment series' vulnerability class, discovered through this file's technique.

### 2.2 — Error Message / Stack Trace Differential

Send a deliberately malformed body in each accepted content type and compare error verbosity:

```
Malformed JSON:  {"username":"test"    ← intentionally unclosed
Malformed XML:   <user><username>test  ← intentionally unclosed
```

**What this specifically tests:** some frameworks have mature, well-tested error handling for their primary content type (JSON) that returns a clean, generic `400 Bad Request`, while a less-used parser (XML, form-encoded) throws an unhandled exception that bubbles up as a `500` with a full stack trace — leaking library names, versions, internal file paths, or ORM query fragments. This is a low-effort, high-value check to run on every content type you've confirmed as accepted, since it costs nothing beyond a single malformed request per type and can reveal information disclosure on parsers the development team clearly spent less hardening effort on.

---

## Step 3: Content-Type / Accept Header Mismatch Testing

Beyond what the *request* body is declared as, test mismatches between what you send and what you ask to receive:

```
POST /api/v2/users HTTP/1.1
Content-Type: application/json
Accept: application/xml

{"username":"testuser","email":"test@test.com"}
```

**What this specifically tests:** whether the response-formatting layer is separately implemented from the request-parsing layer, and whether that response layer has its own bugs — some frameworks' XML *serializers* (converting internal objects back to XML for the response) are more prone to leaking additional object fields than their JSON serializer, because JSON serialization was more carefully scoped (using explicit DTOs/response models) while XML serialization falls back to reflecting the full internal object graph by default in some library configurations. Compare the *fields present* in an XML-formatted response against the same resource's JSON-formatted response for over-exposure.

---

## Step 4: Malformed / Unexpected Content-Type Values

Beyond legitimate alternate content types, test nonsensical or unexpected `Content-Type` header values on the same JSON body:

```
Content-Type: application/json; charset=utf-7
Content-Type: application/json;;;
Content-Type: application/hal+json
Content-Type: APPLICATION/JSON
Content-Type: (empty / header omitted entirely)
```

**What each specifically tests:**
- `charset=utf-7` — a legacy encoding-confusion technique; some older parsing/XSS-filtering logic was built assuming UTF-8 and can be bypassed with alternate encodings that decode to the same dangerous characters after the fact. Low prevalence on modern stacks but effectively free to test.
- Malformed charset/parameter syntax (`;;;`) — tests whether the content-type parser fails open (defaults to attempting JSON parse anyway) or fails closed (`415`) — fail-open behavior widens your Step 1 content-type surface further.
- `application/hal+json` and other JSON-family vendor media types — tests whether content-type matching is done via exact string comparison (would reject this) or substring/prefix matching (`.includes('json')`), which is itself informative about how strict the framework's content-negotiation logic is and can predict whether unusual `vnd.` types will also be accepted.
- Uppercase `APPLICATION/JSON` — content-type matching should be case-insensitive per HTTP spec, but confirms whether the framework does this correctly (a functional check, not usually a security finding on its own, but occasionally reveals a fail-open path when case doesn't match a case-sensitive check and it falls through to a default/permissive parser).
- Omitted `Content-Type` entirely — tests the framework's default parsing behavior when no type is declared at all, which is sometimes JSON-by-default and sometimes a permissive raw-body handler.

---

## PortSwigger Web Security Academy Mapping

Correct difficulty-progression order for the concepts most directly exercised by this file:

1. **XXE injection → "Exploiting XXE using external entities to retrieve files"** — direct practice of confirming XML parsing is live (Step 1.2) and immediately following through on exploitation, which is the natural next step whenever this file's technique confirms XML acceptance.
2. **XXE injection → "Exploiting XXE to perform SSRF attacks"** — extends the same content-type-confirmation technique into a chained-impact scenario.

**Honest gap disclosure:** PortSwigger's academy does not have labs specifically modeling the mass-assignment-via-content-type-switching pattern in Step 2.1, nor the CORS-preflight-exemption CSRF angle in Step 1.3/1.4 as an API-specific scenario (their CSRF labs are built around traditional web forms, not JSON APIs). Practice these two techniques specifically against **crAPI**, which includes intentionally divergent parser validation across its endpoints, and against your own constructed test harness for the CSRF-via-simple-content-type pattern, since no current public lab isolates it cleanly in an API context.

---

## Summary — Content-Type Manipulation Checklist Per Endpoint

- [ ] Baseline JSON behavior recorded (from Part 1)
- [ ] XML acceptance tested — if live, full XXE methodology applied separately
- [ ] `text/plain` acceptance tested with identical JSON-shaped body — CSRF-preflight-exemption implication noted if accepted
- [ ] `application/x-www-form-urlencoded` acceptance tested, including nested-field syntax
- [ ] `multipart/form-data` acceptance tested on non-upload-looking endpoints
- [ ] Previously-rejected JSON payload replayed across every accepted content type to check validation consistency
- [ ] Malformed-body error verbosity compared across every accepted content type
- [ ] `Accept` header varied independently of `Content-Type` to check response-serializer field exposure
- [ ] Malformed/unusual `Content-Type` header values tested for fail-open parsing behavior

Proceed to **Part 5: Response Differential Analysis**.
