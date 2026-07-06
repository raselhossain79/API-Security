# API Injection Testing — Overview & Delivery Context

## Purpose of This Series

This series does **not** re-explain injection mechanics (SQLi logic, NoSQL operator behavior,
command injection primitives, SSTI evaluation, XXE parsing). Those are covered in depth in
the existing web-application injection note series. This series is scoped narrowly to:

- How injection payloads are **delivered** through API endpoints (JSON bodies, nested
  objects, arrays) instead of classic form fields or URL parameters.
- How **testing methodology** changes when the transport is JSON/XML instead of
  `application/x-www-form-urlencoded`.
- How **WAF and API Gateway behavior** differs when inspecting structured body formats,
  and what that means for bypass technique selection.

If you need the underlying vulnerability theory (e.g. why `UNION SELECT` works, why
`$where` executes JS, why SSTI engines evaluate expressions), refer to the corresponding
file in the web-app series. This series assumes that knowledge and builds the API-specific
layer on top of it.

## Why API Injection Is a Distinct Testing Discipline

### 1. Delivery Format: JSON Body vs Form-Encoded

Traditional web app injection testing targets parameters delivered as:

```
username=admin&password=test123
```

Flat key-value pairs, URL-encoded, easy to fuzz character-by-character.

API injection testing targets parameters delivered as:

```json
{
  "username": "admin",
  "password": "test123"
}
```

This matters for three concrete reasons:

- **Structure-awareness required**: A payload injected into a JSON string value must
  respect JSON syntax rules (quote escaping, no raw control characters) or the request
  body will fail to parse *before* it ever reaches the vulnerable backend code. A broken
  JSON body gets rejected at the parser layer — you get a 400, not a SQL error. This is a
  common false-negative trap: testers assume "no error = not injectable" when the real
  issue is malformed JSON.
- **Content-Type dependency**: The backend parser (and any WAF in front of it) decides
  how to interpret the body based on the `Content-Type` header. Sending SQLi-style
  payloads with the wrong `Content-Type` (e.g. sending JSON with
  `Content-Type: application/x-www-form-urlencoded`) can cause the server to parse the
  entire JSON blob as a single form field name, silently breaking the test.
- **Escaping differs from URL encoding**: Form-encoded testing relies on URL-encoding
  reserved characters (`%27` for `'`). JSON testing relies on JSON string escaping
  (`\"`, `\\`, `\u0027` for Unicode-escaped characters). Applying URL-encoding logic to a
  JSON body is a common beginner mistake that produces silently-broken payloads.

### 2. Nested Object Parameters

APIs frequently deliver parameters several levels deep:

```json
{
  "user": {
    "profile": {
      "displayName": "test"
    }
  }
}
```

Web app testing tools built around flat parameter lists (classic Burp Intruder attack
positions on a form field) don't automatically "see" `displayName` as a distinct testable
parameter — it's nested three levels down inside a JSON tree. Practical implications:

- Every leaf string value in the JSON tree is a candidate injection point, not just the
  top-level keys. Testers must walk the full object graph.
- Some injection points only become reachable after understanding what the backend does
  with the parent object (e.g. an ORM might serialize `user.profile` as a whole and pass
  it into a raw query differently than a top-level field).
- Burp's JSON-aware Intruder payload positions (or the "Insertion point" detection in
  Burp's newer versions) and extensions like **Param Miner** help enumerate hidden/nested
  parameters automatically rather than manually tracing the tree.

### 3. Array-Based Injection

APIs also commonly accept arrays:

```json
{
  "tags": ["work", "urgent", "test"]
}
```

or arrays of objects:

```json
{
  "items": [
    {"id": 1, "qty": 2},
    {"id": 2, "qty": 5}
  ]
}
```

Array elements are individually testable injection points, and array-handling backend
code sometimes has different (weaker) validation than scalar field handling — for
example, an endpoint might sanitize `id` when it appears as a single top-level field but
fail to apply the same sanitization when `id` appears inside a looped array of objects,
because the validation logic was written per-endpoint rather than per-field-type.

### 4. Encoding Requirement Differences

| Context | Encoding for special characters |
|---|---|
| Form-encoded body | URL-encoding (`%27`, `%22`, `%3B`) |
| JSON string value | JSON escaping (`\'` not needed, `\"`, `\\`, `\u00XX`) |
| XML body (if Content-Type switched) | XML entity encoding (`&lt;`, `&amp;`, `&quot;`) |
| URL query string on an API endpoint | Still URL-encoding, even if the body is JSON |

A single API request can require **two different encoding schemes simultaneously** — for
example, URL-encoding in the query string plus JSON-escaping in the body. Missing this
distinction is one of the most common reasons a manually-crafted API injection payload
fails silently.

### 5. WAF Behavior Differences: JSON vs Form-Encoded

This is significant enough to warrant its own dedicated file (`06-waf-bypass-api-injection.md`),
but the high-level reason it matters here: many WAF rule sets were originally written
against form-encoded and query-string traffic patterns (signature matching against
`' OR '1'='1` style strings in flat parameters). When the same payload is nested inside a
JSON string value, wrapped in escaped Unicode, or split across a deeply nested object,
some WAF rule sets fail to normalize the JSON before signature matching — creating
detection gaps that don't exist against form-encoded equivalents. Conversely, some
API-Gateway-aware WAFs (built specifically for JSON/REST traffic) apply *stricter*
JSON-schema validation than a generic WAF would apply to a form body, occasionally
making API endpoints *harder* to bypass than equivalent web-app endpoints. Both
directions are covered in the WAF file — don't assume APIs are uniformly "easier" or
"harder" than web app forms; it depends entirely on which WAF/gateway product is deployed
and how its JSON parsing is configured.

## Where WAF/Gateway Relevance Applies Across This Series

Per the requirement to explicitly address WAF/Gateway relevance in every file rather than
silently omitting it: WAF/API Gateway behavior is **relevant to every vulnerability class
in this series** because the common thread across all of them (SQLi, NoSQLi, command
injection, SSTI, XXE) is that they are all delivered through the same JSON/XML body
transport layer, which is exactly the layer where WAF JSON-normalization gaps occur. So
rather than repeating a full WAF section in every vulnerability-specific file, each file
includes a short "WAF/Gateway note" specific to that vulnerability class, and the full
technique breakdown is consolidated in `06-waf-bypass-api-injection.md`. This avoids
duplicating the same Unicode-escaping/nested-JSON/content-type-switching techniques six
times while still making sure the consideration is never silently skipped.

## Real-World Framing

API injection is not a theoretical variant — it's the dominant delivery context in
modern applications:

- Mobile app backends are almost universally JSON REST or GraphQL, meaning every backend
  input a mobile app sends arrives as structured JSON, not form fields.
- Microservice architectures multiply the number of internal API endpoints (service-to-
  service calls), many of which have weaker input validation than public-facing
  endpoints because they were assumed to be "internal only" — a very common real-world
  finding in bug bounty and pentest engagements.
- API Gateways (Kong, AWS API Gateway, Azure APIM) sit in front of these endpoints and
  are frequently misconfigured to pass through raw bodies without inspection, or to
  apply schema validation only to declared fields — leaving undocumented/legacy fields
  in the same JSON body completely unvalidated.

## PortSwigger Lab Coverage Note (Honest Gap Disclosure)

PortSwigger Web Security Academy's injection labs (SQLi, NoSQLi, Command Injection,
SSTI, XXE) are almost all built around **traditional HTTP parameter delivery** (query
string, form body, cookie) rather than JSON REST API bodies specifically. There is
**no dedicated "API injection" lab category** on the Academy as of this writing.

This means the lab mapping in each file below is an **adapted mapping**: the underlying
vulnerability class and exploitation logic taught in a given lab transfers directly to
the API context, but you will need to manually convert the lab's request from
form-encoded/query-string to a JSON body shape to practice the API-specific delivery
skill. Each file calls out exactly which labs transfer well and where the gap is. Where
PortSwigger coverage doesn't exist for a specific API-context technique (e.g. NoSQL
injection via nested JSON operators has no PortSwigger lab at all), **crAPI** (Completely
Ridiculous API) and **OWASP DVWA-style NoSQL labs** are named as the alternative practice
environment, consistent with how gaps are handled in your other series.
