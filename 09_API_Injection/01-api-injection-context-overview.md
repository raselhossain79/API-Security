# API Injection Testing — Context & Methodology Overview

## Series Scope

This series is **not** a re-explanation of injection vulnerability classes. That
ground is already covered in depth in the standalone web application series (SQLi,
NoSQL Injection, OS Command Injection, SSTI, XXE, etc.). This series exists because
**the delivery mechanism changes the entire testing methodology** when the target is
a REST/JSON API instead of an HTML form.

The underlying vulnerability (e.g., unsanitized input reaching a SQL query) is
identical. What changes is:

- How the payload is structured and delivered
- Where in the request the injection point lives
- How the payload must be encoded to survive the transport format
- What tooling configuration is required to even see the injection point
- How the response is interpreted (APIs rarely render HTML back to you)

Treat this series as the "delivery layer" companion to the vulnerability-class deep
dives.

---

## 1. Why API Injection Differs From Traditional Web App Injection

### 1.1 Structured Data Delivery (JSON/XML) vs. Flat Form Encoding

A traditional HTML form submits data as `application/x-www-form-urlencoded`:

```
username=admin&password=test123
```

Every parameter is a flat key-value pair. Injecting into `password` means replacing
`test123` with a payload — the surrounding structure (`key=value&key=value`) stays
intact automatically because form encoding has no nesting, no data types, and no
syntactic delimiters beyond `&` and `=`.

An API request instead typically submits `application/json`:

```json
{
  "username": "admin",
  "password": "test123"
}
```

Here, the payload has to be injected as a **string value inside a structured
document**. This introduces a new failure mode that doesn't exist in form testing:
**breaking the JSON syntax itself**. If your injected payload contains an unescaped
`"`, a raw newline, or a stray `\`, the request body becomes invalid JSON and the API
will reject it with a `400 Bad Request` *before* your payload ever reaches the
vulnerable code path. You are debugging two layers at once — the JSON parser layer
and the downstream interpreter (SQL engine, shell, template engine) layer.

**Practical consequence:** every payload in this series is shown twice — first as
the raw injection string, then as it must appear *encoded inside the JSON value* so
the document remains syntactically valid JSON while still breaking out of its
*semantic* context downstream.

### 1.2 Nested Object Parameters

Web forms are flat. APIs frequently nest data several levels deep:

```json
{
  "user": {
    "profile": {
      "displayName": "test",
      "address": {
        "city": "Dhaka"
      }
    }
  }
}
```

An injection point can live at `user.profile.address.city` — four levels deep. This
matters for testing methodology because:

- Automated scanners that only fuzz top-level keys will miss nested injection points
  entirely. You often have to manually walk the object tree.
- Burp Suite's default parameter parsing (visible in the Params tab) does **not**
  automatically enumerate nested JSON keys the way it enumerates form fields or query
  parameters. You need the **JSON Beautifier** view or an extension (e.g., **Param
  Miner**, **JSON Web Tokens**, or manual body editing) to reliably target nested
  values.
- Nested objects also mean a single request can carry multiple independent injection
  points, each requiring separate baseline/error/time-based confirmation — don't stop
  at the first hit.

### 1.3 Array-Based Injection

APIs commonly accept arrays where forms would require repeated fields or wouldn't
support the concept at all:

```json
{
  "productIds": [101, 102, 103],
  "tags": ["electronics", "sale"]
}
```

Injection considerations specific to arrays:

- **Element-level injection**: replacing one array element with a payload
  (`"tags": ["electronics", "' OR '1'='1"]`).
- **Type confusion injection**: replacing an expected scalar with an array or object.
  This is a distinct and API-specific technique — for example, submitting
  `"password": {"$ne": null}` where the backend expects `"password": "somestring"`.
  This is the foundation of NoSQL operator injection (covered in file 03) and only
  exists because JSON supports rich types where form encoding does not.
- **Array length/structure abuse**: some backends iterate arrays and build dynamic
  queries (e.g., `WHERE id IN (1,2,3)`); injecting a non-numeric string into an array
  element can break out of the `IN (...)` clause the same way a single parameter
  would in a form-based `IN` clause, but the injection point is buried inside an
  array rather than a single named parameter.

### 1.4 GraphQL Field Injection

GraphQL APIs add another layer entirely. Instead of REST endpoints with fixed JSON
shapes, a single `/graphql` endpoint accepts a **query language** as its payload:

```json
{
  "query": "query { user(id: \"1\") { name email } }"
}
```

Injection-relevant differences:

- The injectable value (`id: \"1\"`) is itself embedded inside a string that is
  embedded inside JSON — a **double-encoding problem**. Your SQLi payload has to
  survive GraphQL string-literal escaping *and* JSON string escaping to reach the
  resolver's database call.
- GraphQL resolvers often pass arguments directly into ORM calls or raw queries per
  field, meaning a single query can have many independent injection points (one per
  argument, across nested fields/resolvers).
- Introspection (`{ __schema { types { name fields { name } } } }`) is itself a
  reconnaissance step unique to GraphQL — before injecting anything, testers use
  introspection to enumerate every field, argument, and type, effectively getting a
  full parameter map that REST APIs never hand you directly.
- Batching: GraphQL supports sending multiple queries/mutations in a single HTTP
  request. This is relevant for both efficient injection testing (many payloads, one
  request) and for rate-limit/business-logic bypass, though the latter is outside
  this series' scope.

GraphQL-specific injection testing is referenced here because it shares this
series' "structured delivery" theme, but a full GraphQL security series (IDOR via
resolvers, introspection abuse, batching attacks, DoS via query depth) is planned as
a separate track.

### 1.5 Encoding Requirements Are Different and Stricter

Form-encoded payloads only need to survive URL encoding (`&`, `=`, spaces, etc.).
JSON-delivered payloads need to survive **JSON string escaping** on top of whatever
downstream encoding the vulnerable sink requires. Concretely:

| Character | Meaning in JSON | Must be encoded as |
|---|---|---|
| `"` | closes the string | `\"` |
| `\` | escape character | `\\` |
| newline | breaks JSON string literal | `\n` |
| tab | breaks JSON string literal | `\t` |

If you copy a raw SQLi payload like `admin' OR '1'='1` from your web-app notes into a
JSON body without modification, it works fine (no double quotes in that particular
payload). But a payload like `1" OR "1"="1` will invalidate the JSON document unless
escaped as `1\" OR \"1\"=\"1`. Every payload file in this series marks this
explicitly.

Additionally, some APIs apply **Content-Type-dependent parsing**: the same endpoint
might accept `application/json`, `application/x-www-form-urlencoded`, and
`application/xml` depending on the `Content-Type` header sent, silently switching
parser (and therefore silently changing which injection techniques are even
reachable — see file 06 on XXE, which depends entirely on this behavior).

---

## 2. Tooling Adjustments for API Testing

### 2.1 Burp Suite Configuration

- **Proxy → HTTP History**: filter by `Content-Type: application/json` or
  `application/xml` to isolate API traffic from standard form/page traffic.
- **Inspector panel** (Burp 2023.x+): the JSON body is auto-parsed into an editable
  tree view — use this instead of manually counting braces when modifying nested
  values.
- **Repeater**: when sending JSON bodies through Intruder, use the JSON-aware payload
  position markers (`§`) placed *inside* the string value, never around the quotes,
  so encoding stays intact automatically. Example correct positioning:
  `"username": "§admin§"`.
- **Param Miner extension**: useful for discovering hidden/undocumented JSON keys
  API backends silently accept — this has direct injection relevance because
  undocumented parameters are frequently unvalidated.

### 2.2 Postman / Insomnia

Bug bounty and pentest workflows increasingly start from an OpenAPI/Swagger spec or
a Postman collection rather than manual crawling. Import the collection, then proxy
Postman traffic through Burp (`Settings → Proxy`) so every documented endpoint is
captured for systematic injection testing — this recon step matters because
undocumented parameter discovery (via fuzzing body keys) is a separate, necessary
step API testing requires that form-based testing usually doesn't (forms visibly
render their inputs; APIs don't).

### 2.3 Response Interpretation Differences

Web app SQLi/SSTI/etc. testing frequently relies on visual cues in rendered HTML
(error pages, reflected output, timing via page load). APIs typically return JSON
error bodies or empty responses, so testers rely more heavily on:

- HTTP status code deltas (500 vs 200/400)
- JSON error message content (many frameworks leak stack traces or DB driver errors
  directly in the JSON error body — a common real-world finding by itself)
- Response timing (time-based blind techniques are used more often against APIs
  precisely because visual/boolean feedback is often absent)
- Response body length/structure deltas between payloads

---

## 3. Real-World Industry Framing

API injection is not a theoretical concern — it is explicitly called out in the
**OWASP API Security Top 10** as **API8:2023 Security Misconfiguration** (which
covers XML/content-type confusion) and is a root cause underlying many findings
classified under **API3:2023 Broken Object Property Level Authorization** and
general injection findings that don't get their own API-specific category because
OWASP assumes testers apply the general **Injection** class (historically A03 in the
Web Top 10) across every input surface, JSON included.

In bug bounty programs, JSON body injection is one of the highest-value finding
categories because:

- Many WAF rulesets are tuned primarily for form/query-string SQLi patterns and
  under-inspect JSON bodies, especially nested ones.
- Mobile app backends (a huge bug bounty surface) are almost exclusively JSON APIs
  with no HTML forms at all — this series' techniques are the *primary* injection
  surface for that entire class of targets.
- Microservice architectures mean a single JSON body field can be relayed unmodified
  through multiple internal services before reaching a vulnerable sink, so a single
  injection point at the public API can compromise a downstream service the tester
  never directly interacts with.

---

## 4. PortSwigger Lab Mapping for This Series

PortSwigger Web Security Academy does not have a dedicated "API injection" category
— API-relevant labs are distributed across the SQL Injection, NoSQL Injection, and
OS Command Injection categories, but several are explicitly JSON-body-based and are
the correct starting point for this series. These are referenced individually in
each file's lab-mapping section; this overview file establishes the ordering
principle: **complete the equivalent web-app-context lab first if you haven't
already (per your existing series), then complete the JSON/API-context lab here to
isolate the delivery-layer differences.**

---

## 5. What's Covered Next

- `02-sqli-via-api.md` — SQLi through JSON bodies
- `03-nosql-injection-via-api.md` — MongoDB operator injection
- `04-command-injection-via-api.md` — OS command injection via API parameters
- `05-ssti-via-api.md` — Template injection through API string fields
- `06-xxe-via-api.md` — XXE via content-type confusion
- `07-methodology-and-cheatsheet.md` — Unified methodology and quick reference
