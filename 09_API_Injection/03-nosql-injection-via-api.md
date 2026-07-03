# NoSQL Injection via API (MongoDB Operator Injection in JSON Bodies)

> Prerequisite: core NoSQL injection mechanics from the standalone NoSQL Injection
> series. This file focuses specifically on **operator injection through JSON API
> bodies**, which is the single most common real-world NoSQL injection variant
> because MongoDB's query language *is* JSON — meaning the injection technique here
> requires no escaping tricks at all once you understand the type-confusion
> principle. This is the most API-native injection class in this entire series.

## 1. Why This Is Fundamentally Different From SQLi-Style Injection

SQLi (file 02) works by breaking *out* of a string context using quote characters.
MongoDB operator injection works by exploiting the fact that **MongoDB queries are
themselves JSON/BSON documents** — so if an API takes user-controlled JSON and passes
it directly into a MongoDB query without validating the *structure* (not just the
string content), you don't need to "break out" of anything. You simply **replace an
expected scalar value with an object containing a MongoDB query operator**, and
MongoDB interprets that object as a query condition instead of a literal value to
match.

This means the entire class of injection here is a **type confusion** issue, not a
syntax-breaking issue — which is exactly why file 01's Section 1.3 (array/type-based
injection) flagged this as the foundational API-specific technique.

## 2. The Vulnerable Pattern

```javascript
// Vulnerable Node.js/Express + Mongoose-style handler
app.post('/api/login', async (req, res) => {
  const user = await db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password
  });
  // ...
});
```

The developer assumes `req.body.password` is always a string. Nothing in this code
enforces that assumption — Express's JSON body parser will happily hand `req.body`
whatever structure the client sent, including nested objects.

## 3. Basic Authentication Bypass — Payload Breakdown

### 3.1 Baseline (Legitimate) Request

```json
{
  "username": "admin",
  "password": "wrongpassword"
}
```

Normal behavior: `findOne` looks for a document where `username` equals `"admin"`
**and** `password` equals `"wrongpassword"` (exact string match) — no match, login
fails.

### 3.2 Injected Request

```json
{
  "username": "admin",
  "password": {"$ne": null}
}
```

**Breakdown, piece by piece:**

| Fragment | Role |
|---|---|
| `"username": "admin"` | Unchanged — targets a known or guessed valid username |
| `"password":` | The key the backend expects to hold a plain string |
| `{"$ne": null}` | Instead of a string, this is a **JSON object** containing the MongoDB query operator `$ne` ("not equal"). MongoDB interprets this as: match any document where the `password` field is not equal to `null` |

Because virtually every user document has a non-null `password` field, this
condition evaluates to **true for every document**, and `findOne` returns the first
matching user — typically the admin account, since the `username` filter is still
constraining the match to that specific user. The application logic then treats this
as "credentials matched" and issues a session, with the attacker never having
supplied a valid password at all.

**Why no JSON escaping is needed here:** unlike SQLi, you are not injecting a string
that needs to break out of quote delimiters. You are submitting **valid, well-formed
JSON** that simply has a different *type* (object) than the backend developer
assumed (string). The JSON parser has no complaint at all — this request is 100%
syntactically valid JSON. The vulnerability lives entirely in the backend's failure
to validate the *shape* of the input before using it in a query.

## 4. Other High-Value MongoDB Operators for API Testing

### 4.1 `$gt` / `$lt` — Greater Than / Less Than

```json
{
  "username": "admin",
  "password": {"$gt": ""}
}
```

**Breakdown:** `{"$gt": ""}` matches any password value greater than an empty
string in MongoDB's BSON type/value ordering — which is true for essentially any
non-empty string. Functionally equivalent to `$ne: null` for most schemas; useful as
a fallback if a WAF or input filter specifically blocks `$ne`.

### 4.2 `$regex` — Regular Expression Match (Blind Data Extraction)

This is the NoSQL equivalent of boolean-blind SQLi, and it can be used to
**exfiltrate data character-by-character**, not just bypass a boolean check.

```json
{
  "username": {"$regex": "^admin"},
  "password": {"$ne": null}
}
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `"username": {"$regex": "^admin"}` | Matches any username *starting with* `admin` — useful for enumerating usernames without knowing them exactly |
| `"password": {"$ne": null}` | Same bypass as before, chained so the request still results in a successful match |

**Extending `$regex` to extract secret field values** (e.g., a password reset token
stored in the same collection, assuming the API leaks a boolean signal like
"user found" vs "not found"):

```json
{
  "resetToken": {"$regex": "^a"}
}
```

If the API responds differently (200 vs 404, or a distinct error message) depending
on whether any document has a `resetToken` starting with `"a"`, you can iterate every
character position and every candidate character to reconstruct the entire token
value — one boolean oracle query per character tested, exactly analogous to blind
SQLi character extraction but using regex anchoring instead of `SUBSTRING()`
comparisons.

### 4.3 `$where` — Arbitrary JavaScript Execution (Server-Side)

Some MongoDB deployments/drivers still support the `$where` operator, which executes
arbitrary JavaScript server-side as part of query evaluation. This is the NoSQL
equivalent of a critical RCE-adjacent primitive, not just a filter bypass.

```json
{
  "username": {"$where": "this.username == 'admin' || '1'=='1'"}
}
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `{"$where": "..."}` | Passes a raw JavaScript expression string to MongoDB's JS engine for evaluation against every document |
| `this.username == 'admin' || '1'=='1'` | JavaScript logic evaluated per-document; `this` refers to the current document being scanned — the `|| '1'=='1'` tautology makes this true for every document, same bypass logic as SQLi but expressed in JS instead of SQL |

**Real-world note:** `$where` is disabled by default in modern MongoDB
configurations and is increasingly rare, but legacy deployments and some
self-managed MongoDB instances (especially those not upgraded since MongoDB 4.x-era
defaults) still have it enabled. Always test for it explicitly since its impact
(arbitrary JS execution server-side) is significantly higher severity than `$ne`/`$gt`
filter bypass.

## 5. Nested/Array Delivery Variants

Per file 01 Section 1.2–1.3, real API bodies are often nested. The same operator
injection applies at any depth:

```json
{
  "filters": {
    "user": {
      "credentials": {
        "password": {"$ne": null}
      }
    }
  }
}
```

If the backend passes `req.body.filters.user.credentials` (or similar) directly into
a query builder without flattening/validating it, the injection point is just as
exploitable four levels deep as it is at the top level — and manual testers
frequently miss these because automated scanners default to fuzzing top-level keys
only (as flagged in file 01).

## 6. Query Parameter Variant (Not Just JSON Body)

MongoDB operator injection isn't limited to JSON bodies — it also affects APIs that
parse query strings into nested objects (common with Express + the `qs` library,
which is the Express default query parser).

```
GET /api/users?username=admin&password[$ne]=null
```

**Breakdown:** the `qs` library parses `password[$ne]=null` into
`{ password: { '$ne': 'null' } }` — Express hands this parsed object to the route
handler exactly as if it had arrived via JSON body. This means **GET requests can
carry the exact same NoSQL injection primitive as POST/JSON bodies**, which is a
detail testers frequently miss because they associate "body injection" with POST
requests only. Always test query-string bracket notation against any GET endpoint
backed by MongoDB.

## 7. Testing Workflow (Burp)

1. Identify any endpoint whose JSON body includes fields that plausibly map to a
   database lookup (`username`, `email`, `token`, `id`, filter/search parameters).
2. In Repeater, replace the target string value with each operator payload from
   Section 3–4 in turn, keeping other fields at their baseline values.
3. Compare response status/body/timing against the baseline — a successful bypass
   often returns a 200 with a valid session/JWT where the baseline returned 401/403.
4. For `$regex` character-extraction, script the sweep with Intruder's Cluster Bomb
   or a short Python/requests script iterating position and candidate character,
   since this is inherently a multi-request blind extraction technique (dozens to
   hundreds of requests per secret value, same cost model as blind SQLi extraction).
5. Also test the **query-string bracket variant** (Section 6) against every GET
   endpoint that accepts filter-like parameters, not just POST/JSON endpoints.

## 8. PortSwigger Lab Mapping

**Gap disclosure:** PortSwigger Web Security Academy does not currently have a
dedicated NoSQL Injection lab category. There is no official PortSwigger lab
covering MongoDB operator injection as of this writing. For hands-on practice, use:

- **OWASP crAPI** — `crapi/community/api/v2/community/posts/recent` and related
  endpoints historically included NoSQL-relevant filter parameters (verify current
  state against your local crAPI deployment, as it evolves between versions).
- **NodeGoat** (OWASP) — includes a deliberately vulnerable MongoDB `$where`-based
  search feature, useful specifically for practicing Section 4.3.
- **DVWA** does not cover NoSQL injection (it is a MySQL-backed application) —
  do not expect this technique to apply there.

Practice the *general concept* of boolean/blind data extraction using PortSwigger's
**Blind SQL injection with conditional responses** lab first (same oracle-based
extraction logic, different query language), then transfer the extraction
methodology to a MongoDB target using `$regex` in place of `SUBSTRING()`/`LIKE`.

## 9. Real-World Notes

- This is consistently one of the highest-signal, lowest-effort findings in bug
  bounty programs targeting Node.js/Express + MongoDB stacks (a very common stack for
  startups and mobile app backends) — authentication bypass via `$ne`/`$gt` on a
  login endpoint is often a single-request finding once you know to look for it.
  This is also why several major npm frameworks and libraries have shipped
  mitigations (e.g., `express-mongo-sanitize`) specifically for this pattern —
  always check whether such middleware is present (its absence, or presence but
  misconfiguration on a subset of routes, is itself worth noting in a report).
- Mongoose (the most common MongoDB ODM for Node.js) applies **schema-level type
  casting** by default, which mitigates a large portion of this injection class —
  if a schema declares `password: String`, Mongoose will attempt to cast an incoming
  object to a string and typically fail/strip it rather than pass the operator
  through. This means the vulnerability is most commonly found in codebases using the
  **raw MongoDB driver directly** (`mongodb` npm package, no Mongoose schema layer)
  or in Mongoose schemas using `Schema.Types.Mixed` for the vulnerable field
  (common in loosely-typed "flexible" fields like search filters or metadata).
- Always check password-reset, "forgot password", and account-recovery endpoints in
  addition to login — these frequently reuse the same lookup pattern and are tested
  less rigorously than the primary login flow.
