# NoSQL Injection via API Endpoints (MongoDB Operator Injection)

This file covers MongoDB-style NoSQL injection delivered through JSON API bodies. If your
web-app NoSQLi series covers the general theory, this file focuses on the API-specific
delivery mechanism: **the injection payload isn't a string breaking out of quotes — it's
a JSON object replacing an expected string, using MongoDB's query operators.**

## Why NoSQL Injection via API Looks Completely Different from SQLi

This is the most important conceptual difference in this entire series. SQLi (previous
file) works by breaking out of a string literal using quote characters. NoSQL injection
against MongoDB typically works by **replacing an expected scalar value with a JSON
object containing a MongoDB query operator** — no quote-breaking involved at all, because
the vulnerability lives in how the API layer passes JSON directly into a MongoDB driver
query without validating that the field is a plain string.

A normal, non-malicious login request:

```json
{
  "username": "alice",
  "password": "correctpassword"
}
```

Backend (vulnerable) code conceptually does:

```javascript
db.users.findOne({ username: req.body.username, password: req.body.password })
```

If `req.body.password` is taken directly from the parsed JSON body without type-checking
that it's a string, an attacker can submit:

```json
{
  "username": "alice",
  "password": {"$ne": null}
}
```

Breakdown of what changed and why it works:

- `"password":` — same key as before.
- `{"$ne": null}` — instead of a string value, this is a **nested JSON object** used as
  the value. `$ne` is a MongoDB query operator meaning "not equal to." When this object
  is passed into the `findOne` query, MongoDB interprets the whole query as
  `{ username: "alice", password: { $ne: null } }`, which reads as: "find a user named
  alice whose password is not equal to null" — which is true for any user that has a
  password set at all, regardless of what the actual password is. Authentication bypass
  achieved without knowing the password.
- **Why this is delivery-context-specific**: this exact bypass is *only* possible because
  the API accepts arbitrary JSON structure for the `password` field. A form-encoded
  equivalent (`password={"$ne":null}`) would arrive at the backend as a literal string
  `{"$ne":null}` (form fields are always strings), which would just fail the password
  check normally. The vulnerability requires JSON body delivery specifically, because
  only JSON preserves the nested-object type that MongoDB operators need.

## Key MongoDB Operators for Injection Testing

### `$ne` (not equal)

```json
{"password": {"$ne": null}}
```
As above — matches any non-null value, commonly used for auth bypass on password or
token-check fields.

### `$gt` (greater than)

```json
{"password": {"$gt": ""}}
```
Matches any password value greater than an empty string in MongoDB's comparison
ordering — effectively matches any non-empty password, another auth-bypass variant.
Useful as an alternative to `$ne` if the application specifically filters out `$ne` but
not other comparison operators.

### `$regex` (regular expression match)

```json
{"username": {"$regex": "^admin"}}
```
Instead of an exact-match string, this makes MongoDB match `username` against a regular
expression. Beyond simple bypass, `$regex` is a powerful **data extraction primitive**:
by iteratively testing regex patterns like `^a`, `^ad`, `^adm`, and observing which
requests succeed (e.g. return a valid session vs an error), an attacker can perform a
**blind, character-by-character extraction** of a field they don't already know (e.g.
extracting a password hash or a hidden token one character at a time), similar in concept
to blind SQLi's binary-search extraction but using regex prefix-matching as the oracle
instead of boolean SQL conditions.

### `$where` (arbitrary JavaScript execution)

```json
{"$where": "this.password.length > 0"}
```
`$where` allows a raw JavaScript expression to be evaluated by the MongoDB server against
each document. Breakdown:

- `this.password.length > 0` — `this` refers to the current document being evaluated;
  the expression checks if the password field has any length at all, another
  authentication-bypass primitive.
- `$where` is significantly more dangerous than the other operators because it allows
  **arbitrary JavaScript**, not just a fixed set of comparison semantics — depending on
  MongoDB server configuration and version, this can be a path toward denial-of-service
  (expensive JS execution looped over the whole collection) or, in poorly-sandboxed/older
  configurations, broader server-side impact. Always test `$where` cautiously and only
  within authorized scope, since a heavy `$where` expression can degrade the target
  service for other users.

## Where in the JSON Body These Operators Get Injected

Same "walk every leaf value" principle from the overview file applies, with one addition
specific to NoSQLi: test **both** the field being compared **and** whether the top-level
request body itself can be wrapped. Some vulnerable endpoints will also accept the
operator at the top level of the body rather than nested under a specific field:

```json
{"$where": "sleep(3000) || true"}
```

sent as the *entire* body (replacing the expected `{"username":..., "password":...}`
structure) — useful as a detection technique: if the endpoint still returns a normal
(non-400) response to a completely restructured body, it's a strong signal the backend
is passing the raw parsed JSON into the query layer with little to no schema validation,
which is the root cause enabling all of these bypasses.

## Detecting Blind NoSQL Injection

When responses don't clearly indicate success/failure (no obvious "logged in" vs "denied"
difference), use conditional operators as a true/false oracle, same logic as blind SQLi:

```json
{"username": "alice", "password": {"$regex": "^a"}}
```
vs
```json
{"username": "alice", "password": {"$regex": "^z"}}
```

If the response differs (timing, status code, response body length) between a matching
prefix and a non-matching prefix, you have a working blind oracle and can extract data
character-by-character by iterating the regex prefix.

## Testing Workflow (Burp)

1. Confirm `Content-Type: application/json` and identify all fields going into what is
   likely a MongoDB query (login, search, filter endpoints are the highest-probability
   targets).
2. Replace a scalar field value with each operator payload above, one at a time, checking
   for both immediate bypass (auth success) and behavioral difference (blind oracle
   signals).
3. Use Burp Intruder with a payload set containing operator JSON objects as the
   substitution values — same JSON-escaping caution as the SQLi file applies: your
   Intruder payload list must contain fully valid JSON snippets, since Intruder does raw
   text substitution.
4. There is no direct sqlmap equivalent for MongoDB — sqlmap is SQL-specific. For
   NoSQLi automation, tools like **NoSQLMap** exist but have far less active maintenance
   and reliability than sqlmap; manual Burp-based testing following the operator list
   above remains the most reliable primary approach, with automation as a secondary
   coverage pass rather than a primary method.

## WAF/Gateway Note for NoSQL Injection via API

Signature-based WAFs tuned for SQLi keywords (`UNION`, `SELECT`, `--`) generally have
**no signatures at all for MongoDB operator syntax** (`$ne`, `$gt`, `$where`) unless the
WAF vendor has specifically added NoSQL-aware rules — this is a meaningfully weaker
detection surface than SQLi in many real-world WAF deployments, because `$ne`/`$gt` as
JSON keys look syntactically identical to legitimate application data to a generic
pattern-matching WAF. This makes JSON-structural NoSQL injection one of the higher-success
categories in practice against WAF-protected APIs. See
`06-waf-bypass-api-injection.md` for the shared JSON-context bypass techniques
(Unicode-escaping, nesting) that still apply on top of this baseline detection gap.

## PortSwigger Lab Mapping (Gap Disclosure)

**Honest gap**: PortSwigger Web Security Academy, as of this writing, does **not** have a
dedicated NoSQL injection lab category. There is no Apprentice → Practitioner → Expert
progression to map here for this vulnerability class — this is a genuine coverage gap in
the Academy's curriculum, not an oversight in this note series.

**Alternative practice environments** (used in place of PortSwigger, consistent with how
other series handle Academy gaps):

- **crAPI** — includes intentionally vulnerable endpoints suitable for practicing
  JSON-body NoSQL-style bypass logic in a realistic API context.
- **NoSQL injection-focused intentionally-vulnerable apps** (e.g. community-maintained
  MongoDB CTF-style targets) — useful for operator-by-operator practice in a controlled
  environment before attempting against crAPI's more integrated scenarios.

## Real-World Note

NoSQL injection auth bypass via `$ne`/`$gt` is a recurring finding category in mobile-app-
backed APIs specifically, because mobile clients almost universally deliver JSON, and
many MEAN/MERN-stack backends (MongoDB + Express + Node) pass `req.body` fields directly
into Mongoose/MongoDB driver queries without an explicit schema-validation middleware
layer — a gap that's much less common in mature SQL-backed frameworks where an ORM
typically enforces parameter types by default.
