# Injection Testing in GraphQL

File 6 of 9. Assumes file 1 (variables vs. inline arguments, resolvers
talking to real backends). This file covers how classic injection classes —
SQL, NoSQL, OS command, and others — resurface through GraphQL's input
mechanisms once a value leaves the type system and reaches a resolver.

---

## 1. Why GraphQL's type system doesn't prevent injection

It's tempting to assume a strongly-typed query language is inherently safer
than REST's loosely-typed query strings and form bodies. This is only true
for one narrow guarantee: **GraphQL validates that an argument matches its
declared scalar type before execution** — an argument typed `Int` really
will be an integer by the time the resolver sees it; a `String` really will
be a string. That is the entire scope of what the type system enforces.

**GraphQL's type system says nothing about what the resolver does with a
correctly-typed value afterward.** A `String` argument that gets
concatenated into a raw SQL query, passed into a MongoDB `$where` clause,
or interpolated into a shell command is exactly as exploitable as the
equivalent REST form field would be — the type check only confirmed "this
is a string," not "this string is safe for the context it's about to be
used in." This is the same mechanism-level point made in file 1, section
10: resolvers, not the GraphQL layer, talk to the actual backend, and
GraphQL doesn't sit between the resolver and the backend at all.

---

## 2. The two injection surfaces: variables and inline arguments

From file 1, section 7: inputs enter a GraphQL operation either as
**variables** (typed, in the separate `variables` JSON object) or as
**inline arguments** (written literally in the query string). Both reach
the resolver as a value bound to an argument name — from the resolver's
perspective there is no difference at all between the two once execution
begins. The distinction matters only for *how you craft your test payloads
and where validation might differ*:

- **Variables** go through the GraphQL server's own input coercion for the
  declared type before the resolver runs. For a `String` variable, this
  coercion is minimal — most injection payloads pass through untouched,
  since a SQL/NoSQL/command-injection payload is still syntactically a
  valid string as far as GraphQL is concerned.
- **Inline arguments** are parsed as part of the query document itself.
  Certain characters (unescaped quotes, for instance) can break the GraphQL
  query syntax itself before your payload ever reaches the resolver — so
  inline-argument injection testing sometimes requires correct GraphQL
  string-escaping of your payload first, whereas the `variables` JSON
  object handles escaping for you naturally since it's just JSON.

**Practical rule:** test injection primarily via `variables` first, since
it's the cleaner, less error-prone surface; then retest anything
interesting via inline arguments as well, since a WAF/gateway
(section 6) may treat the two differently, and because some
resolvers apply different validation logic depending on which path the
value arrived through (rare, but seen in the wild when input-sanitization
middleware is only wired into one of the two code paths).

---

## 3. SQL injection through GraphQL

Structurally identical to REST-based SQL injection once you're at the
resolver — the only GraphQL-specific part is where the payload gets
delivered.

```graphql
query GetProduct($id: String!) {
  product(id: $id) {
    name
    price
  }
}
```
```json
{ "id": "1' OR '1'='1" }
```

Breakdown:
- `$id: String!` — note this argument is typed `String`, not `ID` or `Int`,
  in this example. **Look specifically for arguments typed as `String`
  where you'd expect a numeric ID** (`ID` and `Int`-typed arguments will
  fail type coercion for a payload like this before it ever reaches the
  resolver, which tells you nothing useful about the backend — you need a
  string-typed injection point, or one where the resolver casts a
  supposedly-typed value into a raw query some other way further down the
  stack).
- The payload itself (`1' OR '1'='1`) is unchanged classic SQL injection —
  nothing about testing methodology beyond delivery differs from REST.
  Confirm with the standard boolean-based, error-based, and time-based
  techniques you'd already use, and treat this as an ordinary SQLi finding
  once confirmed — this file isn't reintroducing SQLi methodology, only
  showing where in a GraphQL request to place it.
- Also test injection through **input object fields** on mutations, since
  these are just as capable of reaching a raw query:

```graphql
mutation Search($filter: SearchInput!) {
  searchProducts(filter: $filter) { id name }
}
```
```json
{ "filter": { "category": "electronics' OR '1'='1" } }
```

---

## 4. NoSQL injection through GraphQL

More common than classical SQLi in modern GraphQL backends, since GraphQL
and document databases (MongoDB especially) are frequently paired in
practice. The injection surface is the same — variables and inline
arguments — but payloads target operator-based query languages instead of
SQL syntax.

```graphql
query GetUser($username: String!) {
  user(username: $username) { id email }
}
```
```json
{ "username": { "$ne": null } }
```

Breakdown: instead of sending a string value, you send a **JSON object**
where a plain string was expected. If the resolver passes the `username`
variable directly into a MongoDB query filter without validating that it's
actually a scalar string first (e.g. `db.users.findOne({ username:
variables.username })`), MongoDB interprets `{ "$ne": null }` as its own
query operator meaning "username is not null" — matching the first user in
the collection regardless of the real username, a classic NoSQL
authentication-bypass pattern.

**Why this often works even against a "typed" GraphQL variable:** if the
schema declares `$username: String!`, a strict server implementation
*should* reject a JSON object being coerced into a `String` variable at the
input-coercion stage described in section 2 — this is one place where
GraphQL's type system genuinely can block a payload. **Test it anyway.**
In practice this depends entirely on how strictly the specific server
implementation enforces input coercion, and looser or older implementations
have been found to pass the raw value through regardless of the declared
scalar type, especially when the resolver receives the full `variables`
object directly rather than through a strongly-validated intermediate
layer. If the typed path is enforced correctly, check whether the same
argument is also reachable as a `JSON` or unstructured `Object`-scalar-typed
input elsewhere in the schema (some APIs define custom scalar types with no
real validation at all specifically for flexible filter inputs) — that's
your actual injection point instead.

---

## 5. OS command injection through GraphQL

Same principle again: if a resolver takes a string argument and passes it
into a shell command (e.g. a `convertFile(path: String!)` mutation that
shells out to an image-conversion binary), standard OS command injection
payloads apply, delivered via `variables`:

```graphql
mutation Convert($path: String!) {
  convertFile(path: $path) { url }
}
```
```json
{ "path": "image.png; id" }
```

Test methodology (command chaining, blind/time-based confirmation via
`sleep`, out-of-band confirmation) is unchanged from standard OS command
injection testing — again, this file's contribution is identifying that
any resolver accepting a filename, path, URL, or similar string argument
that plausibly reaches a shell invocation is worth this class of testing,
which you'd only know to look for by reading the resolver's likely purpose
from the introspected schema's field/argument names and descriptions
(file 2).

---

## 6. WAF / API gateway relevance for this specific vulnerability

Detection methods commonly seen:

- **Signature/pattern matching on the request body** for known
  injection-payload patterns (`' OR '1'='1`, `$ne`, `; id`, `UNION SELECT`,
  etc.) — identical in principle to how a WAF protects a REST API, just
  applied to the GraphQL request body (which, remember, is JSON containing
  a query string plus a separate `variables` object — a WAF needs to
  inspect both, and inconsistent inspection between the two is a genuine,
  commonly-seen gap).
- **JSON-structure anomaly detection** specifically for NoSQL injection —
  flagging cases where a variable's runtime value doesn't match its
  expected JSON type (e.g. an object supplied where a scalar was declared),
  which is a more GraphQL-schema-aware defense than generic payload
  signature matching, since it can catch novel NoSQL operator payloads the
  signature list hasn't seen yet.

Realistic evasion angles:
- **Splitting the payload across the query string and the `variables`
  object inconsistently** — e.g. if a WAF signature-matches the `variables`
  JSON but not the raw `query` string (or vice versa), moving part of a
  payload to inline arguments (section 2) may dodge detection tuned to only
  one of the two locations.
- **Encoding/obfuscating the payload within the string itself** using
  whatever the underlying injection class already supports (SQL comment
  insertion, alternate NoSQL operator syntax, command-injection separator
  variation) — this is not GraphQL-specific evasion, it's the same
  injection-class-specific WAF evasion you'd already use against a REST
  endpoint, just delivered through a GraphQL request body.
- **Wrapping the payload inside a nested input object field** rather than a
  top-level variable, if the WAF's JSON inspection is shallow and only
  fully parses top-level `variables` keys rather than recursing into nested
  input-object structures — this directly exploits the same nested-input
  shape described in section 3's `SearchInput` example.

A consolidated treatment of GraphQL WAF evasion across every technique in
this series is file 7.

---

## 7. Summary checklist for this file

- [ ] Identify every `String`-typed (and custom unstructured/`JSON`-typed)
      argument in the introspected schema, prioritizing ones with names
      suggesting they reach a database query, filesystem path, or shell
      command.
- [ ] Test each with variables first, then inline arguments (with correct
      GraphQL string escaping).
- [ ] For NoSQL targets, test sending JSON objects (`{"$ne": null}` and
      similar operators) in place of expected scalar values, even against
      typed arguments — strictness of enforcement varies by implementation.
- [ ] Test injection inside nested input-object fields on mutations, not
      just top-level scalar arguments.
- [ ] Apply standard, class-appropriate confirmation techniques (boolean,
      error-based, time-based, OOB) once a candidate injection point is
      found — this file identifies where to look in a GraphQL request, not
      how to confirm SQLi/NoSQLi/command injection once you're there.

**Next: file 7 — WAF Bypass for GraphQL**, consolidating detection methods
and evasion techniques across every attack category covered so far.
