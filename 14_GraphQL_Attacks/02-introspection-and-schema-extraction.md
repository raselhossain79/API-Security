# Introspection and Schema Extraction

File 2 of 9. Assumes file 1 (fundamentals — queries, mutations, types,
fields, resolvers). This file covers using introspection to extract a
GraphQL API's full schema, using that schema to find privileged mutations
never exposed in any UI, and bypassing introspection when it has been
disabled — including the field-suggestion leakage technique.

---

## 1. What introspection actually is

Introspection is a **built-in, spec-mandated GraphQL feature**, not a bug.
Every GraphQL server that follows the spec ships with reserved meta-fields
that let a client query the schema itself: `__schema`, `__type`, and
`__typename`. It exists so client tooling (IDEs, codegen, GraphiQL) can
auto-discover an API's shape.

From an attacker's perspective this means: **if introspection is left
enabled in production, you can retrieve the entire API surface — every
query, mutation, subscription, type, field, argument, and enum value — in a
single request, without any prior knowledge of the application.** This is
the GraphQL equivalent of finding an exposed Swagger/OpenAPI spec for a REST
API, except introspection is on by default in most frameworks and has to be
deliberately turned off.

---

## 2. The universal probe: confirming a GraphQL endpoint

Before introspecting, confirm the endpoint is actually GraphQL:

```graphql
query { __typename }
```

- `__typename` is a reserved field available on **every** object type in
  every GraphQL schema; it returns the name of the type as a string.
- Sent to the `Query` root, it returns `"Query"`.
- Any endpoint that replies with `{"data": {"__typename": "Query"}}` (or
  similar, wrapped in `"data"`) to this exact query is confirmed as
  GraphQL — this works regardless of what schema the target has, which is
  why it's called the universal query.

Try this against common endpoint paths first: `/graphql`, `/api`,
`/api/graphql`, `/graphql/api`, `/graphql/v1`, and the same paths with a
`/v1` suffix. If POST doesn't reveal anything, retry with GET (some
frameworks accept `GET /graphql?query=...` with the query URL-encoded) and
with `Content-Type: application/x-www-form-urlencoded`.

---

## 3. Probing whether introspection is enabled

Don't jump straight to a huge introspection query. Probe cheaply first:

```json
{ "query": "{__schema{queryType{name}}}" }
```

Breakdown:
- `__schema` — the root introspection meta-field, always available at the
  top level regardless of what your `Query` type is called.
- `queryType{name}` — asks for the name of the root query type (normally
  literally `"Query"`).

If this succeeds, introspection is on and you can proceed to the full query
below. If it returns an error like `"GraphQL introspection is not allowed"`
or a validation error naming `__schema` specifically, introspection has been
explicitly disabled — go to section 6.

---

## 4. The full introspection query, broken down field by field

This is the standard, complete introspection query. It is long because it
has to recursively describe every possible construct in the type system.

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
```

Field-by-field breakdown of what each piece buys you:

- **`queryType { name }` / `mutationType { name }` / `subscriptionType { name }`**
  — tells you which of the schema's named types serve as the three root
  entry points. Usually `Query`, `Mutation`, `Subscription`, but a
  security-conscious (or just idiosyncratically-configured) API might rename
  them — you need these names to know where to start reading the `types`
  array.

- **`types { ...FullType }`** — the complete list of every type in the
  schema: every object type, input type, enum, interface, union, and scalar.
  This is where privileged mutations hide (see section 5).

- **`kind`** — one of `OBJECT`, `INPUT_OBJECT`, `ENUM`, `INTERFACE`,
  `UNION`, `SCALAR`, `LIST`, `NON_NULL`. Tells you how to interpret the rest
  of the type's fields. `INPUT_OBJECT` types matter for injection testing
  (file 6) since they define the shape of mutation arguments.

- **`fields(includeDeprecated: true)`** — every field on an object type,
  including ones marked `@deprecated`. **Always pass `includeDeprecated:
  true`.** Deprecated fields are frequently still fully functional
  server-side (deprecation is a documentation-layer signal, not a removal),
  and they're disproportionately likely to have weaker or forgotten
  authorization logic because the team assumes no one uses them anymore.

- **`args { ...InputValue }`** on each field — every argument the field
  accepts, with its own type. This tells you exactly how to call a mutation
  or query you've discovered, without any guessing.

- **`type { ...TypeRef }`** — recursively unwraps `NON_NULL` and `LIST`
  wrappers around a field's actual named type. The nested `ofType` chain in
  the `TypeRef` fragment exists because GraphQL's type-wrapping can nest
  (e.g. `[Product!]!` is a non-null list of non-null `Product`), and each
  layer needs one more `ofType` to unwrap.

- **`isDeprecated` / `deprecationReason`** — flags and explains deprecated
  fields; useful triage signal per above.

- **`inputFields`** — for `INPUT_OBJECT` kinds, the fields expected inside
  an input argument object (e.g. the shape of a `CreateUserInput` type used
  by a mutation).

- **`interfaces`** and **`possibleTypes`** — used for interface/union types;
  tells you which concrete object types can satisfy an interface, which
  matters if you're trying to request fields only available on one specific
  implementing type.

- **`directives`** — schema-level directives like `@deprecated`,
  `@skip`, `@include`, or custom ones a specific API defines.

**Note on the `onOperation` / `onFragment` / `onField` lines** you'll see in
some older published versions of this query: modern schemas reject these as
unknown arguments to `directives`, causing the whole introspection query to
fail. If your introspection query returns a validation error mentioning
these, delete those three lines and resend — this is a version-compatibility
issue with old introspection queries, not a defense.

---

## 5. Turning the raw schema into attack targets

The introspection response is large and repetitive JSON. Two practical
approaches:

1. **Visualize it.** A GraphQL schema visualizer takes the raw introspection
   JSON and renders the relationships between types, queries, and mutations
   as a browsable graph — much faster than reading raw JSON for orientation.
2. **Grep it for privilege signals.** Regardless of tooling, once you have
   the schema, specifically scan the `Mutation` type's field list for names
   suggesting admin/privileged functionality that you have never seen
   surfaced in the UI: `deleteUser`, `deleteOrganizationUser`, `setRole`,
   `promoteToAdmin`, `impersonateUser`, `resetAllPasswords`,
   `updateBillingPlan`, `exportAllData`. **This is the core payoff of
   introspection for a pentester: the UI only calls a subset of the schema's
   mutations. Introspection shows you the full set, including ones the
   frontend team never wired a button to but the backend team never removed
   or gated.**

Concrete example — you introspect and find:

```graphql
type Mutation {
  updateProfile(id: ID!, name: String): User
  deleteOrganizationUser(id: ID!): Boolean
}
```

The web UI's "Edit profile" page only ever calls `updateProfile`. Nothing in
the rendered application calls `deleteOrganizationUser` — no button, no API
call visible in Burp's HTTP history during normal browsing. But because it's
in the schema and the endpoint accepts arbitrary operations from the schema,
you can call it directly:

```graphql
mutation {
  deleteOrganizationUser(id: 3)
}
```

Whether this succeeds depends entirely on the resolver's authorization
logic — which introspection cannot tell you, only testing can (file 5
covers exactly this: testing authorization at the resolver level once
you've found the mutation via this process).

**Also check `description` fields.** Many schemas populate GraphQL SDL
`description` strings (visible in introspection) with genuinely useful
internal documentation written for the API's own developers — sometimes
including notes about intended access restrictions ("admin only", "internal
use") that confirm a field is sensitive even before you test it.

---

## 6. Bypassing introspection when it's disabled

Introspection being disabled is standard production hardening advice, and a
non-trivial number of real APIs implement it via a naive regex/string check
rather than a proper parser-level block. Two independent bypass angles:

### 6a. Whitespace/character insertion around `__schema`

If the block is implemented as something like a regex matching the literal
string `__schema{` or `__schema {`, inserting characters that GraphQL's own
parser ignores — but the defensive regex doesn't account for — can slip
past it:

```json
{
  "query": "query{__schema\n{queryType{name}}}"
}
```

Here a newline is inserted immediately after `__schema`. GraphQL's parser
treats whitespace as insignificant between tokens, so this is a fully valid,
identical query to the parser — but if the block only pattern-matches
`__schema{` as a contiguous substring, the newline defeats it. Try spaces,
tabs, and commas (GraphQL treats commas as insignificant whitespace too) in
the same position.

### 6b. Switching request method/content-type

Introspection blocking middleware is sometimes only wired into the primary
POST/JSON handling path. Try the same probe:
- As a `GET` request with the query URL-encoded in the query string.
- As a `POST` with `Content-Type: application/x-www-form-urlencoded`.

```
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

If either alternate transport reaches a code path where the introspection
block wasn't applied, you get the full schema back through a route the
developers didn't think to test.

---

## 7. Field-suggestion leakage: extracting a schema with introspection fully, correctly disabled

This is the technique you asked to see broken down in detail, because it
matters even when sections 6a/6b both fail and introspection really is
properly disabled at the parser level.

### The mechanism

Many GraphQL server implementations (Apollo Server is the most commonly
seen in the wild) include a **developer-friendliness feature**: if a client
sends a field name that does not exist, but is *close* to a field name that
does exist, the error message suggests the correction.

```json
{ "query": "{ productInfo }" }
```
```json
{
  "errors": [
    {
      "message": "Cannot query field \"productInfo\" on type \"Query\". Did you mean \"productInformation\"?"
    }
  ]
}
```

This suggestion logic runs on a **string-distance comparison** (commonly
Levenshtein distance) between what you typed and every real field name in
the schema — and critically, **this feature has nothing to do with the
introspection meta-fields you disabled.** Disabling `__schema`/`__type`
blocks the direct schema-dump path; it does nothing to the field-resolution
error handler, because that's a completely separate code path that fires
whenever query validation fails on an unrecognized field name, which happens
constantly during normal development and is why the "helpful" suggestion
feature exists in the first place.

### Manual exploitation walkthrough

1. Send a query referencing a field name you're fairly confident doesn't
   exist but is plausible for the domain, e.g. `{ user }`.
2. Read the suggestion in the error. Say it comes back:
   `Did you mean "users"?`
3. Query `{ users }`. If it's a valid field but needs a selection set,
   you'll get a *different* error demanding sub-fields — which itself
   confirms `users` is real and is an object/list type, not a scalar.
4. Probe sub-fields the same way: `{ users { asdf } }` will typically
   return `Cannot query field "asdf" on type "User". Did you mean
   "address"? Did you mean "admin"?` etc. — multiple suggestions when
   several field names are within edit-distance of your guess.
5. Repeat this recursively: every confirmed field becomes a new node to
   expand sub-fields on, and every rejected guess becomes free information
   about nearby real field names, letter by letter.
6. Do the same walk against `Mutation` by trying plausible mutation verbs:
   `mutation { delete }`, `mutation { update }`, `mutation { admin }` — each
   wrong guess leaks the real, similarly-spelled mutation name back to you.

This is slow and tedious done purely by hand, which is exactly why it's
normally automated (see below) — but you should be able to do at least a
few rounds manually so you can recognize the pattern in a live engagement
even without tooling on hand, and so you understand precisely what a tool
like Clairvoyance is doing under the hood rather than treating it as a black
box.

### Automating it

**Clairvoyance** is the dedicated open-source tool for this: it
automatically fuzzes field names against a GraphQL endpoint using the
suggestion-leak oracle described above, and reconstructs as much of the
schema as the suggestion feature will leak — sometimes recovering the
majority of a schema even with introspection completely and correctly
disabled. Full tool usage and flag breakdown is covered in file 8 alongside
InQL and graphql-cop, since all three belong in the same "dedicated GraphQL
tooling" reference.

### The actual fix (know this so you can explain root cause in a report)

The correct mitigation is not disabling introspection harder — it's
disabling the **suggestion feature specifically**. In Apollo Server v4+,
this is the `hideSchemaDetailsFromClientErrors` option. Earlier Apollo
versions require a validation-rule-level workaround, since the option
doesn't exist as a first-class config in those versions. When you report
this finding, be explicit that introspection-disabled alone is
insufficient — this is worth stating clearly in any writeup, since it's a
common false sense of security for developers who believe "introspection
off" fully closes the schema-disclosure risk.

---

## 8. WAF / API gateway relevance for this specific topic

Introspection queries have a distinctive, easily-signatured shape: the
literal strings `__schema`, `__type`, and the long, near-identical
`IntrospectionQuery` boilerplate shown in section 4 are common enough that
WAFs and API gateways with GraphQL-aware rulesets frequently block requests
containing them outright, regardless of HTTP method or content-type.
Detection typically works by:
- Simple substring/regex matching on `__schema` or `__type` in the request
  body.
- Matching the well-known introspection query's fragment names
  (`FullType`, `InputValue`, `TypeRef`) since these are copy-pasted almost
  verbatim across the ecosystem from the reference query used throughout
  this file.

Realistic evasion angles, beyond the parser-vs-regex whitespace trick in
section 6a:
- Renaming the fragments (`fragment MyStuff on __Type { ... }` works
  identically to `fragment FullType on __Type { ... }` — the fragment name
  is arbitrary) to avoid signature matches keyed on the well-known fragment
  names rather than on `__schema`/`__type` themselves.
- Splitting the introspection query into several smaller, individually
  less-recognizable requests (e.g. query `queryType{name}` alone, then
  separately query a handful of specific `__type(name: "User")` lookups)
  rather than sending the single large canonical `IntrospectionQuery`
  payload that most signatures are tuned against.
- Field-suggestion leakage (section 7) is itself a WAF-bypass technique in
  practice, since it never references `__schema` or `__type` at all — a WAF
  rule keyed purely on those meta-field names will not flag it.

A full, dedicated treatment of GraphQL WAF detection and bypass across all
attack categories (not just introspection) is file 7.

---

## 9. Summary checklist for this file

- [ ] Confirm endpoint with `query{__typename}`.
- [ ] Probe cheaply with `{__schema{queryType{name}}}` before sending the
      full query.
- [ ] Run the full introspection query with `includeDeprecated: true` on
      every applicable field.
- [ ] Visualize or grep the `Mutation` type specifically for
      admin/privileged-sounding field names not observed in normal UI
      traffic.
- [ ] Check `description` strings for developer notes on access
      restrictions.
- [ ] If introspection is blocked: try whitespace-insertion and
      alternate-transport bypasses first (cheap, fast).
- [ ] If introspection is properly disabled: fall back to field-suggestion
      leakage, manually for a few rounds to understand the oracle, then via
      Clairvoyance for full coverage (file 8).

**Next: file 3 — Batching and Alias Attacks**, where the `aliases`
mechanic from file 1 becomes a rate-limit bypass, with a full step-by-step
OTP brute-force walkthrough.
