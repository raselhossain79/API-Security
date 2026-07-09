# 02 — Exposed API Documentation

## 1. Why exposed documentation is a misconfiguration, not a feature

Swagger UI, OpenAPI/Swagger JSON specs, and GraphQL introspection all exist to help *developers*
understand and consume an API. None of them are meant to be reachable by an anonymous client
against a **production** deployment. When one of these is left live, it collapses the normal
reconnaissance phase of a pentest into a single request: instead of inferring endpoints from
client-side JS or brute-forcing paths, you get the exact route list, parameter names, types,
required/optional flags, authentication scheme, and often internal-only endpoints that were never
linked from any client application.

## 2. Swagger UI accessible in production

### 2.1 What it exposes

Swagger UI is a rendered, interactive HTML page built from an OpenAPI spec. If reachable, it gives
you:

- Every documented endpoint and HTTP method combination.
- Full request/response schemas, including field names and data types.
- Which endpoints require authentication and what scheme (`Authorization: Bearer`, API key header
  name, etc.) — this alone tells an attacker exactly which header to forge or steal.
- A **"Try it out" button that lets you execute live requests against the real backend directly
  from the browser**, using whatever credentials or cookies are present in that browser session.
- Frequently, internal or deprecated endpoints that are still wired up server-side but never
  exposed to the public-facing client app — these get zero real-world traffic and therefore zero
  real-world hardening attention, making them disproportionately likely to have weaker validation.

### 2.2 Common paths to check

Swagger UI and its underlying spec file are served from a small, well-known set of default paths
depending on framework/library. Check all of these against the API's base path and its root:

```
/swagger-ui.html
/swagger-ui/
/swagger-ui/index.html
/swagger/
/swagger/index.html
/api-docs
/api/swagger.json
/api/swagger.yaml
/api/v1/swagger.json
/v1/swagger.json
/v2/api-docs
/v3/api-docs
/openapi.json
/openapi.yaml
/.well-known/openapi.json
/docs
/redoc
/api/docs
```

**Piece-by-piece: why so many paths.** Each framework picks its own default: springdoc-openapi
(Spring Boot) defaults to `/v3/api-docs` and `/swagger-ui.html`; older springfox defaults to
`/v2/api-docs`; FastAPI defaults to `/docs` (Swagger UI) and `/openapi.json`; NestJS's Swagger
module commonly sits at `/api` or `/api-docs`; Django REST Framework with drf-yasg is often at
`/swagger/`. There is no universal path — this is exactly why a wordlist sweep (ffuf, gobuster,
or Burp Intruder against this list) is standard practice rather than guessing one path and giving
up.

### 2.3 Exploitation walkthrough

1. **Request each candidate path** with a plain `GET`, unauthenticated. A `200` response with
   `Content-Type: text/html` and Swagger-branded markup confirms the UI; a `200` with `application/
   json` or `application/yaml` containing an `"openapi"` or `"swagger"` top-level key confirms the
   raw spec even if the rendered UI itself is blocked.
2. **Read the spec's `paths` object.** Every key is a route the server implements. Cross-reference
   this list against what the production client application actually calls (visible in its JS
   bundle or captured traffic). Routes present in the spec but absent from the client's real
   traffic are the highest-value targets — they are functionality nobody is watching.
3. **Read each operation's `security` field.** This tells you per-endpoint whether auth is
   required and which scheme. An endpoint with an empty `security: []` array in a spec where most
   endpoints require a bearer token is a signal the developer explicitly (or accidentally) marked
   it public — test it unauthenticated first.
4. **Use "Try it out" (if the UI itself is live) to send authenticated-looking requests using
   session state already present in your browser**, or replay the same requests through Burp using
   credentials obtained elsewhere. Because the spec already tells you every required field and its
   type, you skip the trial-and-error of guessing a correct request body.

### 2.4 Impact

Full endpoint enumeration, parameter and type disclosure, authentication scheme disclosure, and
frequently direct execution against production data through "Try it out." This is reconnaissance
acceleration for every other API vulnerability class (BOLA, mass assignment, injection) — it
doesn't grant access by itself in most cases, but it removes the discovery cost for everything
that follows.

## 3. OpenAPI specs exposing internal endpoint details

This is a distinct failure mode from "Swagger UI is reachable": here, the **spec file itself**
contains details that shouldn't ship to a public spec even if the spec is intentionally public
(e.g., a partner-facing API with published docs).

### 3.1 What to look for inside a spec

- **`servers` entries pointing at internal hostnames** — `https://internal-api.corp.local`,
  `http://10.x.x.x:8080`, staging URLs with predictable naming (`api-staging.`, `api-dev.`) that
  may have weaker controls than production.
- **`x-internal`, `x-admin`, or vendor-extension fields** some frameworks emit automatically that
  mark routes as internal-only in intent but do not actually restrict access to them.
- **Path segments revealing internal service names or architecture** — `/internal/reconcile-
  ledger`, `/admin/impersonate`, `/debug/flush-cache` — these tell you what to specifically target
  next even before you've sent a single request to them.
- **`description` and `summary` fields written for internal developer audiences**, which
  occasionally contain operational detail (queue names, downstream service names, feature-flag
  names) useful for building targeted attacks like SSRF payloads or business-logic abuse.
- **Example values (`example`/`examples` keys) containing real-looking data** — sometimes these
  are copy-pasted from real responses during spec authoring and contain real IDs, tokens, or
  internal identifiers instead of synthetic placeholders.

### 3.2 Piece-by-piece: parsing a spec efficiently

Rather than reading raw JSON by eye, extract systematically:

```bash
# All paths + methods
jq -r '.paths | to_entries[] | .key as $p | .value | keys[] | "\($p|ascii_upcase) \(.)"' openapi.json

# All server URLs (internal hostnames often surface here)
jq -r '.servers[].url' openapi.json

# All security schemes and which header/scheme they use
jq -r '.components.securitySchemes' openapi.json

# Any field named with an internal-sounding prefix
grep -Eio '"(internal|admin|debug|staging|legacy)[a-zA-Z_-]*"' openapi.json | sort -u
```

Each of these `jq` queries answers a different reconnaissance question: full route map, alternate
hosts to test against, exact auth header/scheme to forge, and a quick grep for internal-labeled
fields that deserve manual review.

## 4. GraphQL introspection enabled in production

### 4.1 What introspection exposes

GraphQL introspection is a built-in feature of the GraphQL spec itself — it lets a client query
the `__schema` meta-field to retrieve the server's entire type system: every query, mutation,
subscription, their arguments, return types, and (if the schema author wrote them) field-level
descriptions. Unlike REST's OpenAPI spec, which is an *optional* document a team chooses to
generate, introspection is **on by default** in most GraphQL server implementations unless
explicitly disabled — this is the core reason it shows up so often as a production misconfiguration.

### 4.2 Exploitation walkthrough

1. **Confirm the endpoint is GraphQL.** Send `POST` with body `{"query":"{__typename}"}` to
   candidate paths (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`). A JSON response like
   `{"data":{"__typename":"Query"}}` confirms it.
2. **Send a full introspection query.** Burp Suite can generate this automatically (right-click a
   GraphQL request → GraphQL → Set introspection query), or use the standard query requesting
   `__schema { queryType { name } mutationType { name } types { ...} }`.
3. **Piece-by-piece: what the response gives you.**
   - `types[].fields[].name` — every field name on every object type, including fields never
     rendered by the production client (e.g., a `User` type exposing `passwordHash` or
     `internalNotes` fields that the client app simply never queries, but which are still
     resolvable if you ask for them directly).
   - `types[].fields[].args` — every argument each field accepts, including filters or ID
     parameters that hint at IDOR-style access (`getUser(id: ID!)` with no ownership check implied
     by the schema alone).
   - `mutationType` — every mutation, i.e. every write operation the API supports, whether or not
     any client currently calls it.
   - `description` fields — schema authors sometimes leave operational comments here
     (`"Internal use only, requires admin role"`) that are exposed verbatim to anyone who can
     introspect.
4. **Query for a field the production client never requests.** Because GraphQL lets you construct
   arbitrary field selections, once you know a sensitive field name exists (from step 3) you can
   query it directly even if no UI ever surfaces it — this is the single most common way
   introspection turns into an actual data-exposure bug rather than staying "just recon."

### 4.3 When introspection is disabled but not fully removed

A common half-fix: introspection queries are blocked via a simple string match on `__schema` in
the request body, but the resolver itself is untouched.

- **Bypass via whitespace/formatting.** Regex filters matching literally `__schema{` fail against
  `__schema {` (space) or a query with a newline injected immediately after `__schema`, because
  the GraphQL parser doesn't care about whitespace but the filter's regex does.
- **Bypass via HTTP method or content-type change.** If introspection is blocked only on `POST`
  with `application/json`, try `GET` with the query as a URL parameter
  (`/graphql?query=query{__typename}`), or `POST` with
  `Content-Type: application/x-www-form-urlencoded`.
- **Bypass via suggestions.** Some GraphQL servers (notably Apollo) suggest corrections for
  slightly-wrong field names in error messages (`Did you mean "userEmail"?`). Even with
  introspection fully and correctly disabled, sending intentionally near-miss field names and
  reading the suggestion text lets you reconstruct schema fragments field by field.

## 5. WAF / API Gateway relevance for this file

Not meaningfully applicable as a payload-inspection bypass problem, and that's worth stating
directly rather than manufacturing a bypass narrative. Requesting `/swagger.json` or sending
`{"query":"{__schema{types{name}}}"}` is a syntactically valid, non-malicious-looking request —
there's no injection string or anomalous encoding for a WAF signature to catch. What actually
matters here is **API gateway configuration**, not WAF detection:

- Gateways (Kong, Apigee, AWS API Gateway, NGINX-based reverse proxies) can be configured to
  strip or block requests to documentation paths at the edge, independent of what the backend
  framework serves by default — this is a routing/allow-list control, not a signature match.
  Testing whether this control exists means checking whether the *gateway* returns a `404`/`403`
  even though the *backend* (reachable directly, if you can find its real address) would happily
  serve the spec.
- Some organizations rely on a WAF rule that blocks the literal string `__schema` in GraphQL
  bodies as a crude introspection block — this is the one place a "bypass" genuinely applies, and
  it's exactly the whitespace/method/suggestions techniques in §4.3 above, which are WAF-agnostic
  in the sense that they work against both a backend-level filter and a WAF-level string match.

## 6. PortSwigger Web Security Academy lab mapping

GraphQL introspection has direct PortSwigger coverage; OpenAPI/Swagger-specific spec exposure does
not — PortSwigger's Information Disclosure topic covers the general debug-page/backup-file pattern
(cross-referenced in file 04) but has no lab built specifically around an exposed OpenAPI JSON
file. Stated honestly rather than stretched to fit.

**Apprentice**
1. *Accessing private GraphQL posts* — introspection reveals a field (`postPassword`) never used
   by the client UI; querying it directly returns data that should have required authorization.
2. *Bypassing GraphQL introspection defenses* — practices exactly the whitespace-based regex
   bypass described in §4.3.

**Practitioner**
3. *Finding a hidden GraphQL endpoint* — practices endpoint discovery against common GraphQL
   suffixes combined with a `GET`-based introspection bypass, directly matching the discovery
   workflow in §4.2 step 1 and the method-based bypass in §4.3.

**Gap disclosure:** PortSwigger has no lab for Swagger UI/OpenAPI spec exposure specifically, nor
for internal-hostname leakage inside a spec's `servers` array. For hands-on practice on the
REST/OpenAPI half of this file, **crAPI** is a better fit — its documentation is deliberately
left reachable and includes endpoints absent from its mobile client, mirroring §2 and §3 directly.

## 7. Real-world notes

- Swagger UI left live in production is one of the single most commonly reported low-effort
  findings in public bug bounty programs — it's usually a framework default nobody explicitly
  disabled for the production build profile, not a deliberate choice.
- GraphQL introspection being on by default (rather than off by default) in most server libraries
  means "disabled in prod" has to be an explicit, remembered step in the deployment pipeline —
  teams that only test their GraphQL API through their own client app frequently never notice
  introspection is still live, because their client never calls it.
- Internal hostnames leaking through a `servers` array in a spec have directly enabled SSRF and
  internal network reconnaissance in real engagements — cross-reference the SSRF series (API7) if
  you find one, since a leaked internal hostname is often the missing target for an otherwise
  unconfirmed SSRF.

## 8. Remediation summary

- Disable Swagger UI and raw spec serving in production build/deployment profiles; if docs must be
  public, serve a hand-curated subset rather than the framework's auto-generated full spec.
- Disable GraphQL introspection in production (`introspection: false` equivalent for the server
  library in use); if the API is public and introspection is a deliberate design choice, audit the
  schema for fields/mutations never intended for public consumption before shipping it.
- Never rely on a string-match filter as the sole introspection control — disable the resolver
  path entirely.
- Scrub `servers`, `description`, and `example` fields of internal hostnames, operational
  commentary, and real data before any spec is exposed, even intentionally.
