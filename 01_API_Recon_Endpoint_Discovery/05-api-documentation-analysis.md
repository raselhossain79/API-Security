# API Documentation Analysis

Finding a spec file, Postman collection, or GraphQL endpoint (file 2) is only half the
work — the value comes from systematically extracting everything it contains rather than
skimming it. This file covers how to read each of the three most common documentation
artifact types as a structured attack-surface map.

## 1. Reading OpenAPI / Swagger Specs

An OpenAPI (formerly Swagger) spec is a JSON or YAML document describing every endpoint,
method, parameter, and schema an API exposes. Treat it as a checklist, not reading
material — every entry under `paths` is a test target.

### Key sections to extract systematically

```bash
cat openapi.json | jq -r '.paths | keys[]'
```

Breakdown:
- `cat openapi.json` — outputs the spec file content.
- `jq -r '.paths | keys[]'` — `.paths` selects the top-level `paths` object from the
  spec, which is the OpenAPI standard's container for every endpoint; `keys[]` extracts
  just the object's keys (the endpoint path strings themselves, e.g. `/users/{id}`) as a
  list, one per line; `-r` prints them as raw strings rather than JSON-quoted.

```bash
cat openapi.json | jq -r '.paths | to_entries[] | "\(.key): \(.value | keys | join(", "))"'
```

Breakdown:
- `.paths | to_entries[]` — converts the `paths` object into an array of
  `{key, value}` pairs so each path and its contents can be processed together, then
  iterates over each pair.
- `"\(.key): \(.value | keys | join(", "))"` — a jq string interpolation; `\(.key)`
  inserts the path string; `\(.value | keys | join(", "))` takes that path's value
  object (which contains one key per supported HTTP method, e.g. `get`, `post`), extracts
  those method keys, and joins them into a comma-separated string. The overall output is
  a readable one-line-per-endpoint summary of which methods each path supports —
  extracted directly from the spec rather than needing the method enumeration technique
  from file 3, when the spec is accurate.

### Extracting parameter names and types for every endpoint

```bash
cat openapi.json | jq -r '.paths[][] | .parameters[]? | "\(.name) (\(.in)): \(.schema.type // "unspecified")"'
```

Breakdown:
- `.paths[][]` — double iteration: the first `[]` walks every path entry, the second
  `[]` walks every HTTP method defined under that path, reaching the operation object
  (which contains the parameter list) for every path/method combination in the spec.
- `.parameters[]?` — extracts each parameter object from the operation's parameter
  array; the trailing `?` prevents an error on operations that have no `parameters` key
  at all, skipping them silently instead of crashing the whole command.
- The interpolated string prints each parameter's `name`, its `in` field (whether it's a
  query parameter, path parameter, header, or cookie — critical for knowing how to
  actually supply it during testing), and its declared `schema.type`, falling back to
  the literal string `"unspecified"` via the `//` operator when no type is declared.

### What to specifically flag while reading

- **`securitySchemes` definitions** (usually under `components.securitySchemes` in
  OpenAPI 3.x) — reveals exactly what auth mechanisms the API expects (API key header
  name, OAuth2 flow type and scopes, bearer token). This tells you precisely what to
  set up before any active testing can proceed meaningfully.
- **Endpoints with no `security` requirement listed**, when most other endpoints in the
  same spec do have one — a strong signal of an endpoint the developers considered
  intentionally public, or one where an auth requirement was simply forgotten. Both are
  worth testing directly.
- **`deprecated: true` flags** on individual operations — a direct, spec-provided
  confirmation that an endpoint is meant to be retired, which is exactly the kind of
  entry worth checking against file 4's zombie API technique to see if it's still fully
  functional despite the deprecation flag.
- **Example values in `example` or `examples` fields** — frequently contain realistic
  test data (sample IDs, sample tokens) that speed up manual testing far more than
  guessing placeholder values.

## 2. Reading Postman Collections

Postman collections are JSON files representing saved requests, often exported directly
from a team's working development collection — which means they frequently contain far
more operational detail than an OpenAPI spec, including pre-filled auth tokens, internal
environment URLs, and requests to endpoints never formally documented anywhere else.

### Extracting every request URL from a collection

```bash
cat collection.json | jq -r '.. | .request?.url?.raw? // empty' | sort -u
```

Breakdown:
- `..` — jq's recursive descent, walking the entire collection structure at every
  nesting depth; necessary because Postman collections nest requests inside folders
  inside folders arbitrarily deep, with no fixed structure to target directly.
- `.request?.url?.raw?` — at each level reached by the recursive descent, attempts to
  extract `request.url.raw` (the full literal URL string Postman stores for a saved
  request); every `?` in the chain suppresses errors when that level doesn't have the
  expected structure (most levels won't, since only actual request objects have a
  `request` key).
- `// empty` — as in earlier files, filters out non-matches cleanly instead of printing
  `null` for every non-request object walked.
- `sort -u` — deduplicates the final URL list.

### Extracting saved auth tokens and environment variables (handle carefully)

```bash
cat collection.json | jq -r '.. | .key? // empty' | grep -iE "token|key|secret|auth" | sort -u
```

Breakdown:
- Same recursive descent pattern, this time extracting `.key` fields — in a Postman
  environment/variable structure, saved variables are stored as `{key: ..., value: ...}`
  pairs, so this pulls the variable *names* first as a scoping step.
- `grep -iE "token|key|secret|auth"` — filters that list of variable names down to ones
  whose name suggests they hold credential material, case-insensitively.

**Handle with care:** if a collection export contains live, currently-valid credential
values (not just variable names), this is itself a finding — a leaked working API key
or bearer token in an exported Postman collection is a critical exposure independent of
anything else in the collection, and should be reported and rotated rather than
casually reused for further testing without going through proper engagement-scope and
handling procedures.

### What a Postman collection tells you that a spec often doesn't

- **Auth flow sequencing** — the literal order of requests in a folder (login request,
  then a token-refresh request, then the actual API calls using that token) shows you
  exactly how the auth flow is meant to work end to end, which a static OpenAPI spec
  frequently doesn't capture in usable detail.
- **Environment-specific base URLs** — Postman environments (`dev`, `staging`,
  `production`) often reveal internal or staging hostnames as saved variables, directly
  feeding into the subdomain recon covered in `tools/amass-subfinder.md`.

## 3. Introspecting GraphQL Schemas

GraphQL exposes its entire schema — every type, field, query, and mutation — through a
single, standardized introspection query, when introspection is left enabled (which is
extremely common, since disabling it requires an explicit configuration step many teams
skip, especially in non-production or early-stage environments).

### Sending a basic introspection query

```bash
curl -s -X POST "https://api.example.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' \
  -o schema.json
```

Breakdown:
- `-X POST` — GraphQL APIs conventionally accept queries via POST to a single endpoint
  (commonly `/graphql`), unlike REST's many distinct URLs.
- `-H "Content-Type: application/json"` — GraphQL-over-HTTP conventionally expects a
  JSON body wrapping the query string.
- `-d '{"query":"{__schema{types{name,fields{name}}}}"}'` — the request body; `__schema`
  is GraphQL's built-in introspection root field, always available unless explicitly
  disabled server-side; this specific query asks for every `type` defined in the schema
  and, for each type, every `field` name it has — a minimal but complete map of the
  entire data graph the API exposes.
- `-o schema.json` — saves the (often very large) introspection response to a file for
  further parsing rather than dumping it to the terminal.

### A fuller introspection query revealing queries, mutations, and arguments

For a genuinely complete map (not just type/field names but every argument each field
accepts, and every query/mutation entry point), use the full standard introspection
query rather than the minimal one above — it's long enough that hand-writing it isn't
practical, so pull it from a maintained reference rather than retyping it, and feed it
through the same `curl -X POST` pattern shown above with the full query substituted into
the `-d` body.

### Parsing the introspection result for attack surface

```bash
cat schema.json | jq -r '.data.__schema.types[] | select(.name | startswith("__") | not) | .name'
```

Breakdown:
- `.data.__schema.types[]` — navigates into the introspection response's structure
  (GraphQL responses always wrap results under a top-level `data` key) and iterates over
  every type entry.
- `select(.name | startswith("__") | not)` — GraphQL's introspection system itself adds
  a number of internal meta-types prefixed with `__` (like `__Schema`, `__Type` — the
  introspection machinery describing itself); this filters those out so only the API's
  actual application-defined types remain in the output.
- `.name` — extracts just the type name for the final list.

```bash
cat schema.json | jq -r '.data.__schema.types[] | select(.name=="Mutation") | .fields[].name'
```

Breakdown:
- Same navigation as above, but this time filtering (`select`) for the specific type
  named `"Mutation"` — the conventional GraphQL root type listing every write operation
  the API supports — and extracting the name of every field under it, giving a direct
  list of every mutation (create/update/delete-style operation) available, which is
  exactly the subset of a GraphQL API's attack surface most worth prioritizing, since
  mutations are where authorization mistakes carry the highest impact.

**Real-world note:** it's extremely common for a GraphQL schema's `Mutation` type to
include operations that have no corresponding UI element anywhere in the client
application — administrative or internal mutations added for tooling, testing, or a
now-abandoned feature, left fully callable by anyone who can reach the endpoint and
knows (or introspects) the mutation name. This is functionally the GraphQL-specific
version of the shadow API problem covered in file 4.

## 4. PortSwigger Academy Coverage

Academy has genuinely strong, dedicated coverage here — this is the one file in the
series where the gap disclosure is much smaller than elsewhere.

**GraphQL API vulnerabilities** category, difficulty-progression order:

1. *Finding a hidden GraphQL endpoint* — directly teaches locating the `/graphql` (or
   non-standard-path) endpoint itself, a recon step this file assumes as a starting
   point.
2. *Accessing private GraphQL posts through introspection* — direct, hands-on practice
   of the introspection technique in section 3 above, used to discover a query not
   exposed through the normal application UI.
3. *Finding a GraphQL vulnerability by using introspection* — extends the same
   technique to locate a specific exploitable field.
4. *Bypassing GraphQL introspection defenses* — covers the realistic case where basic
   introspection has been disabled but alternate techniques (field suggestion probing,
   partial introspection queries against specific known type names) can still recover
   schema information; directly relevant when a target has taken the "disable
   introspection" hardening step but nothing further.

There is no equivalent Academy category for reading OpenAPI/Swagger specs or Postman
collections specifically — those remain **recon-adjacent, not recon-dedicated**, and
crAPI/DVAPI are the better hands-on option for practicing spec- and collection-driven
recon end to end.

## 5. Next File

Continue to `06-cheatsheet.md` for a condensed, engagement-ready reference pulling
together the commands from every file in this series.
