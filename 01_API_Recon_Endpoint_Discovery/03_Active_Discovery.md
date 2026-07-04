# Active Discovery for API Endpoint Enumeration

Active discovery means sending requests the target wasn't necessarily expecting
— brute-forcing paths, trying methods, probing parameters — in order to map
what passive recon didn't reveal. Unlike passive recon, this phase **does**
interact directly with the target's live infrastructure, including any WAF or
API Gateway sitting in front of it. Where that matters, it's called out
explicitly in the relevant section below (see especially sections 1 and 5).

Always run active discovery after passive recon, using what you already found
to narrow wordlists and prioritize likely-live paths rather than blindly
brute-forcing everything from a generic list.

---

## 1. Directory and Endpoint Brute-Forcing

### Mechanism

Brute-forcing sends a large number of requests, each guessing a different
possible path, and observes which ones return a response indicating the path
exists (as opposed to a generic 404). For APIs specifically, generic web
directory wordlists perform poorly — you want wordlists built from real-world
API path conventions (resource nouns, versioning patterns, common admin/
internal route names).

### Basic ffuf Example (Full Breakdown in 04_Tooling.md)

```bash
ffuf -u https://target.com/api/FUZZ -w api-wordlist.txt -mc 200,201,204,301,302,401,403 -t 40
```

- `-u https://target.com/api/FUZZ` — target URL template; `FUZZ` is the
  placeholder ffuf substitutes with each wordlist entry in turn.
- `-w api-wordlist.txt` — the wordlist file to iterate through.
- `-mc 200,201,204,301,302,401,403` — "match codes"; only show results whose
  HTTP response status is one of these. Critically, `401` and `403` are
  included alongside success codes — as explained in section 4 below, these
  codes usually mean the endpoint *exists* but access is denied, which is
  still a valuable discovery, not a dead end.
- `-t 40` — thread count; sends up to 40 concurrent requests. See the WAF/rate
  limiting note below before pushing this higher against real targets.

(Full ffuf flag reference, including API-specific wordlist sourcing, is in
`04_Tooling.md`.)

### WAF / API Gateway Relevance for This Section

This is the primary place in the entire recon phase where gateway-level
defenses become directly relevant, because brute-forcing generates a request
volume and pattern that gateways are specifically built to detect:

**Detection methods commonly used by WAFs/API Gateways:**
- **Rate-based detection** — flags a single source IP sending an abnormally
  high number of requests to sequentially-similar paths within a short window
  (e.g., 500 requests to `/api/*` in 10 seconds).
- **404 flooding detection** — some gateways specifically watch for a client
  generating an unusually high ratio of 404 responses, since legitimate users
  rarely hit dozens of nonexistent endpoints in succession.
- **User-Agent and header fingerprinting** — default User-Agent strings from
  tools like `ffuf`, `gobuster`, or `wfuzz` are well-known and trivially
  blocklisted.
- **Behavioral/sequential pattern detection** — requests iterating
  alphabetically or dictionary-order through a wordlist produce a
  recognizable timing/sequence signature distinct from human or normal client
  traffic.

**Realistic bypass considerations:**
- Throttle request rate deliberately (`-p` delay flags in ffuf, `-t` thread
  reduction) to stay under the target's rate-limit threshold — slower, but far
  less likely to get the source IP blocked mid-scan.
- Rotate or randomize the User-Agent header per request rather than using tool
  defaults.
- Distribute requests across multiple source IPs only if this is explicitly
  authorized in the engagement scope — doing this without authorization can
  cross from "testing" into behavior indistinguishable from an actual
  distributed attack, which is both an ethical and contractual problem.
- Randomize wordlist request order instead of scanning top-to-bottom, to break
  up the sequential pattern gateways look for.
- Be aware that some gateways silently return `200 OK` with an empty or
  generic body for *every* path once they detect scanning behavior, specifically
  to poison the scan results — validate a sample of "successful" hits manually
  before trusting a large ffuf result set at face value.

### Real-World Notes

- Generic web wordlists (like raft or common.txt) return a lot of noise for
  APIs — REST APIs follow resource-naming conventions, so purpose-built API
  wordlists (see `04_Tooling.md` for kiterunner's bundled lists) consistently
  outperform generic ones.
- Real targets behind a CDN/WAF (Cloudflare, AWS WAF, Akamai) will often start
  silently dropping or CAPTCHA-challenging requests well before you'd expect
  based on lab environments, which have no such protection. Budget engagement
  time accordingly — a scan that takes 5 minutes in a lab can take hours
  against a rate-limited production gateway if you throttle appropriately.

---

## 2. HTTP Method Enumeration

### Mechanism

REST APIs use HTTP methods (GET, POST, PUT, PATCH, DELETE) to represent
different operations on the same resource path. A path might only expose GET
to the front-end application, but the backend framework may still respond to
PUT or DELETE on that same path — sometimes because the developer intended
role-based restriction that was implemented on the front-end only, not
enforced server-side. Enumerating methods per discovered endpoint reveals this
class of exposure early, before you attempt any actual exploitation.

### Command Breakdown

```bash
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" https://target.com/api/users/123)
  echo "$method -> $code"
done
```

- `for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do ... done` —
  iterates over each listed HTTP method string.
- `-X "$method"` — curl's `-X` flag overrides the default request method
  (normally GET) with whichever method the loop is currently on.
- The rest of the command mirrors the status-code-only pattern from the
  passive recon file: capture just the numeric status code per method, then
  print a readable `METHOD -> code` line.

### Using the OPTIONS Method Directly

Many APIs implement `OPTIONS` to advertise which methods are actually
supported on a given path, which can shortcut the manual loop above:

```bash
curl -s -i -X OPTIONS https://target.com/api/users/123
```

- `-i` — includes response headers in the output (normally curl shows only
  the body); this matters here because the supported-methods information
  usually comes back in an `Allow:` response header, not in the body.
- `-X OPTIONS` — sends an OPTIONS request as described above.

Look for a header like `Allow: GET, POST, DELETE` in the response — this is
the server directly telling you what it will accept on that path, no guessing
required.

### Real-World Notes

- Not every framework implements OPTIONS meaningfully — some return a generic
  `204 No Content` with no `Allow` header at all, in which case you're back to
  the manual per-method loop.
- A method returning `405 Method Not Allowed` confirms the path exists (the
  router matched it) but that specific method isn't wired up — this is still
  useful confirmation of endpoint existence, distinct from a `404` which means
  the router found no matching route at all.
- Watch specifically for `PUT`/`DELETE`/`PATCH` succeeding on a path where the
  visible front-end only ever issues `GET` — this pattern, on its own, doesn't
  confirm a vulnerability, but it is exactly the kind of finding that should
  be flagged for follow-up authorization testing in a later phase (broken
  function-level authorization).

---

## 3. Parameter Discovery

### Mechanism

Endpoints frequently accept parameters — in the query string, in a JSON body,
or as headers — that aren't referenced anywhere in the visible front-end
application or the documentation you've collected. These "hidden" parameters
are a common source of business-logic bugs, mass assignment vulnerabilities,
and debug/admin toggles left in production. Discovery works by sending a known
endpoint a large list of candidate parameter names and observing whether the
response changes (different status code, different body length, different
content) compared to a baseline request with no extra parameters.

### Basic Arjun Example (Full Breakdown in 04_Tooling.md)

```bash
arjun -u https://target.com/api/users/123 -m GET --stable
```

- `-u https://target.com/api/users/123` — target endpoint to test.
- `-m GET` — HTTP method to use while fuzzing parameters (Arjun also supports
  POST with JSON/form bodies — see the tooling file for the full flag set).
- `--stable` — instructs Arjun to make extra confirmation requests before
  reporting a parameter as valid, reducing false positives caused by
  inconsistent server responses (common on APIs with caching or load
  balancing across multiple backend instances).

(Full Arjun flag reference is in `04_Tooling.md`.)

### Real-World Notes

- Parameter names discovered this way are frequently internal/debug-style:
  `debug`, `admin`, `test_mode`, `bypass_cache`, `internal`, `role` — worth
  prioritizing these for manual follow-up over generically-named ones.
- Response-diffing tools can produce false positives against APIs with
  non-deterministic responses (timestamps, request IDs, randomized ordering in
  JSON arrays) — always manually verify a "hit" by replaying the exact request
  with and without the discovered parameter before reporting it.

---

## 4. Response-Based Endpoint Inference (404 vs 401 vs 403)

### Mechanism

When you probe a path you don't have confirmed knowledge of, the exact status
code returned tells you different things about what's behind it:

| Code | What It Usually Means |
|---|---|
| `404 Not Found` | The router found no route matching this path at all — the endpoint likely doesn't exist. |
| `401 Unauthorized` | The route exists, but you haven't presented valid authentication at all (missing/invalid token). |
| `403 Forbidden` | The route exists, your authentication was recognized, but your identity/role lacks permission for this specific resource or action. |

This distinction is one of the most valuable signals in endpoint discovery: a
`401` or `403` is proof an endpoint exists and is worth further investigation,
even though you can't access it yet with your current credentials. Many
testers mistakenly treat any non-200 response as a dead end and move on,
missing exactly the endpoints — admin panels, elevated-privilege routes — that
matter most.

### Practical Application

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://target.com/api/admin/users
```

Run this once with no authentication header, and again with a valid low-
privilege token:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <low-priv-token>" https://target.com/api/admin/users
```

- `-H "Authorization: Bearer <low-priv-token>"` — adds an HTTP header; here,
  the standard Bearer-token authentication header, using a token from a
  legitimately low-privileged test account.

If the unauthenticated request returns `401` and the low-privilege-token
request returns `403`, you've confirmed: the endpoint exists, authentication
is being checked, and role-based authorization is separately enforced beyond
just "is logged in" — a specific, actionable map of the access control model
around that path, gathered without ever needing valid admin credentials.

### Real-World Notes

- Not every backend implements this distinction correctly. It's common to
  find APIs that return `403` for both "doesn't exist" and "exists but denied"
  — in that case this signal collapses and you'll need to cross-reference
  against other techniques (timing differences, response body size, Swagger
  spec if found) to distinguish the two cases.
- Some API Gateways deliberately normalize responses (see the WAF/Gateway
  note in section 1 and the overview file) specifically to defeat this
  technique, returning an identical generic response regardless of whether
  the underlying route exists — if you notice every single probed path
  returning byte-identical response bodies and codes, suspect this rather than
  concluding nothing exists.
- Response body content matters as much as the status code — two endpoints
  can both return `403`, but one with a generic error page and another with a
  JSON body naming the specific required role/permission (a common developer
  convenience that leaks the exact authorization model).

---

## 5. Shadow API and Zombie Endpoint Identification

### Mechanism

"Shadow" and "zombie" endpoints are routes that exist on the backend but
aren't part of the officially documented, currently-maintained API surface:

- **Zombie endpoints**: old API versions kept alive after a newer version
  replaced them — e.g., `/v1/users` still functioning identically to how it
  did two years ago, while the current front-end only calls `/v3/users`.
  These are dangerous because they frequently predate security fixes applied
  to the current version (a vulnerability patched in v3 may still be fully
  exploitable via the untouched v1 code path).
- **Shadow endpoints**: routes that were never part of any officially
  documented version at all — internal admin tooling, debug routes, or
  test/staging functionality that made it into the production deployment by
  accident.

### Technique 1: Version Fan-Out

Once you've confirmed the current API version (from documentation, JS
strings, or response headers), systematically test whether older or newer
version prefixes also respond:

```bash
for v in v1 v2 v3 v4 beta internal legacy; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/$v/users")
  echo "$v -> $code"
done
```

- Same loop structure as previous sections; this time iterating over version
  segment candidates instead of full endpoint names, applied to a resource
  path (`/users`) already confirmed to exist under the current version.
- A `200` (or `401`/`403`, per section 4) on `v1` while the app only uses `v3`
  is a strong zombie-endpoint signal worth flagging immediately.

### Technique 2: Debug/Test/Internal Path Probing

```bash
for path in debug test internal admin _internal health-check actuator staging-only console; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/$path")
  echo "$path -> $code"
done
```

- Targets common naming conventions developers use for non-production-intended
  routes that sometimes ship to production regardless.
- `actuator` specifically targets Spring Boot's actuator management endpoints
  (`/actuator/health`, `/actuator/env`, `/actuator/heapdump`), a very common
  real-world misconfiguration where operational/debug endpoints are left
  reachable without authentication.

### Technique 3: Cross-Reference Documentation Against Live Discovery

If you have a Swagger/OpenAPI spec from passive recon, diff the endpoints it
documents against everything discovered through brute-forcing and JS mining:

```bash
jq -r '.paths | keys[]' openapi.json | sort -u > documented-endpoints.txt
comm -13 documented-endpoints.txt discovered-endpoints.txt
```

- `jq -r '.paths | keys[]' openapi.json` — extracts every key under the
  spec's `paths` object (each key is an endpoint path in OpenAPI format) as
  raw strings.
- `sort -u > documented-endpoints.txt` — deduplicates and saves to a file.
- `comm -13 documented-endpoints.txt discovered-endpoints.txt` — `comm`
  compares two sorted files line by line; `-1` suppresses lines unique to the
  first file, `-3` suppresses lines common to both, leaving only lines unique
  to the *second* file (`discovered-endpoints.txt`) — i.e., endpoints you
  found live that aren't in the official documentation at all. This assumes
  `discovered-endpoints.txt` was built and sorted the same way from your
  brute-force/JS-mining results.

### Real-World Notes

- Zombie endpoints are disproportionately common in organizations that
  practice API versioning via URL path (`/v1/`, `/v2/`) rather than via
  headers or content negotiation, since old paths simply continue existing on
  the same router unless someone explicitly removes them — which frequently
  doesn't happen because no one wants to risk breaking an unknown consumer.
- Microservice architectures make this worse in practice: an old version of a
  service may keep running on its own container/pod indefinitely if
  decommissioning isn't part of the deployment pipeline, even after the
  gateway routing table stops directing normal traffic to it — sometimes it's
  still directly reachable if you know its internal-turned-external hostname
  or IP.
- Don't assume a zombie endpoint is automatically vulnerable — it needs the
  same authorization/injection/logic testing as any current endpoint. Its
  value as a finding is that it's *more likely* to have unpatched issues and
  is *unmonitored* compared to current, actively-watched endpoints.

---

## 6. Content-Type Fuzzing

### Mechanism

Some endpoints behave differently — or expose different code paths entirely —
depending on the `Content-Type` header of the request, even when hitting the
identical URL and method. A JSON-only endpoint might reject
`application/xml` outright, but some frameworks fall back to permissive
parsing or default deserialization behavior for unexpected content types,
occasionally bypassing validation logic that was only written with the
expected content type in mind.

### Command Breakdown

```bash
for ct in "application/json" "application/xml" "application/x-www-form-urlencoded" "multipart/form-data" "text/plain"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: $ct" -d '{"test":"data"}' https://target.com/api/users)
  echo "$ct -> $code"
done
```

- `-H "Content-Type: $ct"` — sets the request's declared content type to
  whichever value the loop is currently on.
- `-d '{"test":"data"}'` — sends this literal string as the request body
  regardless of the declared content type — intentionally, since the goal is
  to observe how the server's parser reacts to a body/content-type mismatch,
  not to send well-formed data for each type.
- Comparing status codes and response bodies across content types can reveal
  a parser accepting or mishandling a type the endpoint wasn't designed for.

### Real-World Notes

- This technique connects directly to a related but separate vulnerability
  class (insecure deserialization) — if content-type fuzzing during recon
  reveals a JSON endpoint that also accepts and processes XML, flag it for
  deeper testing during the exploitation phase rather than treating a status
  code change as the finding itself.
- Framework defaults vary widely: some strictly reject anything but the exact
  expected `Content-Type` with a `415 Unsupported Media Type`, which is
  actually the secure behavior — a `415` response here is a non-finding, not
  a miss.

---

## 7. API Documentation Analysis

### Mechanism

If passive recon (section 1 of the previous file) turned up a Swagger/OpenAPI
spec, the fastest and most complete way to build your endpoint map is reading
it directly rather than re-discovering the same information through
brute-forcing. The spec format is standardized, which means it can be parsed
programmatically rather than read manually line by line.

### Extracting Every Endpoint and Method

```bash
jq -r '.paths | to_entries[] | .key as $path | .value | keys[] | "\($path) [\(.|ascii_upcase)]"' openapi.json
```

- `jq -r` — raw string output, as before.
- `.paths | to_entries[]` — converts the `paths` object into an array of
  `{key, value}` pairs so both the path string and its contents can be
  accessed together; `[]` iterates over each pair.
- `.key as $path` — binds the current path string to a named variable `$path`
  for reuse later in the filter.
- `.value | keys[]` — for each path, `.value` is the object of HTTP methods
  defined under it (e.g. `get`, `post`); `keys[]` iterates over each method
  name defined for that path.
- `"\($path) [\(.|ascii_upcase)]"` — string interpolation building an output
  line combining the path and the method name (uppercased via `ascii_upcase`
  for readability, since OpenAPI spec method keys are lowercase by
  convention).

### Extracting Every Parameter for a Given Endpoint

```bash
jq -r '.paths."/api/users/{id}".get.parameters[] | "\(.name) (\(.in)) - required: \(.required)"' openapi.json
```

- `.paths."/api/users/{id}".get.parameters[]` — navigates directly to the
  `parameters` array defined for the GET method on this specific path
  (quoting the path key is required because it contains characters like `/`
  and `{}` that would otherwise confuse jq's dot-notation parsing).
- `"\(.name) (\(.in)) - required: \(.required)"` — for each parameter object,
  prints its name, where it's located (`in`: query, path, header, or cookie —
  a field the OpenAPI spec always includes for parameters), and whether it's
  marked required.

### Extracting Data Types From Request/Response Schemas

```bash
jq -r '.paths."/api/users".post.requestBody.content."application/json".schema.properties | to_entries[] | "\(.key): \(.value.type)"' openapi.json
```

- Navigates into the POST request body schema for a given path, then lists
  every property name alongside its declared JSON Schema `type` (string,
  integer, boolean, etc.) — this tells you, before sending a single test
  request, exactly what shape of data the endpoint expects, which
  dramatically speeds up later testing (you know immediately which fields to
  target for type-confusion or injection testing rather than guessing).

### Real-World Notes

- Specs are frequently out of date relative to the live API — treat a parsed
  spec as a strong starting hypothesis, not ground truth, and confirm key
  findings (especially required-vs-optional parameters and data types)
  against actual live responses.
- Look specifically for schema definitions describing fields that never
  appear in the visible front-end application at all (e.g. an `is_admin`
  boolean field defined in the `User` schema, when the UI never displays or
  sets this field) — these are prime mass-assignment candidates for the
  exploitation phase.
- Some organizations publish a deliberately reduced "public" spec to partners
  while running a fuller internal spec with additional endpoints/fields —
  if you can access both, always diff them.
