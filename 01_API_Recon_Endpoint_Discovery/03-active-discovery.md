# Active Discovery Techniques for API Recon

Active discovery generates real traffic to the target and should only begin once passive
recon (file 2) has given you a seed list — real endpoint fragments, naming conventions,
and version strings to build informed wordlists from. Blind brute-forcing with a generic
wordlist works, but seeded brute-forcing with target-specific terms finds far more in far
less time and generates far less noise against rate limiting and WAF detection.

This file covers the techniques conceptually. Full flag-by-flag tool usage lives in the
dedicated tool files (`tools/kiterunner.md`, `tools/ffuf-api-fuzzing.md`,
`tools/arjun.md`).

## 1. Directory and Endpoint Brute-Forcing

### The core idea

Send requests for a large list of candidate paths against the target and observe which
ones return a response other than a generic 404 — this reveals endpoints that exist but
were never linked from any documentation or client-side code you found passively.

### Building a seeded wordlist

Combine a general API wordlist (e.g., SecLists' `api/api-endpoints.txt` or
`raft-large-words.txt`) with everything you extracted from JS mining, Wayback, and any
spec files found in Phase 1:

```bash
cat seclists-api-wordlist.txt js-mined-endpoints.txt wayback-endpoints.txt | \
  sed 's|^/||' | sort -u > combined-wordlist.txt
```

Breakdown:
- `cat file1 file2 file3` — concatenates the three source wordlists into a single
  stream, one path candidate per line.
- `|` — pipes that combined stream into `sed`.
- `sed 's|^/||'` — a stream editor substitution; `s|pattern|replacement|` is the
  substitute command using `|` as the delimiter (instead of the more common `/`, chosen
  here specifically because the pattern itself contains a literal `/`); `^/` matches a
  leading slash at the start of each line; replacing it with nothing strips that leading
  slash so entries are normalized before being combined with a base URL later.
- `sort -u` — sorts and deduplicates the combined list, since JS mining and Wayback
  output frequently overlap with entries already in the general wordlist.
- `> combined-wordlist.txt` — redirects the final output into a new file rather than
  printing it to the terminal.

### A basic brute-force pass with ffuf

```bash
ffuf -u https://api.example.com/FUZZ -w combined-wordlist.txt -mc 200,201,204,301,302,401,403 -t 40
```

Breakdown (full ffuf reference lives in `tools/ffuf-api-fuzzing.md`):
- `-u https://api.example.com/FUZZ` — the target URL template; `FUZZ` is ffuf's default
  placeholder keyword, replaced on each request with one line from the wordlist.
- `-w combined-wordlist.txt` — the wordlist file to iterate over.
- `-mc 200,201,204,301,302,401,403` — "match codes"; tells ffuf to only display results
  whose HTTP status is in this list. Critically, this includes 401 and 403 alongside
  success codes — an endpoint that returns 403 Forbidden still confirms the endpoint
  *exists* and is worth recording, even though you can't access it without proper auth
  yet.
- `-t 40` — sets 40 concurrent threads, balancing speed against the risk of tripping
  rate limiting; this should be tuned down against production targets with WAF/rate
  limiting observed, and can be tuned up in a permission-scoped lab environment.

### Why kiterunner exists on top of this

Generic wordlist brute-forcing treats every candidate path as a flat string. Real APIs
are structured — resources nest (`/users/{id}/orders/{id}/items`), and a flat wordlist
either misses nested patterns entirely or needs an enormous combinatorial wordlist to
approximate them. kiterunner solves this by brute-forcing using real API route
structures (either learned from a large corpus of known API specs, or from a spec file
you provide), producing far higher hit rates on modern REST APIs. Full usage in
`tools/kiterunner.md`.

## 2. HTTP Method Enumeration

Once an endpoint is confirmed to exist, the next question is which HTTP methods it
actually accepts — documentation frequently only lists the "intended" method (e.g. GET
for a resource) while the underlying framework's routing accepts others by default
(PUT, DELETE, PATCH) that were never meant to be reachable without additional
authorization checks that only got added to the documented method.

### Manual method enumeration with curl

```bash
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}\n" -X "$method" "https://api.example.com/api/v1/users/42"
done
```

Breakdown:
- `for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do ... done` — loops over the
  full set of standard HTTP methods worth checking.
- `echo -n "$method: "` — prints the method name as a label before the result; `-n`
  suppresses the trailing newline so the status code prints on the same line.
- `curl -s -o /dev/null -w "%{http_code}\n"` — same silent-mode, discard-body,
  print-status-code pattern used throughout this series.
- `-X "$method"` — explicitly sets the HTTP request method to the current loop value,
  overriding curl's default of GET.
- `"https://api.example.com/api/v1/users/42"` — a specific, already-confirmed-to-exist
  endpoint (found via Phase 1 or the brute-force pass above).

### Interpreting results

- A method returning `405 Method Not Allowed` confirms the endpoint recognizes and
  explicitly rejects that method — expected, low interest.
- A method returning anything in the `2xx` range that documentation never mentioned is a
  high-priority finding — it means an undocumented write/delete capability may exist on
  a resource you assumed was read-only.
- The `OPTIONS` method deserves special attention: many frameworks respond to `OPTIONS`
  with an `Allow:` response header listing every method actually configured for that
  route, which can reveal the full accepted-method list in a single request without
  needing to enumerate methods one by one.

```bash
curl -s -X OPTIONS -i "https://api.example.com/api/v1/users/42" | grep -i "^allow:"
```

Breakdown:
- `-X OPTIONS` — sends an OPTIONS request specifically to query the server's declared
  capabilities for this route.
- `-i` — includes response headers in the output (normally curl shows only the body).
- `grep -i "^allow:"` — filters to just the line starting with `Allow:` (case-insensitive
  match via `-i`, since header casing varies by server), which is where the method list
  lives when the server implements OPTIONS properly.

## 3. Parameter Discovery

Endpoints frequently accept parameters that are never documented — debug flags,
internal-only filters, or fields left over from an earlier version of the endpoint that
still function even though the current documentation doesn't mention them.

### Why this matters beyond just "more data"

Undocumented parameters are a recurring root cause across multiple API Security Top 10
categories: an undocumented `role` or `is_admin` parameter accepted silently by a user
update endpoint is a mass assignment vulnerability; an undocumented `debug=true` query
parameter can trigger excessive data exposure by returning internal fields not present
in the normal response.

### The manual approach: diffing responses across guessed parameters

```bash
curl -s "https://api.example.com/api/v1/users/42" -o baseline.json
curl -s "https://api.example.com/api/v1/users/42?debug=true" -o test.json
diff baseline.json test.json
```

Breakdown:
- First two lines fetch the same endpoint, once with no extra parameter (`baseline.json`)
  and once with a guessed parameter appended (`test.json`), each redirected to a file
  with `-o` as covered earlier.
- `diff baseline.json test.json` — a standard Unix utility that compares two files
  line by line and prints only the differing lines; here it's used to detect whether
  adding the guessed parameter changed the response body at all — any diff output means
  the server actually read and acted on that parameter, confirming it's a real,
  functioning (if undocumented) input.

### Why automate with Arjun instead of manual guessing

Manually guessing parameter names doesn't scale — real applications can have dozens of
undocumented parameters across hundreds of endpoints. Arjun automates this exact
diffing process against a large built-in parameter wordlist, using a binary-search-style
batching approach to stay efficient against endpoints with strict rate limits. Full
flag-by-flag usage in `tools/arjun.md`.

## 4. Content-Type Fuzzing

Many APIs are built to accept multiple content types (JSON, XML, form-urlencoded) for
the same endpoint, often because of legacy client support, but only the primary content
type receives careful input validation and security review. Sending the same logical
request with a different `Content-Type` header can bypass validation entirely or trigger
different code paths (e.g., XML parsing libraries with entity expansion enabled — see
the XXE file in the web application series for why this matters).

### Testing whether an endpoint accepts an alternate content type

```bash
curl -s -X POST "https://api.example.com/api/v1/users" \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name></user>' \
  -w "\n%{http_code}\n"
```

Breakdown:
- `-X POST` — sets the request method, since content-type fuzzing is most relevant on
  endpoints that accept a request body (POST/PUT/PATCH).
- `-H "Content-Type: application/xml"` — overrides the header to declare the body as XML
  instead of the JSON the documented API expects, testing whether the server's parsing
  layer still processes it.
- `-d '<user><name>test</name></user>'` — the request body itself, formatted as XML to
  match the declared content type.
- `-w "\n%{http_code}\n"` — appends a newline and the response status code after the
  body output, so both the response content and status are visible together.

**What a positive result looks like:** a `200`/`201` response, or any response
indicating the XML body was actually parsed (rather than a `415 Unsupported Media Type`
rejecting it outright), confirms the endpoint has a second, less-scrutinized parsing
path worth testing independently.

## 5. Response-Based Endpoint Inference

Sometimes the most efficient discovery signal isn't a new endpoint at all — it's a
detail buried in a response you already have. Error messages, stack traces, and
response headers frequently leak internal route names, framework details, or references
to other endpoints.

Things to check systematically on every response collected during this phase:

- **Error message bodies** — a 500 error that leaks a stack trace often includes the
  internal file path or route handler name, which can reveal an internal naming
  convention that differs from the public-facing path (e.g., a public `/api/v1/orders`
  route backed by an internal handler class named `LegacyOrderControllerV1`, hinting at
  a `LegacyOrderControllerV2` or a still-live `/api/v2/orders` sibling).
- **Response headers** — `X-Powered-By`, custom `X-API-Version`, or `Link` headers
  (used for pagination or HATEOAS-style APIs) sometimes point directly to other
  endpoint URLs.
- **JSON response bodies with embedded resource links** — REST APIs following HATEOAS
  conventions embed `_links` or `href` fields pointing to related endpoints; even APIs
  that don't formally follow HATEOAS often leak similar structure in nested objects
  (e.g., a user object containing an `"orders_url"` field pointing to an endpoint never
  otherwise discovered).

```bash
curl -s "https://api.example.com/api/v1/users/42" | jq -r '.. | .href? // empty' 2>/dev/null
```

Breakdown:
- `jq -r '.. | .href? // empty'` — `..` is jq's recursive descent operator, walking
  every value in the JSON structure at any nesting depth; `.href?` attempts to extract an
  `href` field from each value, with the trailing `?` suppressing errors on values that
  aren't objects or don't have that field; `// empty` provides a fallback of nothing
  (rather than `null`) when `.href?` doesn't match, so only actual href values print;
  `-r` outputs them as raw strings rather than JSON-quoted.
- `2>/dev/null` — redirects any stderr noise (e.g., from malformed JSON) away from the
  visible output.

## 6. PortSwigger Academy Coverage

**Recon-adjacent, not recon-dedicated**, same disclosure as file 2. No lab category
exists for active API discovery specifically. Relevant transferable material:

- **Access control** labs frequently require discovering an endpoint or parameter
  variant not shown in the application's normal navigation (e.g., finding an admin
  function reachable at a guessable URL) — the discovery step is a small piece of a
  larger access-control lab, not the lab's focus, but the muscle transfers.
- Labs that require enumerating HTTP methods to find an unprotected alternate method
  for a protected action are the closest single-technique overlap with the method
  enumeration technique above.

For structured hands-on practice at the technique level, DVAPI is well suited for
practicing parameter discovery and method enumeration in isolation on small, well-scoped
endpoints. crAPI is the better choice once you want to practice full brute-force +
seeded wordlist discovery against a realistic multi-service API surface.

## 7. Next File

Continue to `04-shadow-and-zombie-apis.md` to turn the raw discovery output from this
phase into a prioritized list of the highest-risk findings: forgotten versions and
undocumented internal endpoints.
