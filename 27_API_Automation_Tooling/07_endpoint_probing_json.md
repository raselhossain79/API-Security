# API Security Testing Tooling — Endpoint Probing & JSON Processing (httpx, katana, jq)

Cross-reference: file 03 for the fuzzing tools whose output typically feeds into
httpx for validation, file 08 for wordlist sourcing that feeds katana/ffuf.

## 1. httpx — Fast HTTP Probing and Validation

httpx (ProjectDiscovery — distinct from the unrelated Python `httpx` HTTP client
library) takes a list of URLs/hosts and rapidly determines which are live,
capturing status codes, titles, technology fingerprints, and other metadata at
scale. In an API testing workflow, httpx is the validation step that runs *after*
ffuf/kiterunner/katana produce a large list of candidate endpoints — turning
thousands of guesses into a confirmed, annotated list of real, live endpoints worth
manually investigating.

### 1.1 Installation
```
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### 1.2 Core Flags (Full Breakdown)

```
cat candidate-endpoints.txt | httpx -status-code -title -tech-detect \
    -content-length -follow-redirects -threads 50 -json -o httpx-results.json
```

- `-l <file>`: file of target URLs/hosts (one per line) to probe — alternative to
  piping via stdin (shown above with `cat | httpx`), both are equivalent.
- `-status-code`: include the HTTP status code of each response in output.
- `-title`: extract and include the page/response `<title>` (for HTML) — less
  relevant for pure JSON APIs but useful when a target mixes API and web-app
  routes.
- `-tech-detect`: run Wappalyzer-style technology fingerprinting against each
  response (identifies frameworks, servers, and libraries from headers/body
  signatures) — useful for quickly spotting which discovered hosts run a
  recognizable API gateway (Kong, Apigee, AWS API Gateway signatures) vs a custom
  backend.
- `-content-length`: include response body size in output — useful as a quick
  manual signal for spotting soft-404 pages (many identical-length responses
  likely share a generic error page) before feeding results into more precise
  filtering in ffuf/nuclei.
- `-content-type`: include the `Content-Type` response header — useful for
  quickly separating JSON API responses from HTML/other content among a mixed
  candidate list.
- `-follow-redirects`: follow HTTP redirects and report the final resolved
  URL/status rather than just the initial redirect response — important for APIs
  that redirect HTTP→HTTPS or unversioned→versioned paths (`/users` → `/v2/users`).
- `-threads <n>`: concurrency level (default 50).
- `-rate-limit <n>`: max requests per second, for rate-limit-sensitive targets
  (analogous to ffuf's `-rate`).
- `-timeout <n>`: per-request timeout in seconds.
- `-retries <n>`: retry count for failed/timed-out requests.
- `-mc <codes>` / `-fc <codes>`: match/filter by status code — same semantics as
  ffuf's equivalent flags (file 03).
- `-ml <n>` / `-fl <n>`: match/filter by response body length in bytes.
- `-json`: output each result as a JSON object (one per line, JSONL format) —
  the format to use when piping into `jq` for further processing.
- `-o <file>`: output file.
- `-H "<header>"`: custom header, repeatable — required for probing authenticated-
  only API routes (an endpoint might 401/403 without auth but 200 with it, which
  changes its "liveness" classification).
- `-x <method>`: HTTP method to probe with (default `GET`) — set to `POST`, etc.,
  for endpoints that don't respond meaningfully to GET (though this requires
  supplying a valid body via `-body` for most POST-only APIs to get a meaningful
  signal rather than a generic 400).
- `-body "<data>"`: request body to send, paired with `-x`.
- `-silent`: suppress httpx's banner/progress output, printing only results — the
  standard flag to use when piping httpx's output directly into another tool
  rather than reviewing interactively.
- `-probe`: prints a simple boolean-style summary tag (`[SUCCESS]`/`[FAILED]`) per
  target — a lightweight liveness-only mode when you don't need full metadata.
- `-vhost`: probe for virtual host routing differences — sends the same request
  with different `Host` headers to detect if a single IP serves multiple distinct
  API backends based on hostname, relevant to host header injection testing
  (cross-reference the host header injection series).
- `-ip`: resolve and include each target's IP address in output — useful for
  spotting when multiple "different" API hostnames actually resolve to the same
  backend infrastructure.

### 1.3 Typical Pipeline Position

```
ffuf -u https://api.target.com/v1/FUZZ -w wordlist.txt -mc 200,201,204,301,302,401,403 -s \
  | httpx -silent -status-code -title -tech-detect -json -o live-endpoints.json
```
- `-s` on ffuf here is ffuf's silent flag, suppressing ffuf's own formatted output
  in favor of raw matched URLs, which httpx then re-validates and enriches. This
  two-stage pattern — broad/noisy discovery tool piped into httpx for precise
  validation — is the standard way to convert a large candidate list into a
  trustworthy target list for manual testing or a subsequent nuclei scan.

### 1.4 Real-World Notes

- Always run discovered endpoints through httpx with `-tech-detect` early — an API
  gateway fingerprint (Kong, Apigee, AWS API Gateway, Cloudflare) materially
  changes testing approach, since gateway-specific quirks (header normalization,
  built-in rate limiting, WAF rulesets) affect which other tools' default settings
  need adjustment (cross-reference file 01's note that this series has no
  standalone gateway-bypass section — httpx's tech-detect output is where that
  context gets gathered instead, feeding into the relevant vulnerability-class
  series' own gateway sections).

## 2. katana — Crawling-Based Endpoint Discovery

katana (ProjectDiscovery) discovers endpoints by **crawling** — following HTML
links, JavaScript file references, sitemap.xml, and robots.txt — as opposed to
ffuf/kiterunner's **brute-force guessing** from a wordlist (file 03). The two
approaches are complementary, not competing: katana finds endpoints that are
*referenced somewhere* (even obscurely, e.g., buried in a minified JS bundle) but
would never appear in a generic wordlist; ffuf/kiterunner find endpoints that exist
but have zero inbound references anywhere the crawler can reach, as long as the
guess happens to be in the wordlist. A thorough recon phase runs both.

### 2.1 Installation
```
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

### 2.2 Core Flags (Full Breakdown)

```
katana -u https://app.target.com -d 3 -jc -kf all -H "Authorization: Bearer <token>" \
       -mr "/api/" -o katana-endpoints.txt -silent
```

- `-u <url>`: starting URL(s) to crawl from — repeatable, or use `-list <file>`
  for many seed URLs at once.
- `-d <n>`: crawl depth — how many link-hops deep katana will follow from the seed
  URL(s). Default 2-3; raise for large single-page applications where meaningful
  API-referencing JS may be several navigation steps deep, but watch for runaway
  crawl time on large sites.
- `-jc`: **JavaScript crawling/parsing** — parses JS files found during the crawl
  for endpoint-like strings (URL patterns, fetch/XHR call targets, API path
  constants) rather than only following literal `<a href>` links. This is the
  single most important flag for API discovery specifically, since modern SPAs
  reference their entire API surface from JS bundles rather than server-rendered
  HTML links.
- `-jsl`: **JavaScript link extraction only** mode — a lighter-weight variant that
  only extracts URL-shaped strings from JS without katana's fuller JS parsing/
  execution — useful when `-jc` is too slow/resource-heavy on very large JS
  bundles and you want a faster first pass.
- `-kf <field-scope>`: **known files** — instructs katana to also fetch and parse
  well-known files as additional endpoint sources. `all` fetches and parses both
  `robots.txt` and `sitemap.xml`; alternatively specify `robotstxt` or `sitemapxml`
  individually.
- `-H "<header>"`: custom header, repeatable — required to crawl authenticated
  sections of an SPA (without a valid session, the crawler only sees the
  unauthenticated/login-page portion of the app and its API surface).
- `-mr <regex>`: **match regex** — only report/follow URLs matching this pattern,
  e.g., `-mr "/api/"` to focus results on API-path-shaped URLs and suppress
  static asset/marketing-page noise from the output.
- `-fr <regex>`: **filter regex** — inverse of `-mr`, exclude URLs matching this
  pattern (e.g., `-fr "\.(png|jpg|css|woff2)$"` to strip static assets from
  output).
- `-mdc <condition>` / `-fdc <condition>`: match/filter by response status code or
  other response-derived condition, DSL-based (e.g., `-mdc "status_code==200"`) —
  finer-grained than a simple `-mc` code list, allowing boolean expressions across
  multiple response attributes.
- `-cs <scope-regex>` / `-cos <out-of-scope-regex>`: crawl-scope regex — restricts
  which discovered links katana will actually follow (vs `-mr`/`-fr`, which filter
  *output* but might still follow out-of-scope links internally) — important for
  staying within engagement scope when a target app links to third-party
  domains.
- `-do`: **display only in-scope endpoints** — a related scope-enforcement flag,
  ensures out-of-scope discovered URLs are suppressed from output entirely.
- `-c <n>`: concurrency (default 10).
- `-p <n>`: parallelism — number of concurrent crawl workers processing different
  seed URLs simultaneously when using `-list` with multiple seeds.
- `-rd <n>`: rate-limit delay in milliseconds between requests.
- `-timeout <n>`: per-request timeout in seconds.
- `-o <file>`: output file (one discovered URL per line by default).
- `-jsonl`: output results as JSONL instead of plain text — for piping into `jq`.
- `-silent`: suppress banner/progress output, printing only discovered URLs.
- `-headless`: use a real headless browser (chromium) for crawling instead of
  katana's default non-headless HTTP-based crawler — necessary for SPAs that
  construct API-calling routes dynamically at runtime via client-side JS execution
  rather than having them present as static strings in the JS source (which
  `-jc` alone can miss). Slower but more thorough against heavily client-rendered
  applications.
- `-xhr`: (used with `-headless`) specifically capture XHR/fetch requests made by
  the browser during headless rendering — this is often the single most valuable
  flag combination (`-headless -xhr`) for API discovery against modern SPAs, since
  it captures the *actual* API calls the app makes at runtime, including ones
  assembled dynamically that static JS parsing would never find.
- `-form-extraction`: extract HTML form fields/action URLs during crawl — more
  relevant to traditional web apps than JSON APIs, but included for completeness
  when a target mixes both.

### 2.3 Crawling vs Brute-Forcing — Practical Guidance

| Signal | Use katana (crawl) | Use ffuf/kiterunner (brute-force) |
|---|---|---|
| Endpoint is referenced in app JS/HTML | ✅ finds it | only if guess is in wordlist |
| Endpoint has zero inbound references (orphaned/legacy) | ❌ never finds it | ✅ finds it if guessed |
| Need to understand the app's *actual* used API surface | ✅ best signal | less relevant |
| Need to find hidden/undocumented/debug endpoints | less likely | ✅ primary use case |
| Target is a heavily client-rendered SPA | ✅ with `-headless -xhr` | still useful for guessing unlinked routes |

Run both. katana's crawl output and ffuf/kiterunner's brute-force output should be
merged and deduplicated (`sort -u`, or via `jq`, below) before feeding the combined
list into httpx for validation.

### 2.4 Real-World Notes

- `-jc` (JS parsing) is essential but not sufficient against modern SPAs built
  with frameworks that construct API call URLs via string concatenation or
  runtime config objects rather than literal string constants — for these, `
  -headless -xhr` is the only reliable discovery method, at the cost of
  significantly slower crawl speed.
- Always scope-restrict katana with `-cs`/`-do` on engagements involving a target
  that links out to third-party domains (payment processors, CDNs, social login
  providers) — an unrestricted crawl will happily wander off-target and waste
  both time and, more importantly, requests against systems outside your
  authorized scope.

## 3. jq — Command-Line JSON Processing

jq is a JSON query/filter language and CLI processor. In an API testing workflow
it is the connective tissue between every other tool in this series: piping
curl/httpx/ffuf/nuclei/newman JSON output through jq to extract, filter, and
reshape fields is a constant, recurring task.

### 3.1 Installation
```
apt install jq        # Debian/Ubuntu
brew install jq        # macOS
```

### 3.2 Core Syntax and Filters (Full Breakdown)

**Basic filtering — extract a field**:
```
curl -s https://api.target.com/v1/users/1 -H "Authorization: Bearer $TOKEN" | jq '.'
```
- `jq '.'`: the identity filter — pretty-prints the input JSON with syntax
  highlighting and indentation, with no transformation. The most common first
  step when inspecting a raw API response.

```
curl -s .../users/1 | jq '.email'
```
- `.email`: dot-notation field access — extracts the value of the top-level
  `email` key. Nested access chains dots: `.profile.address.city`.

**Array indexing and iteration**:
```
curl -s .../users | jq '.[0]'          # first element of a top-level JSON array
curl -s .../users | jq '.[].email'     # iterate every array element, extract .email from each
curl -s .../users | jq '.data[].id'    # for a {"data": [...]} envelope, iterate the nested array
```
- `.[]`: the array/object iterator — expands every element for downstream
  filtering, one output value per element.

**Filtering with conditions**:
```
curl -s .../users | jq '.[] | select(.role == "admin")'
```
- `select(<condition>)`: keeps only elements where the condition is true — the jq
  equivalent of a `WHERE` clause. Common security-testing use: filtering a bulk
  user-list API response down to only admin-role accounts, or filtering nuclei/
  httpx JSON output down to only `high`/`critical` severity findings.

**Field extraction with reshaping (building a new object)**:
```
curl -s .../users | jq '.[] | {id: .id, email: .email, role: .role}'
```
- `{key: <expr>, ...}`: object construction syntax — builds a new, smaller JSON
  object from selected fields of the input, useful for trimming verbose API
  responses down to just the fields relevant to a specific finding before pasting
  into a report.

**Raw output (no quotes, for shell piping)**:
```
curl -s .../users | jq -r '.[].email'
```
- `-r` / `--raw-output`: outputs string values without surrounding JSON quotes —
  essential when piping jq output into another shell command expecting plain text
  (e.g., feeding extracted emails or IDs into a `while read` loop that fires
  follow-up requests per value).

**Compact output (single line, for log/pipeline use)**:
```
jq -c '.'
```
- `-c` / `--compact-output`: prints each JSON object on a single line rather than
  pretty-printed — the correct mode for JSONL log files or piping into
  line-oriented tools (`grep`, `wc -l`).

**Slurping multiple JSON objects into one array**:
```
cat httpx-results.jsonl | jq -s '.'
```
- `-s` / `--slurp`: reads all input (e.g., a JSONL file with one JSON object per
  line, as produced by httpx/nuclei's `-json` output) and wraps it into a single
  JSON array — necessary before running array-level jq operations (like `sort_by`,
  `group_by`, `length`) against line-delimited tool output.

**Sorting and grouping**:
```
cat nuclei-results.json | jq -s 'sort_by(.info.severity)'
cat httpx-results.jsonl | jq -s 'group_by(.status_code)'
```
- `sort_by(<expr>)`: sorts an array by the given field expression.
- `group_by(<expr>)`: groups array elements into sub-arrays sharing the same value
  for the given expression — useful for quickly seeing "how many discovered
  endpoints returned each status code" from httpx output.

**Counting**:
```
cat ffuf-results.json | jq '.results | length'
```
- `length`: returns the count of elements in an array (or characters in a string,
  or keys in an object) — quick sanity-check of how many results a scan produced.

**Combining filters with pipes**:
```
cat nuclei-results.json | jq -s '.[] | select(.info.severity == "critical") | .info.name'
```
jq filters chain with `|` the same way shell commands do — read left to right as a
pipeline of transformations applied to each value in sequence.

**Comparing two JSON files (diff-style, useful for retest verification)**:
```
diff <(jq -S '.' before.json) <(jq -S '.' after.json)
```
- `-S` / `--sort-keys`: sorts object keys alphabetically before output — necessary
  before diffing two JSON files, since two semantically identical JSON objects can
  have keys in different orders and would otherwise produce a noisy line-by-line
  diff.

### 3.3 Practical Pipeline Examples for This Series

**Extract only verified secrets from truffleHog JSON output**:
```
cat trufflehog-output.json | jq -s '.[] | select(.Verified == true) | {source: .SourceMetadata, secret: .Raw}'
```

**Extract live, JSON-content-type endpoints from httpx output for further nuclei scanning**:
```
cat httpx-results.json | jq -r 'select(.content_type == "application/json") | .url' > api-endpoints.txt
nuclei -l api-endpoints.txt -tags api -json-export nuclei-results.json
```

**Summarize Newman collection run results by pass/fail count**:
```
cat newman-results.json | jq '.run.stats.assertions'
```

### 3.4 Real-World Notes

- jq's `-r` (raw output) is the single most-used flag in practice, since almost
  every downstream use of extracted data (feeding into another tool's `-l`/`-w`
  input file, or a shell loop) requires plain text lines rather than JSON-quoted
  strings.
- Building a small library of reusable jq one-liners (as in 3.3) for your common
  tool-output formats (httpx, nuclei, newman, truffleHog/gitleaks) saves
  significant time across engagements, since these tools' JSON schemas are stable
  across versions and the same filters keep working project to project.
