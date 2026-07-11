# API Security Testing Tooling — Fuzzing Tools (ffuf, kiterunner, Arjun)

Cross-reference: file 08 for wordlist selection guidance, file 07 for how these
tools differ from crawling (katana).

## 1. ffuf — Fast Web Fuzzer

ffuf (Fuzz Faster U Fool) is a Go-based HTTP fuzzer. For API testing it is used for
three main jobs: path/endpoint brute-forcing, parameter fuzzing, and JSON body
field fuzzing.

### 1.1 Installation
```
go install github.com/ffuf/ffuf/v2@latest
```

### 1.2 Core Flags (Full Breakdown)

```
ffuf -u https://api.target.com/v1/FUZZ -w /path/wordlist.txt -mc 200,201,204 \
     -t 50 -rate 100 -H "Authorization: Bearer <token>" -o results.json -of json
```

- `-u <url>`: target URL. The literal string `FUZZ` marks the injection point —
  ffuf substitutes each wordlist line into every position where `FUZZ` appears.
- `-w <path>`: path to the wordlist file. Multiple `-w` flags with named keywords
  (e.g., `-w list1.txt:W1 -w list2.txt:W2`) allow multiple simultaneous fuzz
  positions, each referenced by its own keyword (`W1`, `W2`) instead of `FUZZ`.
- `-mc <codes>`: **match** responses with these HTTP status codes (comma-separated).
  Default is `-mc 200,204,301,302,307,401,403,405` — for API fuzzing, explicitly set
  this to whatever your target's "valid endpoint" signal is (often `200,201,204,400`
  since a 400 on a POST-only endpoint hit with GET can still confirm existence).
- `-fc <codes>`: **filter out** (hide) responses with these status codes — the
  inverse of `-mc`. Useful for hiding a noisy catch-all `404` page that actually
  returns `200` (soft-404), which you'd otherwise have to filter by size instead.
- `-t <n>`: number of concurrent threads. Default 40. Lower this (e.g., `-t 10`)
  against rate-limited API gateways to avoid tripping WAF/rate-limit blocks and
  getting your source IP banned mid-scan.
- `-rate <n>`: maximum requests per second, overriding raw thread-based throughput.
  More predictable than `-t` alone for staying under a known rate limit (e.g., a
  gateway documented as allowing 100 req/min → `-rate 1` with headroom).
- `-H "<header>"`: add a custom header, repeatable. Essential for API fuzzing since
  almost every API requires `Authorization` and often a versioning header like
  `Accept: application/vnd.api+json;version=2`.
- `-X <method>`: HTTP method (default `GET`). Set to `POST`, `PUT`, `PATCH`, `DELETE`
  as needed — combine with `-d` for body fuzzing.
- `-d "<data>"`: request body data. Use with `-X POST` and `Content-Type` header set
  via `-H`.
- `-o <file>` / `-of <format>`: output file and format. Formats: `json`, `ejson`,
  `html`, `md`, `csv`, `all`. `json` output is the most useful for piping into `jq`
  (see file 07) for further automated processing.
- `-mr <regex>` / `-fr <regex>`: match/filter responses by a regex against the
  response body — useful when status code alone doesn't distinguish valid from
  invalid (e.g., filter out responses containing `"error":"not_found"` in the JSON
  body even if the status code is 200).
- `-fs <size>` / `-ms <size>`: filter/match by response size in bytes — the classic
  way to hide a repetitive soft-404 page once you've identified its consistent byte
  size.
- `-fw <n>` / `-mw <n>`: filter/match by response **word count** — an alternative
  size-based signal that's sometimes more stable than byte size when responses have
  minor variable content (timestamps, request IDs) padding the byte count.
- `-recursion`: enables recursive fuzzing — when a matched result looks like a
  directory/path segment, ffuf automatically re-fuzzes into it.
- `-recursion-depth <n>`: caps how many levels deep `-recursion` will go (default
  unlimited, which can run away on deeply nested API path structures — cap it at
  `2` or `3` for typical REST APIs).
- `-e <extensions>`: comma-separated list of extensions to append to each wordlist
  entry (e.g., `-e .json,.xml`) — more relevant to legacy web apps than modern JSON
  APIs, but occasionally useful against APIs that serve format-suffixed routes
  (`/users.json`).
- `-c`: colorize terminal output (readability only, no functional effect).
- `-v`: verbose output — prints full request/response info per match instead of the
  compact single-line summary.
- `-timeout <n>`: per-request timeout in seconds (default 10) — raise this against
  slow backend APIs to avoid false negatives from premature timeouts.
- `-p <delay>`: fixed delay between requests per thread, e.g., `-p 0.1-0.5` for a
  randomized delay range — combine with low `-t` for stealth against basic
  rate-limit/anomaly detection.

### 1.3 API-Specific Fuzzing Modes

**Path/endpoint brute-forcing:**
```
ffuf -u https://api.target.com/v1/FUZZ -w seclists/api-endpoints.txt \
     -H "Authorization: Bearer <token>" -mc 200,201,204,400,401,403 -t 30
```

**Path parameter (resource ID) fuzzing** — testing for BOLA by iterating numeric or
UUID-like IDs:
```
ffuf -u https://api.target.com/v1/users/FUZZ/orders -w numeric-ids.txt \
     -H "Authorization: Bearer <low_priv_token>" -mc 200 -fc 403,404
```

**Header fuzzing** (e.g., discovering an internal API version header or a hidden
debug header):
```
ffuf -u https://api.target.com/v1/status -H "X-FUZZ: test" \
     -w header-names.txt:FUZZ -mode clusterbomb
```
Note: `FUZZ` in a header **name** requires ffuf's raw-request mode (`-request` with
a raw file) since standard `-H` substitution fuzzes header *values*, not names — see
`-request` below for header-name fuzzing.

**JSON body field fuzzing** — this is the most API-specific ffuf use case, fuzzing
the *value* of a specific JSON key inside a POST/PUT body:
```
ffuf -u https://api.target.com/v1/users -X POST \
     -H "Content-Type: application/json" -H "Authorization: Bearer <token>" \
     -d '{"username":"testuser","role":"FUZZ"}' \
     -w roles-wordlist.txt -mc 200,201 -fc 400,403
```
Here `FUZZ` sits inside the JSON string value for `"role"` — useful for testing
mass assignment (does supplying `"role":"admin"` on user creation get accepted?
cross-reference the BOPLA/mass assignment series) or enum/value validation bypass.

**Multiple simultaneous positions** (clusterbomb across two JSON fields):
```
ffuf -u https://api.target.com/v1/users -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"W1","role":"W2"}' \
     -w usernames.txt:W1 -w roles.txt:W2 -mode clusterbomb -mc 200,201
```
- `-mode <mode>`: `clusterbomb` (every combination of all wordlists — Cartesian
  product) vs `pitchfork` (parallel, line-by-line pairing across wordlists — use
  when you have matched pairs like username:expected-role and want to test each
  pair once rather than every combination).

**Raw request file mode** (needed for fuzzing header names, or replaying a captured
Burp request with full fidelity):
```
ffuf -request raw_request.txt -request-proto https -w wordlist.txt
```
- `-request <file>`: path to a raw HTTP request file (as saved/exported from Burp's
  "Copy to file" or "Save item"), with `FUZZ` placed anywhere in the raw text
  including header names.
- `-request-proto <http|https>`: since the raw request file has no scheme, this
  tells ffuf whether to connect over HTTP or HTTPS.

### 1.4 Real-World Notes

- Many API gateways return `200 OK` with a JSON error envelope (`{"error":"not
  found"}`) instead of an HTTP 404 for missing routes — `-mc` alone will produce
  massive false positives on these targets. Always pair `-mc 200` fuzzing with `-fr`
  or `-fs`/`-fw` filtering once you've identified the "not found" response's
  signature.
- Combine `-recursion` cautiously on versioned APIs (`/v1/`, `/v2/`) — recursion
  depth can explode combinatorially if every discovered segment is itself
  fuzzable; cap `-recursion-depth` and prefer running kiterunner (below) for
  realistic nested route structures instead.

## 2. kiterunner — Realistic API Route Brute-Forcing

kiterunner (from Assetnote) is purpose-built for API endpoint discovery. Unlike
ffuf's flat wordlist-per-segment model, kiterunner uses **route dictionaries**
built from real-world API specs (Swagger/OpenAPI files scraped from public sources),
so it guesses realistic, versioned, RESTful path *and method* combinations (e.g.,
`GET /api/v2/users/{id}/orders`) rather than single flat path segments.

### 2.1 Installation
```
git clone https://github.com/assetnote/kiterunner.git && cd kiterunner && make build
```
Prebuilt binaries and the required wordlist/route dictionaries (`.kite` and `.json`
files) are published in Assetnote's `kiterunner` and `wordlists` GitHub releases.

### 2.2 Core Flags (Full Breakdown)

```
kr scan https://api.target.com -w routes-large.kite -x 20 -j -k -A "Bearer <token>"
```

- `scan`: kiterunner's primary subcommand — brute-force a single target (as opposed
  to `brute`, used for scanning many hosts against many wordlists at once, or
  `kb` for managing the local kite-file database).
- `<url>`: the target base URL kiterunner will prepend every guessed route to.
- `-w <file.kite>`: the route dictionary file. Assetnote publishes several sizes
  (`routes-small.kite`, `routes-large.kite`, `data/kiterunner/routes-*`), where
  larger files trade scan time for coverage. `.kite` is kiterunner's compiled
  binary route-dictionary format (compiled from raw wordlists via `kb`, below).
- `-x <n>`: number of concurrent connections (analogous to ffuf's `-t`).
- `-j`: output results as JSON (machine-parseable, pipeable into `jq` — see file 07).
- `-k`: skip TLS certificate verification — useful against internal/staging APIs
  with self-signed certs.
- `-A "<header>"`: add an `Authorization` header shortcut (equivalent to a full `-H`
  but specifically for the common auth case); use `-H "<header>"` for arbitrary
  additional headers, repeatable.
- `--fail-status-codes <codes>`: comma-separated status codes to treat as
  "not found" and suppress from output (default excludes common 404-equivalents;
  override this for APIs with nonstandard "not found" codes).
- `--ignore-length <n>`: suppress results whose response body length exactly
  matches `<n>` bytes — used the same way as ffuf's `-fs`, to filter a known
  soft-404 page size.
- `--full-scan`: scans every route in the dictionary against every discovered
  "valid" base path, rather than stopping early once a path segment is confirmed
  invalid — increases coverage at the cost of scan time; use on high-value targets
  where thoroughness matters more than speed.
- `-o <file>`: write results to a file instead of (or in addition to) stdout.
- `--delay <ms>`: fixed delay in milliseconds between requests, for rate-limit
  evasion (analogous to ffuf's `-p`).

### 2.3 Building Custom Route Dictionaries

If you have a target-specific wordlist (e.g., extracted parameter/route names from
a leaked Swagger file, or Arjun output — see 3.0 below) and want to compile it into
kiterunner's `.kite` format for faster repeated scans:
```
kb kite build routes-custom.kite -w custom-wordlist.txt
```
- `kb kite build <output.kite> -w <input wordlist>`: compiles a plain text wordlist
  of path segments into kiterunner's binary `.kite` format.

### 2.4 Real-World Notes

- kiterunner's real-world route dictionaries (scraped from public Swagger/OpenAPI
  files across the internet) are its main advantage over ffuf: it guesses paths
  like `/api/v1/users/{id}/payment-methods` as a *unit*, matching real API design
  patterns, rather than fuzzing each path segment independently and missing
  multi-segment realistic structures. Use kiterunner first for broad realistic
  coverage, then ffuf for target-specific wordlists once you understand the API's
  naming conventions.
- kiterunner also brute-forces **HTTP methods** per discovered path automatically
  (GET/POST/PUT/DELETE/PATCH), surfacing method-based BFLA findings (e.g., a `GET`
  on `/users/{id}` is allowed for any user, but so is an undocumented `DELETE`) that
  a pure-path fuzzer like ffuf would miss unless you separately iterate `-X`.

## 3. Arjun — HTTP Parameter Discovery

Arjun discovers hidden/undocumented HTTP GET/POST parameters by sending batches of
candidate parameter names and detecting which ones change server behavior — the
same underlying technique as Param Miner (file 02) but as a standalone CLI tool
better suited for scripted/CI use.

### 3.1 Installation
```
pip install arjun
```

### 3.2 Core Flags (Full Breakdown)

```
arjun -u https://api.target.com/v1/search -m GET -w params.txt -t 10 \
      --headers "Authorization: Bearer <token>" -oJ results.json
```

- `-u <url>`: target URL to test for hidden parameters.
- `-m <method>`: HTTP method to test — `GET`, `POST`, `JSON`, `XML`, `HEADERS`. The
  `JSON` mode specifically tests for hidden parameters inside a JSON request body
  (as opposed to querystring/form params), which is the mode most relevant to
  modern REST APIs.
- `-w <file>`: custom wordlist of candidate parameter names. If omitted, Arjun uses
  its bundled default wordlist (~25,000 common parameter names).
- `-t <n>`: number of threads (default 25).
- `-d <delay>`: delay between requests in seconds — for rate-limit evasion.
- `--headers "<header>"`: custom headers, semicolon- or newline-separated for
  multiple; use for `Authorization` and any required API version/content headers.
- `--data <body>`: for `-m POST`/`JSON`/`XML` modes, a template request body that
  Arjun merges candidate parameters into (e.g., a valid JSON skeleton so injected
  test parameters sit alongside required fields the endpoint expects).
- `-oJ <file>`: output results as JSON. Other formats: `-oT <file>` (plain text),
  `-oB <file>` (Burp-importable XML).
- `--stable`: forces extra verification requests before confirming a parameter as
  valid, reducing false positives on noisy/inconsistent APIs at the cost of speed.
- `-c <n>`: chunk size — how many candidate parameters Arjun bundles into a single
  test request before narrowing down which specific one caused the behavioral
  change (binary-search style). Lower `-c` on APIs with strict parameter-count
  limits or strict schema validation that rejects requests with too many unknown
  fields at once.
- `--include <string>`: only report a parameter as valid if this string appears in
  the response when the parameter is included — a manual match-string override for
  targets where Arjun's automatic response-diffing heuristic is unreliable.
- `-i <import-file>`: import a list of URLs from a file to test in bulk (instead of
  a single `-u`), useful for running Arjun across every endpoint discovered by
  ffuf/kiterunner/katana in one pass.

### 3.3 Real-World Notes

- Run Arjun's `JSON` mode specifically against **write** endpoints (`POST`/`PUT`/
  `PATCH`) as part of mass assignment testing — a hidden accepted field like
  `is_admin` or `account_balance` on a user-editable JSON body is a direct
  cross-reference to the BOPLA/mass assignment series' core vulnerability class.
- Arjun's default wordlist is generic (web parameters generally); for best API
  coverage, supply a domain-specific wordlist via `-w`, ideally seeded from
  Assetnote's API-specific wordlists or SecLists (see file 08).
