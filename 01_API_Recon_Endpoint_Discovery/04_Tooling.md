# Tooling Reference — API Recon Toolset

This file covers the four core tools used throughout this series in full
flag-by-flag depth: **kiterunner** (API-aware endpoint brute-forcing),
**Arjun** (parameter discovery), **ffuf** (general-purpose fuzzing with
API-specific application), and **Amass**/**Subfinder** (subdomain recon for
finding API-specific hosts). Read this alongside `02_Passive_Recon.md` and
`03_Active_Discovery.md`, which reference these tools in context.

---

## 1. Kiterunner — API-Aware Endpoint Brute-Forcing

### Why Kiterunner Instead of a Generic Fuzzer for This Job

Kiterunner (`kr`) was purpose-built for API endpoint discovery, unlike
general-purpose directory brute-forcers. Its key advantage: it doesn't just
try flat wordlist entries against a single path template — it uses
**routes** derived from real-world Swagger/OpenAPI specs scraped across the
internet, meaning it tries realistic, full request shapes (method +
path + likely parameters) rather than guessing bare path segments one at a
time. This produces meaningfully better hit rates against real APIs than a
generic wordlist-based brute-force.

### Installation Note

```bash
git clone https://github.com/assetnote/kiterunner.git && cd kiterunner && make build
```

- `git clone ...` — downloads the kiterunner source repository.
- `&& cd kiterunner` — changes into the cloned directory, only if the clone
  succeeded (`&&` chains commands so a failed clone doesn't attempt to `cd`
  into a nonexistent folder).
- `&& make build` — runs the project's Makefile build target to compile the
  Go binary, again only if the previous step succeeded.

### Core Scan Command

```bash
kr scan https://target.com -w routes-large.kite -x 20 -j 10 -t 8 --fail-status-codes 400,404,426,502,503
```

- `kr scan` — the primary subcommand; performs an active scan against a
  target using a specified route wordlist.
- `https://target.com` — the target base URL.
- `-w routes-large.kite` — specifies the wordlist file. Kiterunner ships with
  pre-built `.kite` route files (`routes-large.kite`, `routes-small.kite`)
  compiled from real-world API specs — these are binary/compiled formats, not
  plain text, containing full method+path+parameter combinations rather than
  bare path strings.
- `-x 20` — sets the maximum number of redirects to follow per request before
  giving up (prevents the scan from getting stuck in redirect loops some
  misconfigured APIs produce).
- `-j 10` — job concurrency; the number of parallel scan "jobs" kiterunner
  runs — distinct from raw thread count, this controls how many independent
  route-testing workflows run simultaneously.
- `-t 8` — per-job thread count; combined with `-j`, the effective total
  concurrency is roughly `-j` × `-t`. Tune both together based on target
  rate-limit tolerance (see the WAF/Gateway section in
  `03_Active_Discovery.md`).
- `--fail-status-codes 400,404,426,502,503` — tells kiterunner which status
  codes should be treated as "this route does not exist" and therefore
  excluded from results by default. Notably, `401` and `403` are deliberately
  **not** included here — consistent with the response-inference technique
  covered earlier, since those codes typically mean the route exists but is
  access-restricted, and you want kiterunner to surface those as hits, not
  silently discard them.

### Scanning With a Specific Wordlist Subset (Faster, Targeted Runs)

```bash
kr scan https://target.com -w routes-small.kite -A "MyPentestTool/1.0" --delay 200ms
```

- `-w routes-small.kite` — the smaller, faster route file; a reasonable
  starting point before committing to the much larger full route set, useful
  when time or rate-limit budget is constrained.
- `-A "MyPentestTool/1.0"` — sets a custom User-Agent string for every
  request. Directly relevant to the WAF fingerprinting discussion earlier —
  kiterunner's default User-Agent is well-known and easily blocklisted, so
  overriding it is a realistic evasion step on real (non-lab) engagements.
- `--delay 200ms` — inserts a fixed delay between requests; a direct
  throttling control to avoid tripping rate-based detection on production
  gateways, at the cost of total scan time.

### Scanning Using a Spec File Directly (When You Already Have One)

```bash
kr brute https://target.com --kitebuilder-full openapi.json
```

- `kr brute` — an alternate subcommand focused on brute-forcing derived
  directly from a provided specification rather than kiterunner's built-in
  route corpus.
- `--kitebuilder-full openapi.json` — points kiterunner at a locally-obtained
  OpenAPI spec (e.g., one found during passive recon) and instructs it to
  derive its own request templates directly from that file, testing every
  documented endpoint/method combination plus close variations (like nearby
  version prefixes) rather than relying on its generic internet-sourced route
  corpus.

### Real-World Notes

- Kiterunner's real value shows up against large, complex APIs with many
  resource types — for a small API with a handful of endpoints, a targeted
  ffuf run with a hand-built wordlist can be faster to configure and just as
  effective.
- The `.kite` route files are periodically updated by the Assetnote team as
  new leaked specs get incorporated — check for an updated release before a
  long engagement rather than relying on a stale local copy.

---

## 2. Arjun — HTTP Parameter Discovery

### Mechanism Recap

Arjun automates the parameter-guessing technique described in
`03_Active_Discovery.md` — it sends a baseline request, then batches large
numbers of candidate parameter names against the target, comparing each
response against the baseline to flag parameters that produce a meaningfully
different result.

### Core Command

```bash
arjun -u https://target.com/api/users/123 -m GET -o results.json -t 10 --stable
```

- `-u https://target.com/api/users/123` — the target endpoint URL to test.
- `-m GET` — the HTTP method to use for every fuzzing request. Arjun also
  supports `POST`, `PUT`, `JSON` (POST with a JSON body instead of form
  encoding), and `XML` as method values.
- `-o results.json` — writes discovered parameters to a JSON file instead of
  only printing to stdout, useful for feeding into later automated steps or
  documentation.
- `-t 10` — thread count; number of concurrent requests. As with kiterunner
  and ffuf, tune this down against rate-limited production targets.
- `--stable` — as introduced in `03_Active_Discovery.md`: forces Arjun to
  send extra confirmation requests before reporting a parameter as valid,
  reducing false positives on APIs with non-deterministic or load-balanced
  responses.

### Using a Custom Wordlist Instead of Arjun's Built-In List

```bash
arjun -u https://target.com/api/search -m GET -w custom-api-params.txt --include "session={{session_token}}"
```

- `-w custom-api-params.txt` — overrides Arjun's default bundled parameter
  wordlist with your own — useful once JS mining or spec analysis has already
  surfaced candidate parameter names specific to this target, letting you
  prioritize a small, high-signal list before falling back to Arjun's larger
  generic one.
- `--include "session={{session_token}}"` — injects a fixed value (here, a
  session/auth token) into every request Arjun sends, using Arjun's templating
  syntax (`{{...}}` is replaced with the literal value given). Necessary for
  testing authenticated endpoints, since without this every request would be
  sent unauthenticated and likely just return a uniform `401`.

### Testing a POST Endpoint With a JSON Body

```bash
arjun -u https://target.com/api/users -m JSON --headers "Content-Type: application/json" -o post-params.json
```

- `-m JSON` — tells Arjun to send candidate parameters as fields within a JSON
  request body rather than as query-string or form-encoded parameters,
  matching how most modern REST APIs actually accept POST data.
- `--headers "Content-Type: application/json"` — explicitly sets the request
  content-type header to match the JSON body being sent (some backends are
  strict about content-type matching actual body format, so this avoids
  false negatives from requests being rejected purely on a header mismatch).

### Real-World Notes

- Arjun's default wordlists are generic (broadly useful across many types of
  web apps); for API-specific engagements, supplementing with parameter names
  pulled from JS mining or a partial Swagger spec (section 7 of
  `03_Active_Discovery.md`) produces higher-quality results than relying on
  the defaults alone.
- Always manually replay any parameter Arjun flags before including it in a
  report — automated response-diffing tools occasionally flag parameters due
  to caching artifacts or randomized response ordering rather than genuine
  parameter acceptance.

---

## 3. ffuf — Fast Web Fuzzer for API-Specific Fuzzing

### Why ffuf Is Used Across Multiple Recon Sub-Tasks

ffuf is general-purpose but flexible enough to cover several distinct
API-recon needs: endpoint brute-forcing, parameter value fuzzing, and
content-type/header fuzzing, all with the same underlying tool and syntax.

### Endpoint Brute-Forcing (API-Specific Wordlist and Filtering)

```bash
ffuf -u https://target.com/api/v2/FUZZ -w seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,302,401,403 -fc 404 -t 40 -o ffuf-results.json -of json
```

- `-u https://target.com/api/v2/FUZZ` — target URL; `FUZZ` marks the
  injection point ffuf substitutes wordlist entries into.
- `-w seclists/Discovery/Web-Content/api/api-endpoints.txt` — a wordlist
  specifically curated for API endpoint names (part of the widely-used
  SecLists project), performing better here than a generic directory list.
- `-mc 200,201,204,301,302,401,403` — match codes to display, as discussed
  earlier: success codes plus `401`/`403` to catch existing-but-restricted
  endpoints, consistent with the response-inference technique.
- `-fc 404` — "filter code"; explicitly excludes `404` responses from output.
  Combined with `-mc` above this is slightly redundant (since 404 isn't in the
  match list anyway) but is included here for clarity and defensive
  filtering if the match-code list is later broadened.
- `-t 40` — thread count/concurrency.
- `-o ffuf-results.json` — writes results to a file.
- `-of json` — output format; specifies the results file should be structured
  JSON rather than ffuf's default plain-text summary, making it easy to feed
  into further scripted processing (e.g., the `comm` diff technique in the
  shadow-endpoint section of `03_Active_Discovery.md`).

### Fuzzing Multiple Positions Simultaneously (Version + Endpoint)

```bash
ffuf -u https://target.com/api/VERSION/ENDPOINT -w versions.txt:VERSION -w api-endpoints.txt:ENDPOINT -mc 200,401,403
```

- `-w versions.txt:VERSION` and `-w api-endpoints.txt:ENDPOINT` — ffuf
  supports multiple simultaneous fuzz positions, each with its own named
  placeholder and its own wordlist; the colon syntax `wordlist:KEYWORD` binds
  a specific wordlist to a specific placeholder in the URL template. This
  combination tests every version against every endpoint name in a single
  scan (a Cartesian product), directly supporting the shadow/zombie API
  version fan-out technique at scale, rather than the smaller manual loop
  shown in `03_Active_Discovery.md`.

### Response Size and Word-Count Filtering (Reducing False Positives)

```bash
ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -mc 200 -fs 1234 -fw 42
```

- `-fs 1234` — filter by response size; excludes any response whose body size
  in bytes exactly matches `1234`. Used when you've identified that the
  target returns a fixed-size generic "not found" page even with a `200`
  status (a common gateway-level anti-enumeration behavior noted in the
  WAF/Gateway section of `03_Active_Discovery.md`) — filtering that known
  size out surfaces genuinely different (and therefore interesting)
  responses.
- `-fw 42` — filter by word count in the response body; same logic as `-fs`
  but counting words instead of raw bytes, useful when response size varies
  slightly (e.g. due to a timestamp) but word count stays constant for the
  generic response.

### Method Enumeration With ffuf

```bash
ffuf -u https://target.com/api/users/123 -X FUZZ -w methods.txt -mc all
```

- `-X FUZZ` — here the fuzz placeholder is placed in the method flag itself
  rather than the URL, meaning ffuf substitutes each wordlist entry as the
  HTTP method used for the request (the wordlist in this case would just be a
  plain-text list: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, etc.) — an
  ffuf-based alternative to the manual bash loop shown in
  `03_Active_Discovery.md`.
- `-mc all` — matches every response code (no filtering), appropriate here
  since the goal is to observe every method's exact status code rather than
  filter anything out.

### Rate-Limiting Controls (Direct WAF/Gateway Mitigation)

```bash
ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -p 0.5-1.5 -t 5 -mc 200,401,403
```

- `-p 0.5-1.5` — sets a randomized delay (in seconds) between each request,
  chosen randomly from within this range per request; this randomization
  specifically defeats the fixed-interval timing signature that rate-based
  and behavioral detection systems look for, rather than just slowing down at
  a constant pace.
- `-t 5` — reduces concurrency significantly compared to the earlier
  40-thread example — the direct trade-off between scan speed and staying
  under a production gateway's detection threshold, as discussed in
  `03_Active_Discovery.md`.

### Real-World Notes

- ffuf's flexibility (multiple simultaneous fuzz positions, JSON output,
  fine-grained filtering) makes it the right tool once you already know
  roughly what you're looking for; kiterunner remains better for a first-pass
  broad sweep across an entire unknown API using its route corpus.
- Always run a baseline request (a known-nonexistent path) before a full scan
  to determine what a genuine "not found" response looks like on this
  specific target — many production APIs customize their 404 page, breaking
  naive default-only filtering assumptions carried over from lab practice.

---

## 4. Amass and Subfinder — API Subdomain Reconnaissance

These two tools serve the same broad goal (subdomain enumeration) using
different techniques, and are commonly used together — Subfinder for fast,
broad passive coverage, Amass for deeper, more exhaustive enumeration
including active techniques when authorized.

### Subfinder — Fast Passive Subdomain Enumeration

```bash
subfinder -d target.com -all -o subdomains.txt
```

- `-d target.com` — the root domain to enumerate subdomains for.
- `-all` — enables all configured passive sources rather than the smaller
  default set, querying a broader range of data sources (certificate
  transparency logs, DNS aggregators, search engines) for more thorough — but
  slower — coverage.
- `-o subdomains.txt` — writes discovered subdomains to a file.

### Filtering Subfinder Results for API-Relevant Hosts

```bash
subfinder -d target.com -all -silent | grep -iE "api|gateway|gw|graphql|internal"
```

- `-silent` — suppresses Subfinder's banner/verbose output, printing only the
  discovered subdomains themselves — necessary here since the output is being
  piped directly into `grep` rather than saved to a file first.
- `grep -iE "api|gateway|gw|graphql|internal"` — same filtering logic
  introduced in the certificate-transparency section of `02_Passive_Recon.md`,
  narrowing broad subdomain results down to ones matching common API-related
  naming patterns.

### Amass — Comprehensive Enumeration (Passive Mode)

```bash
amass enum -passive -d target.com -o amass-passive.txt
```

- `amass enum` — Amass's primary subdomain enumeration subcommand.
- `-passive` — restricts Amass to passive data sources only (no direct DNS
  brute-forcing or active resolution attempts against the target's
  infrastructure) — the appropriate default choice when scope or rules of
  engagement are uncertain, since it mirrors the "no direct interaction with
  live target defenses" principle from passive recon.
- `-d target.com` — root domain to enumerate.
- `-o amass-passive.txt` — output file.

### Amass — Active Enumeration (When Explicitly Authorized)

```bash
amass enum -active -d target.com -brute -w api-subdomain-wordlist.txt -o amass-active.txt
```

- `-active` — enables active techniques, including direct DNS resolution
  attempts and, depending on configuration, reverse DNS sweeps and zone
  transfer attempts — this directly touches the target's DNS infrastructure
  and should only be run when the engagement scope explicitly permits active
  subdomain enumeration.
- `-brute` — enables DNS brute-forcing, attempting resolution of subdomain
  names drawn from a wordlist rather than relying solely on passive-source
  discovery.
- `-w api-subdomain-wordlist.txt` — the wordlist used for the brute-force
  step; here, ideally a list curated toward API-specific naming conventions
  (`api-`, `api-v1-`, `graphql-`, `gateway-`) rather than a generic subdomain
  wordlist, for better relevance to this specific recon goal.

### Combining Both Tools' Output

```bash
cat subdomains.txt amass-passive.txt | sort -u > all-subdomains.txt
```

- `cat subdomains.txt amass-passive.txt` — concatenates both tools' output
  files together.
- `sort -u` — deduplicates the combined list (since both tools likely found
  significant overlap) and sorts it alphabetically.
- `> all-subdomains.txt` — redirects the final deduplicated list into a new
  file for the next step (liveness confirmation, as shown in
  `02_Passive_Recon.md`'s certificate transparency section, using `dig`).

### Real-World Notes

- Subfinder is generally faster and lighter-weight for an initial pass;
  Amass's passive mode tends to surface additional sources Subfinder doesn't
  query, so running both and merging results (as above) consistently
  outperforms running either alone.
- Active enumeration (`amass enum -active`) generates DNS query volume that
  can itself be logged and flagged by security-conscious organizations running
  DNS monitoring — treat it with the same scoping caution described for
  active brute-forcing in `03_Active_Discovery.md`.
- Neither tool is API-aware by design — the API-specific value comes entirely
  from filtering their generic subdomain output against API-related naming
  patterns, as shown above. Don't expect either tool to distinguish an API
  subdomain from any other kind on its own.
