# Passive Reconnaissance for API Endpoint Discovery

Passive recon means gathering information without sending abnormal or
high-volume requests directly to the target's live infrastructure. You're
either reading things the target has already published (JS files, spec files)
or querying third-party services that have already indexed the target
(Wayback Machine, certificate transparency logs, search engines). This is why
the WAF/Gateway bypass discussion from the overview file does not apply to
this file — there is no live defensive system being interacted with in an
anomalous way.

Always perform passive recon before active discovery. It's free, it's silent,
and it frequently produces a better endpoint map than brute-forcing ever will.

---

## 1. Swagger / OpenAPI Specification Exposure

### Mechanism

Swagger (now OpenAPI) is a specification format that describes an API's
endpoints, parameters, request/response schemas, and authentication
requirements in a single machine-readable JSON or YAML file. Developers
generate this file to power interactive documentation UIs (Swagger UI,
Redoc). The problem: development teams frequently leave the spec file itself,
or the interactive documentation UI, accessible on production infrastructure
without any authentication — sometimes intentionally (public API), often by
accident (internal tooling exposed publicly).

If you find this file, you don't need to guess endpoints at all — the entire
API surface, including parameter names, data types, and sometimes example
values, is handed to you directly.

### Common Paths to Check

```
/swagger.json
/swagger.yaml
/swagger/v1/swagger.json
/swagger-ui.html
/swagger-ui/
/api-docs
/api-docs.json
/api/swagger.json
/openapi.json
/openapi.yaml
/v2/api-docs
/v3/api-docs
/.well-known/openapi.json
/docs
/redoc
```

### Command Breakdown

```bash
curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" https://target.com/swagger.json
```

- `curl` — the HTTP client used to send the request.
- `-s` — silent mode; suppresses the progress meter so only the output you
  format with `-w` is shown.
- `-o /dev/null` — discards the response body; at this stage you only want to
  know if the file exists (status code), not read the full content yet.
- `-w "%{http_code} %{url_effective}\n"` — write-out format string. Prints the
  numeric HTTP status code and the URL that was actually requested (useful if
  redirects occurred), followed by a newline.
- `https://target.com/swagger.json` — the candidate path being tested.

To check the full list of common paths in one pass:

```bash
for path in swagger.json swagger.yaml swagger-ui.html api-docs api-docs.json \
  openapi.json openapi.yaml v2/api-docs v3/api-docs redoc docs; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
  echo "$code - /$path"
done
```

- `for path in ... ; do ... done` — a bash loop that iterates over each listed
  candidate path string in turn, assigning it to the variable `$path`.
- `code=$(...)` — command substitution; captures the output of the `curl`
  command (just the status code, due to `-w` and `-o /dev/null` as before)
  into the variable `code`.
- `"https://target.com/$path"` — variable interpolation builds the full URL
  for each iteration.
- `echo "$code - /$path"` — prints the result in a readable `code - /path`
  format so you can scan output for `200` responses.

### Once Found: What to Do With It

If a spec file returns `200`, fetch and save it:

```bash
curl -s https://target.com/openapi.json -o openapi.json
```

- `-s` — silent mode, same as before.
- (no `-o /dev/null` this time) `-o openapi.json` — saves the response body to
  a local file named `openapi.json` instead of discarding it, since this time
  you want the content.

Then move to spec analysis (covered in `03_Active_Discovery.md`, section on
Documentation Analysis) to extract every endpoint from it.

### Real-World Notes

- Swagger UI pages (`/swagger-ui.html`, `/swagger-ui/index.html`) often load
  the actual JSON spec via a separate XHR request you won't see just by
  viewing the HTML — check the browser's Network tab or grep the HTML source
  for a `url:` field pointing to the real spec file.
- Internal/staging Swagger instances are sometimes left open specifically
  because the team assumes "no one will guess this subdomain" — this is why
  subdomain enumeration (certificate transparency, later in this file) and
  spec-path checking go hand in hand.
- Many frameworks expose predictable default paths: Spring Boot with
  springdoc-openapi defaults to `/v3/api-docs`, older Springfox defaults to
  `/v2/api-docs`, and NestJS with `@nestjs/swagger` commonly uses `/api` or
  `/api-docs`. Recognizing the backend framework (via headers, error pages, or
  JS bundle strings) narrows down which default path to try first.

---

## 2. JavaScript File Mining for API Endpoints

### Mechanism

Modern web front-ends (React, Vue, Angular) are compiled into JavaScript
bundles that contain every API call the application will ever make, hardcoded
as string literals — because the browser has to know where to send requests.
Even minified and bundled, these endpoint paths remain as readable strings in
the JS file. This makes JS bundles one of the richest sources of endpoint
information available without ever triggering active detection, since you're
just downloading files the site already serves to every visitor.

### Step 1: Enumerate JS Files Loaded by the Application

```bash
curl -s https://target.com | grep -oP '(?<=src=")[^"]*\.js'
```

- `curl -s https://target.com` — fetches the target's HTML source silently.
- `grep -oP` — `-o` prints only the matched text (not the full line); `-P`
  enables PCRE (Perl-compatible regex) syntax, needed for the lookbehind used
  below.
- `(?<=src=")[^"]*\.js` — a lookbehind assertion `(?<=src=")` matches the
  position right after a literal `src="` without consuming those characters,
  then `[^"]*\.js` matches any characters that aren't a quote, up to and
  including a `.js` extension. Net effect: extracts every `.js` file path
  referenced in a `src="..."` attribute.

### Step 2: Download and Search Each JS File for Endpoint Patterns

```bash
curl -s https://target.com/static/js/main.a1b2c3.js -o main.js
grep -oE '"(/api/[a-zA-Z0-9/_-]+)"' main.js | sort -u
```

- First line: downloads the JS bundle and saves it locally as `main.js`.
- `grep -oE` — `-o` prints only matches, `-E` enables extended regex.
- `"(/api/[a-zA-Z0-9/_-]+)"` — matches a double-quoted string starting with
  `/api/` followed by one or more characters from the set (letters, digits,
  underscore, hyphen, forward slash) — this pattern targets typical REST-style
  endpoint paths like `/api/users/profile`.
- `sort -u` — sorts the results alphabetically and `-u` removes duplicate
  lines, since the same endpoint string often appears many times in a bundle.

### Step 3: Broaden the Pattern for Non-Standard API Prefixes

Not every API uses `/api/` as a prefix. Broaden the search:

```bash
grep -oE '"/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_{}:-]+)+"' main.js | sort -u | head -100
```

- `"/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_{}:-]+)+"` — matches any double-quoted string
  that looks like a multi-segment path (at least two `/`-separated segments),
  including path parameter placeholders like `{id}` or `:id` which some
  frameworks embed literally in route-definition strings.
- `head -100` — limits output to the first 100 lines, since this broader
  pattern produces far more noise (CSS class paths, image paths, etc.) and you
  don't want to be flooded; adjust or pipe to a file instead if you need the
  full list.

### Step 4: Automate Across All Discovered JS Files

```bash
for js in $(curl -s https://target.com | grep -oP '(?<=src=")[^"]*\.js'); do
  curl -s "https://target.com$js" | grep -oE '"/api/[a-zA-Z0-9/_-]+"'
done | sort -u
```

- `for js in $(...)` — iterates over the list of JS file paths produced by the
  Step 1 command, assigning each to `$js`.
- `curl -s "https://target.com$js"` — downloads each JS file in turn (note:
  if the extracted `src` was already a full URL rather than a relative path,
  this concatenation needs adjusting — check the raw output first).
- The pipeline inside the loop extracts endpoint strings from each file as it
  downloads, and the final `sort -u` outside the loop deduplicates across all
  files combined.

### Real-World Notes

- Source maps (`.js.map` files) are a goldmine if left deployed — they let you
  reconstruct the original, unminified source code, including comments and
  original variable names, which often name the exact backend route they call.
  Check for a `//# sourceMappingURL=` comment at the end of any JS file.
- Minifiers sometimes split strings across concatenations (e.g.
  `"/ap" + "i/users"`) specifically to defeat naive grepping — if a JS mining
  pass on a heavily obfuscated bundle comes up unexpectedly empty, open the
  file in a formatter/beautifier and read it manually rather than assuming
  there's nothing there.
- On single-page applications, check every route's lazy-loaded chunk, not just
  the main bundle — modern bundlers split code by route, so the endpoint for
  an admin panel might only appear in a chunk that's never loaded until a user
  navigates there, meaning it won't appear in the initially-loaded JS at all.

---

## 3. Google Dorking for API Documentation

### Mechanism

Search engines index publicly accessible pages, including documentation
portals, exposed Swagger UIs, and API references that were never meant to be
publicly discoverable but weren't blocked by `robots.txt` or authentication.
Dorking uses search operators to filter results down to exactly this kind of
exposure.

### Useful Dorks

```
site:target.com inurl:swagger
site:target.com inurl:api-docs
site:target.com intitle:"swagger ui"
site:target.com filetype:json inurl:api
site:target.com inurl:"/v1/" OR inurl:"/v2/" OR inurl:"/v3/"
"target.com" api key inurl:docs
```

- `site:target.com` — restricts results to pages Google has indexed under this
  domain (or subdomains, depending on Google's interpretation) only.
- `inurl:swagger` — restricts results to URLs containing the literal string
  "swagger" anywhere in the path.
- `intitle:"swagger ui"` — restricts results to pages whose `<title>` tag
  contains the exact phrase "swagger ui" — this catches default Swagger UI
  page titles that weren't customized.
- `filetype:json inurl:api` — restricts to indexed files with a `.json`
  extension whose URL also contains "api" — used to catch exposed spec files
  or config files directly.
- `inurl:"/v1/" OR inurl:"/v2/" OR inurl:"/v3/"` — the `OR` operator broadens
  the search to match any of the three version path segments, useful for
  discovering which API versions Google has indexed pages for (a strong signal
  for which versions are/were live).
- Quoting `"target.com"` in the last example without `site:` also catches
  third-party pages (blog posts, Postman public collections, GitHub gists)
  that reference the target's API externally.

### Real-World Notes

- Dorking is most effective against organizations that publish public/partner
  API documentation on a separate marketing or developer-relations site
  (`developers.target.com`, `target.com/dev-portal`) — these are indexed far
  more thoroughly than internal-only tooling.
- Public Postman collections shared by a target's own developers (searchable
  via `site:postman.com "target.com"` or similar on Postman's own search) are
  a frequently overlooked source — developers sometimes publish a collection
  to make onboarding easier for partners, unintentionally documenting internal
  or undocumented endpoints in the process.
- Don't expect much from dorking against an API with no external partners or
  public documentation strategy — in that case, JS mining and spec-path
  brute-forcing will outperform it.

---

## 4. Wayback Machine for Historical Endpoints

### Mechanism

The Internet Archive's Wayback Machine crawls and stores snapshots of pages
over time, including old JavaScript files, old API responses that were
directly linked, and old documentation pages. Because it stores *historical*
snapshots, it frequently reveals endpoints that existed in a previous version
of the application and may still be live on the backend even though the
current front-end no longer references them — exactly the "zombie endpoint"
pattern this series is concerned with.

### Command Breakdown

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey" | grep -i "api"
```

- `curl -s` — fetches silently, as before.
- `"http://web.archive.org/cdx/search/cdx?..."` — the CDX Server API, the
  Wayback Machine's index-query endpoint (not the snapshot viewer itself; this
  returns a plain list of archived URLs, much faster than scraping the
  wayback UI).
- `url=target.com/*` — the wildcard `*` tells the CDX API to return every
  archived URL under this domain, not just the exact root.
- `output=text` — requests plain-text output rather than the default JSON,
  simplifying downstream parsing with `grep`.
- `fl=original` — "fields=original"; tells the CDX API to return only the
  original URL field for each archived record, omitting timestamp/mimetype/
  statuscode columns you don't need at this stage.
- `collapse=urlkey` — deduplicates results that share the same canonicalized
  URL key, so you don't get the same URL repeated for every snapshot date the
  Archive happens to have — one line per unique URL instead.
- `grep -i "api"` — filters the resulting URL list to only lines containing
  "api" (case-insensitive via `-i`), since the raw CDX output includes every
  archived asset (images, CSS, unrelated pages) on the domain.

### Extracting Just Path Structure for Review

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey" \
  | grep -i "api" \
  | sed 's|https\?://[^/]*||' \
  | sort -u
```

- `sed 's|https\?://[^/]*||'` — substitution command; `s|pattern|replacement|`
  uses `|` as the delimiter instead of `/` (since the pattern itself contains
  slashes, this avoids escaping every one). `https\?://[^/]*` matches the
  protocol and domain portion of each URL (`https?` allows optional `s`), and
  replacing it with nothing strips it off, leaving just the path — making it
  easier to scan for endpoint patterns without domain noise repeating on every
  line.
- `sort -u` — deduplicates and sorts the resulting bare paths.

### Real-World Notes

- Wayback data reflects what was **publicly crawlable** at the time, so
  authenticated-only or robots.txt-disallowed API paths generally won't appear
  here even if they existed — this technique complements JS mining and
  Swagger discovery, it doesn't replace them.
- Cross-reference every path Wayback returns against the current, live API
  surface. A path that shows up in a 2022 snapshot but returns `404` today is
  either genuinely removed or a candidate zombie endpoint — worth a manual
  check rather than assuming it's dead.
- Large, long-lived targets can return tens of thousands of archived URLs. It
  is worth writing the deduplicated output to a file and reviewing it with a
  text editor or additional `grep` filters rather than trying to eyeball raw
  terminal output.

---

## 5. Certificate Transparency Logs for API Subdomains

### Mechanism

Certificate Transparency (CT) is a public, append-only log system that every
publicly trusted Certificate Authority must submit issued certificates to.
Any time an organization requests an HTTPS certificate for a subdomain — even
an internal-sounding one like `api-internal.target.com` or
`staging-api.target.com` — that subdomain name becomes permanently visible in
CT logs, whether or not the organization intended to publicize it. This makes
CT logs one of the most reliable ways to discover API-specific subdomains that
were never meant to be found.

### Using crt.sh

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

- `curl -s "https://crt.sh/?q=%25.target.com&output=json"` — queries crt.sh's
  search interface; `%25` is the URL-encoded form of the `%` wildcard
  character (since `%` itself has meaning in URLs), so `%25.target.com` means
  "any certificate issued for any subdomain of target.com." `output=json`
  requests machine-readable JSON instead of the default HTML table.
- `jq -r '.[].name_value'` — `jq` is a JSON processor; `-r` outputs raw
  strings without quotation marks; `.[].name_value` iterates over every object
  in the returned JSON array and extracts the `name_value` field, which holds
  the domain name(s) the certificate covers.
- `sort -u` — deduplicates and sorts results, since the same subdomain
  frequently appears across multiple certificate renewals/reissues over time.

### Filtering for API-Relevant Subdomains

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u | grep -iE "api|gateway|gw|graphql"
```

- `grep -iE "api|gateway|gw|graphql"` — case-insensitive extended regex match
  for any subdomain containing common API-related naming conventions:
  "api" (e.g. `api.target.com`, `api-v2.target.com`), "gateway"/"gw" (common
  naming for API Gateway instances), and "graphql" (a common naming pattern
  for GraphQL-specific endpoints, which have their own distinct recon
  considerations covered in a separate note series).

### Confirming Which Subdomains Are Actually Live

A subdomain appearing in CT logs only proves a certificate was issued for it —
not that it currently resolves or serves anything:

```bash
while read -r sub; do
  ip=$(dig +short "$sub")
  [ -n "$ip" ] && echo "$sub -> $ip"
done < api-subdomains.txt
```

- `while read -r sub; do ... done < api-subdomains.txt` — reads the file
  line by line, assigning each line to the variable `sub`; `-r` prevents
  backslash characters in input from being interpreted as escape sequences.
- `dig +short "$sub"` — DNS lookup tool; `+short` suppresses the verbose
  default output and prints only the resolved IP address(es), or nothing if
  the domain doesn't resolve.
- `[ -n "$ip" ] && echo "$sub -> $ip"` — `[ -n "$ip" ]` tests whether the
  `$ip` variable is a non-empty string (i.e., the lookup succeeded); `&&` only
  runs the following `echo` if that test passed, so dead subdomains are
  silently skipped rather than printed with a blank IP.

### Real-World Notes

- Wildcard certificates (`*.target.com`) will appear in CT logs as a single
  entry and won't reveal individual subdomain names — in that case CT logs
  alone won't help, and you'll need to fall back on brute-force subdomain
  enumeration (covered with Amass/Subfinder in `04_Tooling.md`).
- CT logs never expire and never get "taken down" — a subdomain decommissioned
  three years ago can still show up in results. Always confirm liveness (DNS
  resolution, then an HTTP request) before reporting a subdomain as part of
  the current attack surface.
- Organizations using automated certificate issuance (e.g. Let's Encrypt with
  frequent renewal) tend to have far noisier, more complete CT log histories
  than organizations using long-lived manually-issued certs — expect
  significantly more results against modern cloud-native infrastructure.
