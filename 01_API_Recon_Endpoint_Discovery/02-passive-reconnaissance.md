# Passive Reconnaissance for API Discovery

Passive recon generates no direct traffic to the target application itself (or, in the
case of Wayback/certificate transparency, traffic only to third-party archives and CT
log mirrors — never to the target). It always comes first because it's free, low-risk,
and frequently hands you real endpoint names that make every later active technique
faster and more accurate.

## 1. Swagger / OpenAPI Spec Exposure

Many APIs expose their machine-readable spec file at a predictable path, sometimes
intentionally (for public API consumers) and sometimes by accident (a dev/staging
convention that made it into production).

### Common spec locations to check manually

```
/swagger.json
/swagger.yaml
/swagger-ui.html
/swagger-ui/
/api-docs
/api/swagger.json
/v1/swagger.json
/v2/api-docs
/openapi.json
/openapi.yaml
/.well-known/openapi.json
/api/v1/openapi.json
```

**Why check so many variants:** Swagger/OpenAPI tooling has no single universal
convention — Springfox (Java/Spring) defaults to `/v2/api-docs`, plain swagger-ui
defaults to `/swagger-ui.html` plus a separate JSON/YAML spec path, and hand-rolled
setups can put the file anywhere. Checking only `/swagger.json` misses a large share of
real-world exposures.

### Automating the check with a simple loop

```bash
for path in swagger.json swagger.yaml api-docs openapi.json v2/api-docs v1/swagger.json; do
  echo "[*] Checking /$path"
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.example.com/$path"
done
```

Breakdown:
- `for path in ... ; do ... done` — a Bash loop that iterates over each candidate path
  string in the list, one at a time, assigning it to the variable `$path`.
- `curl -s` — runs curl in silent mode, suppressing the progress meter so only the
  output we ask for is shown.
- `-o /dev/null` — discards the response body; at this stage we only want to know if the
  path exists, not read its content yet.
- `-w "%{http_code}\n"` — tells curl to print the HTTP status code it received, followed
  by a newline, instead of the default curl output.
- `"https://api.example.com/$path"` — the target URL, with `$path` substituted in from
  the loop variable on each iteration.
- A `200` response here is a strong signal; a `401`/`403` still confirms the path
  exists and is worth noting (the spec may be reachable with valid auth later); a `404`
  means try the next candidate.

### Reading the spec once found

Once you have a spec file, don't just skim it in a browser — pull it down and treat it
as a structured document (see `05-api-documentation-analysis.md` for the full
breakdown of what to extract: every `paths` entry, every `parameters` block, every
`securitySchemes` definition).

```bash
curl -s "https://api.example.com/v2/api-docs" -o openapi.json
```

Breakdown:
- `curl -s` — silent mode, same as above.
- `"https://api.example.com/v2/api-docs"` — the confirmed spec URL from the check above.
- `-o openapi.json` — writes the response body to a local file named `openapi.json`
  instead of printing it to the terminal, so it can be parsed by tooling afterward.

**Real-world note:** exposed Swagger UI without any authentication in front of it is one
of the most common single findings in API assessments — not because it's a
vulnerability on its own, but because it hands an attacker the complete endpoint map,
parameter names, expected data types, and often example request/response bodies that
would otherwise take hours of active probing to reconstruct.

## 2. JavaScript File Mining for API Endpoints

Single-page applications call APIs from client-side JS, which means the endpoint list
is often sitting in plain text inside files the browser already downloaded.

### Manual approach

1. Load the target application in a browser with dev tools open, Network tab filtered
   to JS/XHR.
2. Identify every `.js` bundle loaded (main bundle, vendor chunks, lazy-loaded route
   chunks).
3. Download each one and grep for URL patterns.

### Grepping a downloaded JS bundle for endpoints

```bash
curl -s "https://app.example.com/static/js/main.a1b2c3.js" | \
  grep -Eo '"(\/api\/[a-zA-Z0-9\/_\-]+)"' | sort -u
```

Breakdown:
- `curl -s "..."` — downloads the JS bundle silently, same flag meaning as before.
- `|` — pipes curl's output (the raw JS file content) into `grep` rather than printing
  it to the terminal.
- `grep -E` — enables extended regular expressions, needed for the `{}`/`+`/alternation
  syntax used in the pattern.
- `-o` — tells grep to print only the matched portion of each line, not the whole line;
  critical here because a minified JS file has extremely long lines.
- `'"(\/api\/[a-zA-Z0-9\/_\-]+)"'` — the regex pattern: matches a double-quoted string
  that starts with `/api/` followed by one or more alphanumeric characters, slashes,
  underscores, or hyphens. This targets the common convention of API paths being
  written as string literals like `"/api/users/profile"` in JS source.
- `sort -u` — sorts the results alphabetically and removes duplicate lines, since the
  same endpoint string often appears many times across a bundle.

### Automating across many JS files with a dedicated tool

For real engagements, running this grep manually against dozens of bundles is
impractical. Purpose-built tools like **LinkFinder** and **SecretFinder** parse JS files
specifically for endpoint-shaped and secret-shaped strings using more refined regex than
a single grep line:

```bash
python3 linkfinder.py -i "https://app.example.com/static/js/main.a1b2c3.js" -o cli
```

Breakdown:
- `python3 linkfinder.py` — runs the LinkFinder script under Python 3.
- `-i "https://..."` — the `-i`nput flag; accepts a single URL, a local file, or a
  directory of files.
- `-o cli` — the `-o`utput flag set to `cli`, printing results directly to the terminal
  instead of generating an HTML report file.

**Real-world note:** source map files (`.js.map`) are an even richer target than the
minified bundle itself when present — they map minified code back to original,
unminified source with original variable and function names, which frequently exposes
internal endpoint names, comments, and even internal-only route definitions that never
made it into the production bundle's visible strings. Always check for a
`//# sourceMappingURL=` comment at the end of a JS file.

## 3. Google Dorking for Exposed API Documentation

Search engines index far more than most organizations realize, including Postman
documentation pages, exposed Swagger UIs, and API reference pages never meant to be
public.

### Useful dork patterns

```
site:example.com inurl:swagger
site:example.com inurl:api-docs
site:example.com filetype:json inurl:swagger
site:postman.com "example.com" intitle:"API documentation"
site:example.com inurl:"/v1/" filetype:json
intitle:"index of" "api" site:example.com
```

Breakdown of the dork operators used:
- `site:example.com` — restricts results to pages Google has indexed under this domain
  specifically, the foundational operator for target-scoped dorking.
- `inurl:swagger` — matches pages where "swagger" appears anywhere in the URL, catching
  paths like `/swagger-ui/` or `/api/swagger`.
- `filetype:json` — restricts results to files Google has indexed with a `.json`
  extension, useful for catching directly indexed spec files.
- `intitle:"..."` — matches pages whose HTML `<title>` tag contains the given phrase;
  quoting forces an exact phrase match rather than matching the words separately.
- `site:postman.com "example.com"` — searches Postman's own public documentation
  hosting for any published collection that mentions the target domain — teams commonly
  publish Postman docs publicly without realizing search engines index them.
- `intitle:"index of"` — a classic dork for finding exposed directory listings, which
  sometimes reveal API doc files, backup spec files, or old versioned API folders sitting
  in an unprotected directory.

**Real-world note:** Postman's public workspace publishing feature is a recurring
source of real exposure. Teams publish a collection for internal sharing convenience,
forget it's public by default under certain workspace settings, and it stays indexed
long after the API itself has changed — but the auth flow, base URLs, and parameter
structure it reveals are usually still accurate enough to jump-start active testing.

## 4. Wayback Machine and Archive Mining for Old Endpoints

The Internet Archive's Wayback Machine has been crawling and archiving pages for
decades, which makes it a reliable source for endpoints that existed in a past version
of an application and may still be live even though nothing currently links to them.

### Using the Wayback CDX API directly

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/api/*&output=text&fl=original&collapse=urlkey" | sort -u
```

Breakdown:
- `curl -s "..."` — silent GET request to the CDX (Capture Index) API endpoint, which is
  Wayback Machine's query interface for its archive index rather than the archived pages
  themselves.
- `url=example.com/api/*` — the CDX query parameter specifying which URLs to search for;
  the trailing `/*` wildcard matches any URL under the `/api/` path, not just an exact
  match.
- `output=text` — requests plain text output instead of the default JSON, easier to pipe
  directly into other Unix tools.
- `fl=original` — "fields" parameter restricted to just `original`, meaning return only
  the original archived URL for each match rather than all metadata (timestamp,
  mimetype, status code, digest) the CDX API can return.
- `collapse=urlkey` — deduplicates results that share the same canonicalized URL key, so
  the same endpoint archived at 50 different points in time only appears once.
- `sort -u` — final client-side sort and dedupe pass, since CDX output ordering and any
  near-duplicate variations benefit from a second pass.

### Using a dedicated tool: waybackurls

```bash
echo "example.com" | waybackurls | grep "/api/" | sort -u
```

Breakdown:
- `echo "example.com"` — prints the target domain to standard output.
- `|` — pipes that domain string into `waybackurls` as its input.
- `waybackurls` — a Go tool (by tomnomnom) that queries the same CDX API under the hood
  but handles pagination, deduplication, and multiple archive sources automatically,
  saving the manual CDX query construction above.
- `grep "/api/"` — filters the (often very large) full list of archived URLs down to
  just ones containing `/api/`.
- `sort -u` — final dedupe pass.

**Real-world note:** archived endpoints are frequently *dead* in the sense of returning
404 today, but the pattern they reveal (old versioning schemes, old parameter naming
conventions, old resource names) is still valuable for informing active brute-force
wordlists in Phase 3 — a resource named `/api/v1/legacy_orders` in a 2021 archive snapshot
is a strong hint to also try `/api/v2/legacy_orders` or `/api/v2/orders` today, even if
the exact archived URL is gone.

## 5. Certificate Transparency for API Subdomains

Every publicly trusted TLS certificate issued since roughly 2018 is logged in public
Certificate Transparency (CT) logs, which means every subdomain that has ever had a
certificate issued for it — including `api.example.com`, `api-staging.example.com`,
`api-v2.example.com` — is discoverable even if DNS itself doesn't advertise it.

### Querying crt.sh

```bash
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

Breakdown:
- `curl -s "https://crt.sh/?q=%.example.com&output=json"` — queries crt.sh's search
  interface; `%.example.com` uses SQL-style `%` wildcard matching (crt.sh's backend is a
  PostgreSQL database of CT log entries) to match any subdomain of example.com;
  `output=json` requests structured JSON instead of the default HTML results page.
- `|` — pipes the JSON response into `jq`.
- `jq -r '.[].name_value'` — `jq` is a JSON processor; `-r` outputs raw strings instead
  of JSON-quoted strings; `.[].name_value` iterates over every object in the top-level
  JSON array and extracts its `name_value` field, which is the certificate's Common Name
  or Subject Alternative Name — the actual domain/subdomain string.
- `sort -u` — sorts and deduplicates, since CT logs frequently contain many certificates
  (renewals, reissues, multi-domain certs) for the same subdomain.

**Why this specifically matters for API recon:** organizations are far more likely to
remember to remove a subdomain from their public marketing site than from DNS or from CT
log history. `api-legacy.example.com` or `api-internal.example.com` showing up in CT
logs, still resolving, and still responding is a very common finding — it is effectively
a company's own certificate issuance history telling you about infrastructure they
forgot existed.

## 6. PortSwigger Academy Coverage

**Recon-adjacent, not recon-dedicated.** Academy has no lab category for passive API
recon. The closest related material:

- Labs in the **Information Disclosure** category occasionally require finding a hidden
  API endpoint or version string via exposed debug information, comments, or backup
  files — the skill of "look at what the application accidentally reveals" transfers
  directly, even though the lab framing isn't API-specific.
- Any lab that requires reading response headers, error messages, or source comments to
  find a hidden path builds the same muscle used in JS mining and dork-style thinking.

For hands-on passive recon practice specifically, crAPI is the strongest option: it
ships with JS bundles containing real embedded endpoint references and a Swagger/OpenAPI
spec that is intentionally not fully reflected in the front-end, closely mirroring the
documentation-drift scenario described in file 1.

## 7. Next File

Continue to `03-active-discovery.md` for brute-forcing, method enumeration, and
parameter discovery once passive recon has narrowed and seeded your target list.
