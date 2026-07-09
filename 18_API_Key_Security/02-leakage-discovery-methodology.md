# API Key Security Testing — Leakage Discovery Methodology

This file covers five discovery surfaces in the order you should generally work
through them on an engagement: JavaScript bundles, git repositories, API
responses/error messages, the browser DevTools Network tab, and public Postman
collections. Each section explains *why* keys end up there before giving the
technique.

## 1. API Keys in JavaScript Bundles

### 1.1 Mechanism

Any key used by client-side JavaScript to call a third-party or first-party API
directly from the browser has to physically exist in the code the browser
downloads and executes. There is no way to hide a value from code that must use
that value at runtime in an unauthenticated browser context — obfuscation and
minification make it *harder to read*, not impossible to extract, because the
JS engine itself has to be able to read it. This is different from a
server-side secret, which never leaves the server. If a developer intended a
key to be server-only but the frontend calls the third-party API directly
instead of proxying through the backend, the key is now client-exposed by
design, whether or not they realized it.

### 1.2 Manual Discovery Workflow

Step 1 — enumerate all JS served to the page:

```
curl -s https://target.com/ | grep -oE 'src="[^"]+\.js"'
```
- `curl -s` — fetch the page quietly (`-s` suppresses progress meter output so
  it doesn't pollute the piped result).
- `grep -oE` — `-o` prints only the matched substring rather than the whole
  line; `-E` enables extended regex so we can use `+` and `[^"]` without
  escaping.
- `'src="[^"]+\.js"'` — matches any `src="..."` attribute ending in `.js`,
  which is how `<script>` tags reference external bundles.

This only gets scripts referenced in the initial HTML. Modern SPAs lazy-load
additional chunks at runtime, so also check the Network tab (Section 4) or crawl
with Burp's spider to catch dynamically-loaded bundle files.

Step 2 — pull down each bundle and search it:

```
curl -s https://target.com/static/js/main.abc123.js -o main.js
grep -EoI '(AKIA|ASIA)[0-9A-Z]{16}' main.js
```
- `-o main.js` — write the response body to a local file instead of stdout, so
  we can run multiple greps against it without re-downloading.
- `grep -EoI` — `-E` extended regex, `-o` print only the match, `-I` skip
  binary-looking files (some bundles are minified to the point grep may treat
  them as binary depending on encoding; `-I` prevents grep from silently
  skipping or garbling output).
- `(AKIA|ASIA)[0-9A-Z]{16}` — the AWS Access Key ID pattern from File 1: a
  4-letter prefix followed by 16 base32-style characters (total 20).

Repeat with provider-specific patterns from File 1's table — `AIza[0-9A-Za-z_-]{35}`
for Google, `sk_live_[0-9a-zA-Z]{24,}` for Stripe, `xox[baprs]-[0-9a-zA-Z-]+`
for Slack, and so on. For a target with an unknown/custom key format, pattern
matching won't work — jump to File 3's entropy-based approach instead, or grep
for the variable names developers commonly use to hold secrets:

```
grep -EoI '(api[_-]?key|apikey|secret|token|auth)["\047]?\s*[:=]\s*["\047][A-Za-z0-9_\-\.]{16,}["\047]' main.js
```
- `(api[_-]?key|apikey|secret|token|auth)` — common variable-name fragments
  that precede a hardcoded credential.
- `["\047]?` — an optional single or double quote around the variable name
  (`\047` is the octal escape for `'`, used here because unescaped `'` would
  break the shell's single-quoted string).
- `\s*[:=]\s*` — matches `:` (object literal) or `=` (assignment), with
  optional whitespace, covering both JSON-style and JS-assignment-style
  patterns.
- `["\047][A-Za-z0-9_\-\.]{16,}["\047]` — a quoted string at least 16
  characters of key-safe alphabet, which filters out short flags/booleans and
  keeps genuinely credential-shaped values.

### 1.3 Handling Minification and Source Maps

Minified code compresses variable names but not string literals — a hardcoded
key string is untouched by minification, so the grep patterns above still work
directly against minified bundles. What minification *does* hide is context:
you'll find the string but not which function uses it or why. Two ways to
recover that:

- **Source maps.** If the target ships a `.js.map` file alongside the bundle
  (check for a `//# sourceMappingURL=` comment at the end of the JS file, or
  just try `main.js.map` next to `main.js`), you can reconstruct
  close-to-original source with a source map tool, which restores original
  variable names and file structure and makes it obvious whether a key is a
  live production secret or a placeholder/example value.
- **Beautification only.** If no source map exists, run the bundle through a
  JS beautifier to at least get readable indentation and line breaks — this
  won't restore names but makes manual reading of the surrounding 10-20 lines
  around a found key much faster than reading a single 400,000-character line.

### 1.4 Real-World Note

This is one of the single most common high-severity findings on HackerOne for
consumer-facing web apps, precisely because it requires zero authentication and
zero special tooling to find — a developer proxy setting, a debug build
accidentally shipped to production, or a "temporary" hardcoded key that was
never removed are all extremely common root causes. Several disclosed HackerOne
reports across ride-sharing, e-commerce, and SaaS platforms follow this exact
pattern: tester loads the page, views source or a bundle, finds a live
third-party API key (commonly a mapping, payments, or analytics provider key)
directly in the JS. Severity depends entirely on what the key can do — see
File 3's scope testing before assuming a finding is high severity just because a
key was hardcoded.

## 2. API Keys in Git Repositories

### 2.1 Mechanism

Two distinct sub-cases, and they require different techniques:

- **A key currently in the repo** — trivial, just grep the checked-out files.
- **A key that was committed at some point and later "removed"** — the far more
  interesting case. Deleting a file or a line in a new commit does not remove
  it from git history. The old blob is still reachable via `git log`, and
  anyone who clones the repo gets the full history by default. Developers
  frequently believe they've "fixed" a leak by deleting the line in a follow-up
  commit, without realizing the original commit is still fully retrievable.

### 2.2 Searching Live Repository Content

If you already have the repo cloned:

```
git grep -nE '(AKIA|ASIA)[0-9A-Z]{16}' $(git rev-list --all)
```
- `git grep` — searches file content, faster than plain `grep -r` on large repos
  because it uses git's internal indexing.
- `-n` — show line numbers, so you can jump straight to the finding.
- `-E` — extended regex, same reasoning as before.
- `$(git rev-list --all)` — this is the key part: `git rev-list --all` lists
  every commit reachable from every ref (all branches, all tags), and wrapping
  it in `$()` passes that entire list to `git grep` as the set of revisions to
  search, rather than just searching the current checked-out working tree.
  This is what lets you find a key that existed in commit history even if it
  was deleted in a later commit.

### 2.3 Searching Full History for Deleted Secrets

A more targeted approach when you suspect a specific file was ever added then
removed (e.g., a `.env` file):

```
git log --all --full-history -- "**/.env"
```
- `--all` — search across all branches, not just the current one.
- `--full-history` — normally `git log` on a path simplifies history to commits
  that changed that path *as seen from the current tree*; `--full-history`
  disables that simplification so you see every commit that ever touched the
  path, including ones later made irrelevant by merges or reverts.
- `-- "**/.env"` — the `--` separates revision arguments from path arguments;
  `**/.env` matches an `.env` file at any depth in the repo.

Once you have a commit hash from that output, view the file as it existed at
that point:

```
git show <commit-hash>:path/to/.env
```
- `git show` — displays an object; `<commit-hash>:path/to/.env` is git's syntax
  for "the content of this path, as it existed in this specific commit,"
  regardless of what the file looks like now or whether it still exists.

### 2.4 GitHub Search Dorking (Repos You Don't Have Cloned)

GitHub's own code search supports targeted queries useful for finding a
specific organization's leaked keys, or generic patterns across all public
repos (be mindful of scope/authorization — only search within engagement scope
unless you're doing general research on public disclosure patterns):

```
org:target-org "AKIA" in:file
```
- `org:target-org` — restricts results to repositories owned by the target
  organization.
- `"AKIA"` — literal string search for the AWS key prefix; GitHub search
  supports quoted exact-match strings.
- `in:file` — restricts the search to file content rather than file names, repo
  descriptions, etc.

```
"target-app-name" "api_key" filename:.env
```
- `"target-app-name"` — narrows to repos/files mentioning the product, useful
  when searching public GitHub broadly rather than within a known org.
- `filename:.env` — restricts results to files literally named `.env`, one of
  the highest-hit-rate filenames for this kind of search since `.env` files are
  conventionally where developers put secrets and are frequently
  accidentally committed despite `.gitignore` best practice.

Other high-value filename/extension dorks: `filename:credentials`,
`filename:.npmrc` (leaks npm registry auth tokens), `extension:pem`,
`extension:ppk`, `filename:config.json "apiKey"`.

**Note on GitHub search limitations:** GitHub's code search indexing is not
real-time and does not always index forks or very recently pushed commits
consistently. A negative result from GitHub search is not proof a key was
never committed — cross-check with a direct clone-and-`git log` approach
(Section 2.2/2.3) when you have repo access, or with a dedicated scanning tool
(File 4) which can search history exhaustively rather than relying on GitHub's
index.

### 2.5 Real-World Note

Leaked-in-git-history findings are extremely common in disclosed reports
involving CI/CD configuration files (`.travis.yml`, `.github/workflows/*.yml`,
`Jenkinsfile`) where a developer hardcodes a deploy key "just to get the
pipeline working" and forgets to move it to a secrets manager. This is exactly
the pattern truffleHog and gitleaks are built to catch at scale — see File 4.

## 3. API Keys in API Responses and Error Messages

### 3.1 Mechanism

Two common root causes:

- **Debug/verbose error handlers left enabled in production.** A stack trace or
  a verbose error object can include internal configuration values, including
  the very API key used to reach a downstream service, if that config object is
  serialized into the error response instead of a sanitized message.
- **Over-inclusive response objects.** An endpoint that returns "the user's
  account object" or "the integration configuration" sometimes includes fields
  the frontend never renders but which were never stripped from the backend
  response — a classic case of returning the full database row instead of a
  DTO with only the fields actually needed. This overlaps conceptually with
  Excessive Data Exposure (API3/BOPLA) — cross-reference that series for the
  general pattern; this section focuses specifically on when the
  over-exposed field is a credential.

### 3.2 Manual Testing Workflow

- Trigger errors deliberately: malformed JSON bodies, wrong content-types,
  missing required fields, invalid IDs, oversized inputs — anything likely to
  hit an unhandled exception path rather than a clean validation error path.
  Compare verbose vs. generic error responses; a verbose one is a signal to dig
  further even before you find a key in it.
- Inspect full response bodies in Burp, not just the fields the UI renders —
  use Burp's Proxy history and check every response body for provider-shaped
  strings from File 1's table, not just the ones the frontend visibly uses.
- Check integration/webhook/settings endpoints specifically — endpoints that
  let a user view or manage their connected third-party integrations
  (payment processor, email provider, analytics) are disproportionately likely
  to echo back a stored API key in full instead of masking it
  (`sk_live_••••1234`), because the developer only tested the "set" path and
  never re-reviewed the "get" path.

### 3.3 Real-World Note

This is a frequent finding category in "connect your account" style
integrations (e.g., an app that stores a user's third-party API key on their
behalf to perform actions for them) — the settings/integrations GET endpoint
returns the full unmasked key instead of the last 4 characters, because the
masking logic was applied on the frontend display component rather than the
backend response, and the tester with API access (or a proxy) bypasses the
frontend entirely.

## 4. API Keys via Browser DevTools Network Tab

### 4.1 Mechanism

This isn't a separate leakage *root cause* so much as a separate discovery
*vantage point* — it surfaces keys that reach the wire via the query-string
transmission pattern flagged in File 1 as worst-practice, and it surfaces keys
that a JS bundle constructs dynamically (e.g., concatenated from multiple
config values at runtime) and therefore wouldn't appear as a single static
string in the bundle itself even though grepping the bundle would fail to find
it.

### 4.2 Manual Workflow

- Open DevTools → Network tab, reload the page and interact with every feature
  (this matters — many key-bearing requests only fire on specific user actions
  like "connect payment method" or "load map view", not on initial page load).
- Filter by `Fetch/XHR` to cut noise from static assets.
- For each request, check: the full request URL (query string), all request
  headers, and the request body if POST/PUT. Query strings are visible directly
  in the Network tab's request list without even opening request details,
  which is exactly why query-string key transmission is the pattern most
  likely to be caught by casual observation, screen-sharing, or browser
  history sync.
- Check `Preview`/`Response` tab of each response too — this is the DevTools
  equivalent of Section 3's response-body inspection, useful when you don't
  have Burp running and want a quick manual check.

### 4.3 Real-World Note

Query-string API keys showing up in browser history and being synced via
browser account sync (e.g., cross-device history sync) is a leakage vector
that's easy to underestimate because it doesn't require an "attacker" doing
anything technical at all — a shared or synced browser profile is enough.
This is part of why the query-string pattern is treated as inherently
worse practice than headers, independent of any other control.

## 5. API Keys in Publicly Shared Postman Collections

### 5.1 Mechanism

Postman collections often store environment variables — including API keys set
during testing — directly inside the collection JSON, in the
`variable`/`environment` blocks. Developers export and share collections
(publicly on the Postman public workspace/network, in a GitHub repo as API
documentation, in a support forum post asking for help) without realizing the
export includes their configured values, not just placeholder variable names.

### 5.2 Manual Discovery Workflow

- Search the Postman public API network / public workspaces for the target
  organization or product name directly through Postman's own search.
- Search GitHub for committed `.postman_collection.json` or
  `.postman_environment.json` files using the same dorking approach as Section
  2.4:
  ```
  org:target-org filename:.postman_environment.json
  ```
  Same flag reasoning as Section 2.4 — `filename:` restricts to that exact
  filename pattern, which is Postman's standard export naming.
- Once you have a collection/environment file, inspect the `value` field of
  every variable entry, not just ones with obviously credential-sounding
  `key` names — some collections use generic names like `token1`, `x`, or
  leave the descriptive name blank.
- Check whether the value is literally the secret (`"value": "sk_live_..."`) or
  a Postman "secret" type variable — Postman does support a `type: "secret"`
  field that masks the value in the Postman UI, but if the raw JSON is what's
  been exposed (e.g., committed to git), that masking is a UI-only convenience
  and does not remove the plaintext value from the exported file itself.

### 5.3 Real-World Note

This is a very "easy button" leakage vector precisely because it requires no
reverse engineering at all — the collection is *designed* to contain working,
pre-filled example requests, which is the entire point of sharing it for
onboarding/documentation purposes. HackTheBox's API-focused machines and
challenges frequently script this exact scenario (a discoverable Postman
export, or an equivalent Swagger/OpenAPI file with embedded example
credentials) as an intended foothold step — worth practicing there
specifically because PortSwigger has no direct lab for this vector.

## 6. WAF / API Gateway Relevance for This File

As established in File 1, none of the five techniques in this file involve
sending an attack-shaped request to the target's live API — they involve
reading content (JS bundles, git history, error responses, DevTools traffic
you generated through normal use, and third-party-hosted Postman collections)
that a WAF or gateway sitting in front of the API has no visibility into or
relevance to. The one exception, DevTools-based discovery (Section 4), does
involve normal application traffic — but it's traffic indistinguishable from
ordinary use, so there's nothing for a WAF to flag.

## 7. PortSwigger, HackTheBox, and HackerOne Mapping for This File

**PortSwigger (Apprentice → Practitioner → Expert):**
- *Information Disclosure* topic, Apprentice: "Information disclosure in error
  messages" — directly applicable to Section 3's error-message leakage, though
  the lab's specific scenario isn't API-key-flavored; the *methodology*
  transfers directly.
- *Information Disclosure* topic, Practitioner: "Information disclosure via
  version control history" — this is the closest PortSwigger lab to Section 2
  in spirit (finding sensitive data via `.git` exposure) and is worth doing
  even though it covers an exposed `.git` directory on the live web server
  rather than a public GitHub repo's history; the extraction technique
  (`git log`, `git show` against recovered objects) is the same skill.
- No PortSwigger lab exists for JS-bundle key hunting (Section 1), Postman
  collection leakage (Section 5), or GitHub dorking specifically (Section 2.4)
  — stated honestly rather than mapped to a loosely-related lab.

**HackTheBox (supplementary, for the gaps above):**
- API-focused machines/challenges that include a discoverable Postman
  collection, Swagger/OpenAPI file, or JS-bundle-embedded key as an
  intended foothold — demonstrates Sections 1 and 5 in a realistic
  end-to-end scenario where the leaked key is the entry point to a larger
  chain, not the end of the exercise.

**HackerOne (case study reading, not a lab):**
- Search Hacktivity for disclosed reports tagged with hardcoded API key /
  secret exposure across mapping, payments, and analytics SDK integrations —
  useful for calibrating real-world severity assessment (Section 1.4) and for
  seeing how bug bounty programs typically triage "found a key, what's its
  actual scope" (which is exactly what File 3 covers next).

## 8. Cross-References

- **File 3** — what to do once you've found a key (entropy check if you
  suspect a *pattern* rather than a specific leaked key, scope testing, and
  rotation testing).
- **File 4** — truffleHog and gitleaks automate Sections 1–2 of this file at
  scale; nuclei templates can automate parts of Section 3.
- **API Reconnaissance series** — for the broader endpoint enumeration this
  file assumes as a starting point.
- **Excessive Data Exposure (API3/BOPLA)** — for the general over-inclusive
  response pattern referenced in Section 3.1.
