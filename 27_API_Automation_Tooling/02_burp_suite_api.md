# API Security Testing Tooling — Burp Suite for APIs

Cross-reference: JWT series (for JWT attack theory), GraphQL series (for GraphQL
vulnerability classes), HTTP request smuggling / HTTP2 series (for smuggling theory).
This file covers **tool configuration and extension usage only** — vulnerability
mechanics live in their dedicated series.

## 1. Core Burp Configuration for JSON APIs

By default, Burp's scanner and Logger are tuned for HTML/form-based traffic. For
JSON APIs you need to adjust a few things so Burp recognizes and actively tests JSON
bodies.

### 1.1 Enabling JSON parameter parsing

Burp Suite Professional (2020.9+) parses JSON bodies as insertion points
automatically once detected via `Content-Type: application/json`. To confirm/force
this:

- **Proxy → Options → Miscellaneous → "Set 'Connection: close' on all requests"**:
  leave this OFF for API testing — many API gateways multiplex over keep-alive
  connections and forcing close increases latency and can trigger some gateway
  timeout heuristics.
- **Scanner → Scan configuration → Input types**: ensure "JSON" is checked under
  "Static parse locations" so the active scanner inserts payloads into JSON key
  values, not just query/form parameters.
- **Inspector panel** (right-hand pane in Repeater/Proxy): when a request body is
  valid JSON, Burp's Inspector automatically renders it as an editable tree. Click
  any value to edit it in place rather than hand-editing raw text — this preserves
  JSON syntax (quoting, escaping) and avoids self-inflicted 400 errors from malformed
  payloads.

### 1.2 Handling nested and array JSON structures

Burp's JSON insertion point detection walks nested objects and arrays automatically.
For deeply nested bodies where you want to fuzz one specific field:

1. Right-click the request in Repeater → **"Insertion point"** → manually highlight
   the value inside the JSON body.
2. Send to Intruder; Burp preserves the surrounding JSON structure and only
   substitutes the highlighted value.

### 1.3 Content-Type mismatches

Some APIs accept JSON bodies but expect `Content-Type: application/x-www-form-
urlencoded` or vice versa (a common source of parser differential bugs, and
relevant to mass assignment/BOPLA testing — see that series). In Repeater, edit the
`Content-Type` header directly and resend; Burp does not auto-correct it, which is
exactly what you want when testing for parser confusion.

## 2. Configuring Burp for GraphQL

### 2.1 Detecting and marking GraphQL endpoints

Burp 2021.9+ includes native GraphQL support: it auto-detects requests to endpoints
like `/graphql` sending a JSON body containing a `query` key, and renders the
Inspector with a GraphQL-aware editor (separate panes for the query, variables, and
operation name).

- **Inspector → GraphQL tab**: edit the query text directly; Burp keeps the
  `variables` JSON object in sync separately, so you don't have to manually escape
  the query string inside the outer JSON body.
- If Burp does not auto-detect a GraphQL endpoint (e.g., it's served over a
  non-standard path or via `GET` with a `query` querystring parameter), right-click
  the request → **"Change request method"** or manually confirm the body content-
  type is `application/json` and the body contains a top-level `query` field — Burp
  will then offer the GraphQL Inspector view.

### 2.2 Sending to Intruder for GraphQL

When sending a GraphQL request to Intruder, mark insertion points inside the
`variables` object rather than the `query` string itself in most cases — this
targets user-controlled input the same way a real client would, and avoids breaking
GraphQL query syntax during payload substitution.

## 3. Key Extensions for API Testing

All extensions below are installed via **Burp → Extensions → BApp Store** (Burp
Suite Professional) or manually loaded as `.py`/`.jar` files via **Extensions → Add**
for Community Edition where the BApp Store version is unavailable.

### 3.1 Autorize — Automated Authorization/BOLA Testing

**What it does**: Autorize automatically repeats every request that passes through
Burp's proxy using a lower-privileged session (a second set of cookies/tokens you
provide), and flags responses where the lower-privileged replay returns a similar
response to the original — indicating a potential BOLA/BFLA (broken object/function
level authorization) finding. Cross-reference the BOLA and BFLA series for the
underlying vulnerability class.

**Setup, step by step**:

1. Install Autorize from the BApp Store.
2. Go to the **Autorize** tab in Burp.
3. In the **Configuration** sub-tab, paste the **low-privileged** session's
   authorization header value into the **"Headers"** field, e.g.:
   ```
   Authorization: Bearer eyJhbGciOi...LOW_PRIV_TOKEN
   ```
   You can add multiple headers (one per line) if the low-priv session needs more
   than one header (e.g., both `Authorization` and a custom `X-API-Key`).
4. Set **"Enforcement detector"** mode:
   - **Enforced** (default heuristic): Autorize compares response length and status
     code between the original (high-priv) and replayed (low-priv) request, and
     colors the result:
     - **Red = Bypassed!**: low-priv request got a response with similar
       length/status to the original → likely authorization bug, investigate.
     - **Yellow = Is enforced (but with same response length)**: response differs
       in content but not length — inspect manually, this is a heuristic gray zone.
     - **Green = Enforced**: low-priv request was rejected — no finding.
5. Under **"Filters"**, restrict scope to the target host(s) so Autorize does not
   waste requests replaying analytics/CDN/third-party calls. Add the target domain
   under **"Include in scope"**.
6. Toggle **"Interception is On"** at the top of the Autorize tab. From this point,
   every request that passes through Burp's proxy (browse the app manually as the
   high-privileged user) is automatically replayed with the low-priv token and
   color-coded in the Autorize results table.
7. **Unauthenticated check**: Autorize also supports a third comparison — no
   authorization header at all — toggled via the **"Also test with no headers
   (unauthenticated)"** checkbox, to check for fully unauthenticated access to
   endpoints that should require any valid session.

**Practical workflow**: log in as User A (high-priv or resource owner) in the
browser with Burp's proxy active, paste User B's (or an unauthenticated) token into
Autorize, then simply browse/use the application normally as User A. Every object
User A touches (order IDs, profile IDs, admin functions) is auto-replayed as User B,
surfacing BOLA/BFLA findings without manually re-sending each request.

**Limitations to note in your report**: Autorize's response-length heuristic
produces false positives on endpoints that return generic error pages of similar
length regardless of authorization outcome, and false negatives on endpoints that
return `200 OK` with an empty/redacted body for unauthorized users. Always manually
verify red/yellow findings before reporting.

### 3.2 InQL — GraphQL Testing

**What it does**: InQL introspects a GraphQL endpoint's schema, generates a
navigable list of every query/mutation/subscription with pre-built request
templates, and provides a standalone Attacker tool for batch/bulk query testing.

**Setup, step by step**:

1. Install InQL from the BApp Store (v5+ is the actively maintained Burp-native
   version; older InQL was a standalone Python CLI — the CLI variant is still
   usable and covered below).
2. Go to the **InQL** tab in Burp.
3. **Scanner sub-tab**: enter the target GraphQL endpoint URL and click **"Run
   Scan"**. InQL sends an introspection query (`__schema { types { ... } }`) and, if
   introspection is enabled on the target, builds a full schema tree in the left
   panel — every type, field, query, mutation, and subscription.
4. If introspection is **disabled** (a common hardening measure), InQL cannot
   auto-generate the schema tree; you must fall back to manual schema reconstruction
   via error-based field guessing or a tool like `clairvoyance` (outside this
   series' scope — noted here for completeness). Cross-reference the GraphQL series
   for introspection-disabled testing methodology.
5. Click any query/mutation in the schema tree to auto-generate a fully-formed
   request template with all arguments and selectable fields — InQL pre-fills
   scalar arguments with placeholder values (e.g., `"placeholder_string"`, `0`) that
   you then edit with real test data.
6. **Right-click any generated query → "Send to Repeater"** to move it into a normal
   Burp Repeater tab for manual manipulation and follow-on testing (auth bypass,
   injection, BOLA via ID substitution in arguments).
7. **Attacker sub-tab**: for batch testing (e.g., testing every mutation for a
   specific authorization bypass pattern), select multiple queries/mutations from
   the schema tree and InQL will send them as a batch, letting you compare
   authenticated vs unauthenticated responses across the entire schema at once —
   useful for quickly surfacing BFLA across dozens of mutations rather than
   testing each one manually.

**InQL CLI mode** (standalone, outside Burp — useful for CI/automation):
```
inql -t https://api.target.com/graphql -o /tmp/inql_output
```
- `-t <url>`: target GraphQL endpoint.
- `-o <dir>`: output directory where InQL writes generated `.json` query templates
  and an HTML schema report, for offline review or import into Postman.
- `-k`: (if present in your InQL version) disables TLS certificate verification —
  useful against self-signed cert lab/staging environments.
- `--proxy <host:port>`: route the introspection request through Burp's proxy
  (e.g., `--proxy 127.0.0.1:8080`) so the raw introspection request/response is
  also visible in Burp's HTTP history for manual review.

### 3.3 JWT Editor — Token Manipulation

**What it does**: adds a **JWT Editor** tab inside Repeater/Proxy message editors
whenever a JWT is detected in a request (header or body), and a dedicated **JWT
Editor Keys** tab for managing signing keys used to forge tokens. Cross-reference
the JWT series for the underlying attack theory (alg confusion, `none` algorithm,
key confusion, kid injection) — this section covers extension mechanics only.

**Setup, step by step**:

1. Install "JSON Web Tokens" (the extension is commonly listed as **JWT Editor**) from
   the BApp Store.
2. Open any request in Repeater that contains a JWT (e.g., in the `Authorization:
   Bearer <token>` header). Burp auto-detects the JWT structure and adds a **"JSON
   Web Token"** sub-tab in the message editor showing the decoded header and payload
   as editable JSON.
3. Edit any claim (e.g., change `"role": "user"` to `"role": "admin"`, or change
   `"sub"` to another user's ID) directly in the decoded view — the extension
   re-encodes the base64url segments automatically as you type.
4. **Signing the modified token**:
   - Go to the **JWT Editor Keys** tab (top-level Burp tab, separate from the
     per-request panel).
   - Click **"New Symmetric Key"** (for HS256/384/512) or **"New RSA Key"** / **"New
     EC Key"** (for RS/ES algorithms) to generate a fresh key pair, or **"New JWK"**
     to paste a key you've extracted from a JWKS endpoint or brute-forced secret.
   - Back in the per-request JWT tab, click **"Sign"**, choose the key from the
     dropdown, and Burp recomputes the signature segment using that key and updates
     the token in the request.
5. **Attack-specific buttons in the JWT tab**:
   - **"Attack" → "None"**: sets `alg` to `none` and strips the signature, for
     testing `none`-algorithm acceptance.
   - **"Attack" → "Embedded JWK"**: injects a `jwk` header claim pointing to an
     attacker-controlled public key and self-signs with the matching private key —
     tests whether the server trusts an embedded key rather than validating against
     its own trusted key store.
   - **"Attack" → "JWK Key ID"**: supports `kid`-based key confusion attacks —
     letting you set the `kid` header to a path traversal or SQL injection payload
     to test if the server resolves keys unsafely based on that claim.

### 3.4 HTTP Request Smuggler

**What it does**: automates detection of HTTP request smuggling conditions
(CL.TE, TE.CL, TE.TE desync) between a front-end proxy/gateway and back-end API
server. Cross-reference the HTTP request smuggling and HTTP/2 series for smuggling
theory; this section is extension usage only.

**Setup, step by step**:

1. Install "HTTP Request Smuggler" from the BApp Store.
2. Right-click a request (in Proxy history, Repeater, or Target) → **"Extensions" →
   "HTTP Request Smuggler" → "Smuggle Probe"**. The extension sends a series of
   crafted probe requests with conflicting `Content-Length` and `Transfer-Encoding`
   headers and times/observes the responses to infer front-end/back-end desync
   behavior.
3. Results appear in Burp's **Issues** panel (or the Dashboard's issue list) tagged
   with the specific desync type detected (e.g., "HTTP request smuggling: CL.TE
   ambiguity").
4. For manual follow-up, the extension also adds pre-built smuggling payload
   templates accessible via right-click → **"Extensions" → "HTTP Request Smuggler" →
   "Turbo Intruder"** integration, which launches a Turbo Intruder script pre-loaded
   with the smuggling payload for high-speed confirmation/exploitation (Turbo
   Intruder is a separate BApp Store extension that HTTP Request Smuggler depends
   on for some of its advanced probes — install it alongside if prompted).
5. **Configuration → Smuggler settings** (accessible from the extension's own
   settings tab) lets you tune:
   - **Concurrent connections**: how many parallel probes to send; lower this
     against production/rate-limited API gateways to avoid tripping WAF/rate-limit
     blocking mid-scan.
   - **Timeout thresholds**: how long to wait for a timing-based desync signal
     before marking a probe inconclusive — raise this on high-latency targets to
     reduce false negatives.

### 3.5 Param Miner — Hidden Parameter and Header Discovery

**What it does**: guesses hidden/unlinked HTTP parameters and headers by sending a
baseline request plus many variant requests, each adding one candidate
parameter/header from a wordlist, and diffing responses to detect ones that change
server behavior — surfacing hidden parameters an API accepts but never documents
(relevant to mass assignment and cache poisoning testing).

**Setup, step by step**:

1. Install "Param Miner" from the BApp Store.
2. Right-click a request → **"Extensions" → "Param Miner" → "Guess params"** (or
   **"Guess headers"** / **"Guess cookie names"** — separate menu entries for each
   input type).
3. In the dialog that appears:
   - **Wordlist**: choose the built-in wordlist or point Param Miner at a custom
     file (e.g., a SecLists parameter wordlist — see file 08).
   - **"Diff based on"**: choose which response signal to diff on — status code,
     response length, or a specific reflected string. For API JSON responses,
     response length is usually the most reliable signal since JSON responses are
     rarely padded with irrelevant whitespace the way HTML pages are.
4. Click **"OK"** to start; results stream into a dedicated **Param Miner** results
   tab, listing each candidate parameter/header that produced a response different
   from baseline, ranked by confidence.
5. **Global passive settings** (Extensions → Param Miner → its own **Settings** tab):
   - **"Enable cache poisoning detection"**: passively watches all traffic for
     signs of unkeyed input reflected into cached responses — leave this on during
     general Burp usage against any API sitting behind a caching layer (see the
     web cache poisoning series for the underlying vulnerability class).
   - **Rate limit / thread count**: reduce against gateways with aggressive
     rate-limiting to avoid false negatives from throttled responses being
     misread as "no difference."

## 4. Practical Combined Workflow (crAPI Example)

Against crAPI (see file 08 for setup):

1. Configure Burp as browser proxy, log into crAPI as a normal user, browse all
   features (profile, orders, community posts, vehicle location).
2. Enable Autorize with a second low-privileged/victim account's token → re-browse
   as the first user → review red/yellow flags for BOLA on `/identity/api/v2/user/...`
   and `/workshop/api/...` endpoints.
3. If testing crAPI's GraphQL-adjacent or JSON-heavy endpoints, use the Inspector's
   JSON tree view to manipulate nested `vehicle` and `location` objects directly.
4. Run Param Miner against the `/community/api/v2/community/posts` endpoints to
   check for hidden moderation/admin parameters.
5. Extract a JWT from crAPI's auth flow, load it into JWT Editor, and test `none`-
   algorithm and key-confusion attacks against protected endpoints (cross-reference
   JWT series).

## Real-World Notes

- Many production API gateways (Kong, Apigee, AWS API Gateway) strip or normalize
  `Transfer-Encoding` headers at the edge, which can mask HTTP Request Smuggler
  findings that would appear against the origin server directly — if you have
  origin access in scope, test both the gateway-fronted URL and the origin
  directly and compare results.
- Autorize's default response-length heuristic has a high false-positive rate
  against APIs that return consistent envelope structures (e.g., every response is
  `{"status": "...", "data": null}` on both success and failure) — tighten the
  comparison to status code only, or manually verify every flagged result, on
  these targets.
- InQL's introspection scan is itself a detectable, loggable action — on
  engagements with strict scope/stealth requirements, confirm introspection is
  permitted in scope before running it, since a single introspection query can
  return the entire private schema in one request.
