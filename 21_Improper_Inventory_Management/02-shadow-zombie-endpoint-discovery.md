# API9:2023 — File 2: Shadow and Zombie Endpoint Discovery

## Definitions (Precise, Not Interchangeable)

- **Shadow endpoint** — exists and functions, but appears in *no* documentation,
  spec, changelog, or dev portal. It may have been built intentionally (an
  internal admin tool) or accidentally (a debug route left from development). The
  defining trait is: **no record of it exists anywhere a security review would
  look.**
- **Zombie endpoint** — a specific subtype of shadow endpoint: something that was
  *intentionally decommissioned or was never meant to leave a non-production
  environment*, but is still reachable. Test routes, debug panels, and internal
  service endpoints accidentally exposed to the public internet fall here.

Both require the same discovery techniques below; the distinction matters mainly
for how you report and prioritize them (a zombie debug endpoint that dumps env
variables is usually a more urgent finding than a shadow endpoint that's simply
an alternate, equally-secured route to public data).

## 1. Technique: JavaScript File Mining

**What signal reveals the endpoint, and why it works:**
Frontend JavaScript must contain the actual API calls the application makes,
because the browser has to know where to send requests. Documentation can lie or
go stale; the JS bundle cannot — it's the literal source of truth for what the
client calls, including calls to endpoints that were never added to public docs
because they were meant for internal/admin use of the same frontend framework.

**Step-by-step:**

1. **Pull all JS assets**, not just the main bundle:
   ```
   curl -s https://target.com/ | grep -oE 'src="[^"]*\.js"'
   ```
   Then fetch each file, including sourcemaps if present (`.js.map` files —
   these frequently contain full original, unminified source with comments).

2. **Grep for endpoint patterns**, not just literal `/api/` strings — shadow
   endpoints are often prefixed differently:
   ```
   grep -oE '"(/[a-zA-Z0-9_\-/{}\.]+)"' bundle.js | sort -u
   grep -oE '(fetch|axios\.(get|post|put|delete))\(["'\''][^"'\'']+' bundle.js
   ```
   Also search for common internal-tooling naming conventions:
   ```
   grep -iE '(internal|admin|debug|test|staging|beta|_v[0-9]|legacy)' bundle.js
   ```

3. **Use a purpose-built tool for scale** — for large SPAs, manual grep doesn't
   scale. Use `LinkFinder`, `SecretFinder`, or `JSluice` to extract endpoint-like
   strings across dozens of bundles at once:
   ```
   python3 linkfinder.py -i https://target.com -d -o results.html
   ```
   The `-d` flag makes LinkFinder crawl and pull all discoverable JS files
   automatically, not just the one you point it at.

4. **Check for API client SDK definitions.** Many SPAs use a generated API client
   (from an OpenAPI spec) bundled into the JS. If you find a file like
   `api-client.js` or `sdk.min.js`, it frequently contains the *entire* method
   list the backend supports — including admin/internal methods the frontend UI
   never calls but the SDK still exposes, because SDK generation doesn't filter
   by "is this method used in the UI."

5. **Cross-reference every discovered path against public docs.** Anything in the
   JS but not in the docs is, by definition, a shadow endpoint candidate. Confirm
   it's live with a direct request before treating it as a finding.

**Why this works (mechanism):** Frontend build tooling doesn't strip unused code
paths reliably, especially in larger codebases with code-splitting and dynamic
imports. Admin panels sharing a codebase with the public app, feature flags that
hide UI but not the underlying API call, and abandoned feature branches merged but
never fully removed all leave traces in the shipped JS that a security review of
"the documented API" would never catch.

## 2. Technique: Response Inference

**What signal reveals the endpoint, and why it works:**
APIs frequently reference related resources in their responses — IDs, internal
type names, or links — even when the resource they point to has no public
documentation. A response body is the API telling you about itself more honestly
than its docs do.

**Step-by-step:**

1. **Read every field in every response, not just the ones you asked for.** A
   `GET /api/v4/users/42` response containing a field like
   `"permissionGroupId": "internal-staff-7"` tells you a `permissionGroup`
   resource type exists server-side, even if `/permission-groups/` is nowhere in
   the docs.

2. **Test pluralization and REST-convention guesses derived from response
   fields.** If a response references `orderId`, test:
   ```
   /api/orders/{orderId}
   /api/order/{orderId}
   /api/v4/orders/{orderId}/items
   /api/v4/orders/{orderId}/history
   ```
   REST APIs are conventionally predictable — an object referenced by ID
   strongly implies a corresponding resource collection endpoint exists.

3. **Inspect `Link`, `Location`, and HATEOAS-style response fields.** APIs that
   follow HATEOAS conventions embed URLs to related actions directly in
   responses (`"_links": {"self": ..., "cancel": ..., "refund": ...}`). A
   `refund` action link on an order object you didn't know supported refunds is
   a direct, explicit signal of a shadow capability.

4. **Compare responses across user roles.** If you have access to two accounts
   with different privilege levels, diff their responses to the *same* endpoint.
   An admin-tier response containing extra fields (`"internalNotes"`,
   `"riskScore"`, `"adminActions": [...]`) tells you those admin actions have
   corresponding endpoints even though your low-priv account's UI never surfaces
   them.

## 3. Technique: Brute-Forcing (Directory/Endpoint Fuzzing)

**What signal reveals the endpoint, and why it works:**
When no other information source is available, systematic fuzzing forces the
server to reveal what it handles versus what it doesn't, based on response
differentials.

**Step-by-step:**

1. **Build a targeted wordlist, don't just use a generic one.** Combine:
   - A general API wordlist (SecLists' `api/api-endpoints.txt`,
     `raft-large-words.txt`)
   - Terms harvested from JS mining (Technique 1) and response inference
     (Technique 2) — these are far higher-signal than a generic list because
     they're specific to *this* application's naming conventions
   - Common internal/admin naming patterns: `admin`, `internal`, `debug`,
     `test`, `staging`, `_health`, `actuator`, `metrics`, `swagger`,
     `swagger.json`, `openapi.json`, `graphql`, `console`

2. **Run with `ffuf` or `feroxbuster`, filtering on response size/status, not
   just status code alone** — a naive scanner treating every `200` as a hit will
   miss endpoints, and treating every `404` as a miss will miss soft-404s
   (endpoints that return `200` with an "error" body):
   ```
   ffuf -u https://target.com/api/FUZZ -w custom-wordlist.txt \
        -mc all -fs 1234 -t 40
   ```
   `-fs 1234` filters out the known "not found" response size, surfacing
   everything that deviates from it — this catches soft-404s that status-code
   filtering alone would miss.

3. **Fuzz the version segment specifically, combined with path fuzzing** (ties
   into File 01):
   ```
   ffuf -u https://target.com/api/VER/FUZZ -w endpoints.txt \
        -w versions.txt:VER -mc all
   ```
   This cross-products version guesses with endpoint guesses in one pass,
   surfacing combinations like `/api/v1/internal-report` that neither list alone
   would flag as interesting.

4. **Watch for rate limiting or WAF interference during brute-forcing itself** —
   see the WAF/Gateway section below. Slow down (`-p` flag for ffuf request
   delay) and randomize User-Agent/headers if you're getting blocked mid-scan
   before you've covered the wordlist.

## 4. Technique: Error Message Analysis

**What signal reveals the endpoint, and why it works:**
Verbose error messages, especially from frameworks in debug mode or from older
codepaths that never had error handling hardened, frequently disclose internal
routing structure, file paths, or even other endpoint names as part of a stack
trace or framework default error page.

**Step-by-step:**

1. **Send malformed input deliberately to trigger verbose errors**: wrong
   content-type, truncated JSON, oversized payloads, unexpected HTTP methods.
   ```
   curl -X PATCH https://target.com/api/v4/users/1 -d 'not-json'
   ```
   A framework in debug mode may respond with a full stack trace showing
   internal file paths like `/app/routes/internal/userAdmin.js:44`, directly
   naming a route file you didn't know existed.

2. **Test unsupported HTTP methods on every known endpoint** (`TRACE`,
   `CONNECT`, `PATCH`, `PUT` where only `GET`/`POST` are documented). A `405
   Method Not Allowed` response frequently includes an `Allow:` header listing
   *every* method the route actually supports — this can reveal an
   undocumented `DELETE` or admin-only method on an otherwise normal-looking
   endpoint.

3. **Compare error verbosity between suspected old and new environments.**
   Older/deprecated infrastructure is more likely to be running with debug mode
   still enabled (see File 01's mechanism explanation for why — nobody
   revisits legacy stacks to harden them) and will leak more in error responses
   than current infrastructure.

4. **Look for framework-default error pages** left un-customized (Django DEBUG
   pages, Express default stack traces, Spring Boot Whitelabel error pages with
   full exception traces) — these are a strong zombie-endpoint signal because
   customizing error pages is exactly the kind of hardening step that gets
   applied to current infrastructure and skipped on forgotten infrastructure.

## 5. Zombie Endpoint-Specific Considerations

Zombie endpoints (test/debug/internal routes exposed externally) have some
distinct signals worth calling out separately from general shadow-endpoint
discovery:

- **Naming conventions are a strong prior.** Real-world zombie endpoints are
  disproportionately found at predictable names: `/test`, `/debug`, `/_debug`,
  `/internal`, `/health`, `/actuator` (Spring Boot — often exposes environment
  variables, heap dumps, and full request mapping lists if not locked down),
  `/console`, `/admin-test`, `/qa`.
- **Cloud/orchestration metadata leaks.** Zombie endpoints built for internal
  service-to-service communication sometimes assume network-level isolation
  ("nothing outside the VPC can reach this") rather than authentication — if
  network config drifts (a misconfigured ingress rule, an exposed load balancer
  target group), the endpoint has *zero* auth because it was never designed to
  need any. This is a distinct root cause from the deprecated-version problem in
  File 01: here the endpoint never had controls, rather than having controls
  that rotted.
- **Test endpoints often accept unsafe actions without confirmation** — e.g. a
  `/test/reset-user-password` route built for QA automation, left reachable in
  production, requiring no auth because QA automation ran unauthenticated
  against a test environment by design.

## 6. WAF / API Gateway Section — Detection and Bypass Considerations

Unlike File 01 (where WAF relevance is minimal), **this file's techniques directly
interact with WAF/gateway detection**, because brute-forcing and directory
enumeration are exactly the pattern these controls are built to catch.

**Common detection methods:**

- **Rate-based detection** — WAFs and gateways commonly flag a high volume of
  requests from a single IP within a short window, especially requests producing
  a high ratio of `4xx` responses (a strong brute-force signature).
- **Sequential/pattern-based path detection** — some WAFs maintain rules that
  flag rapid requests to structurally similar paths (`/api/vX/...` with
  incrementing or wordlist-like values) as directory brute-forcing.
- **User-Agent and tooling fingerprinting** — default User-Agent strings from
  `ffuf`, `gobuster`, `dirb`, etc. are commonly signature-matched and blocked
  outright regardless of request rate.
- **Behavioral anomaly detection on gateways** (Apigee, Kong, AWS WAF with
  managed rule groups) — flags clients requesting many distinct, previously-unseen
  paths in a short session, which is structurally what shadow-endpoint discovery
  looks like from the server's perspective.

**Realistic bypass considerations:**

- **Rate reduction and jitter** — throttling scan speed and adding randomized
  delays (`ffuf -p 0.5-2.0`) reduces the volume-based signal without eliminating
  the pattern-based signal, so this alone is often insufficient against
  well-tuned gateways.
- **User-Agent and header rotation** — using realistic browser User-Agent strings
  and consistent, realistic header sets (Accept, Accept-Language,
  Sec-Fetch-* headers) defeats naive tooling-fingerprint rules but not
  behavioral/volumetric ones.
- **Distributing requests across time and, in authorized engagement scope, across
  source IPs** — reduces the likelihood of triggering a single-source rate
  threshold, but this must stay within the authorized rules of engagement for
  the assessment; this is not a justification for evading detection on systems
  you don't have explicit permission to test aggressively against.
- **Preferring passive discovery techniques first** (JS mining, response
  inference, error analysis) **before active brute-forcing** — this is the most
  reliable "bypass" in practice: if you can identify shadow endpoints without
  ever sending an anomalous request pattern, there's nothing for the WAF to
  detect in the first place. Treat brute-forcing as your last-resort technique
  precisely because it's the loudest and most detectable of the four methods in
  this file.
- **Honest limitation:** none of the above reliably defeats a well-configured,
  modern WAF/gateway with tuned behavioral rules — the realistic expectation on
  a hardened target is that aggressive brute-forcing *will* be detected and
  potentially blocked or alert the client's SOC. Plan engagement pacing and
  client communication accordingly rather than treating bypass as guaranteed.

## 7. PortSwigger Web Security Academy Lab Mapping

| Difficulty | Lab | Relevance |
|---|---|---|
| Apprentice | *Finding and exploiting an unused API endpoint* | Direct practice of the core shadow-endpoint discovery skill |
| Apprentice | *Exploiting an API endpoint using documentation* | Practice reading real spec/doc structure — the negative-space skill of noticing what's absent from docs |
| Practitioner | *Discovering GraphQL endpoints* / *Bypassing GraphQL introspection defenses* | If the target uses GraphQL, this is the shadow-discovery equivalent (see your GraphQL security notes for full depth) |
| Practitioner | Information disclosure labs (e.g. *Information disclosure in error messages*, *Information disclosure on debug page*) | Directly builds the error-message-analysis technique in Section 4 |
| Expert | *Information disclosure in version control history* | Adjacent skill: source history sometimes reveals routes removed from current code but still deployed — same mindset as JS mining, applied to git history when accessible |

**Honest gap disclosure:** PortSwigger does not have labs specifically modeling
JS-bundle mining at scale, or brute-force wordlist construction from harvested
application-specific terms. These are tooling-heavy techniques better practiced
against real, larger applications (with authorization) or against crAPI.

## 8. crAPI Supplementary Practice

- crAPI's **community and forum modules** include endpoints not linked from the
  main navigation, directly modeling shadow endpoint discovery via response
  inference (IDs/references appearing in one module's responses that point to
  another module's unlinked functionality).
- crAPI ships with an **exposed internal/`mechanic`-role API surface** used for
  its vehicle service workflow — this is a purpose-built zombie/internal-endpoint
  scenario: an API meant for internal mechanic-partner use that is reachable and
  under-authorized from a regular user context. Use it to practice Section 5's
  zombie-endpoint identification technique end-to-end.
- crAPI's JS/mobile client (it ships an accompanying mobile app) is a good target
  for practicing JS/mobile-binary-based endpoint mining, since the mobile client
  frequently calls endpoints the web UI does not expose.

## 9. Cross-References

- Version-segment fuzzing overlaps with **File 01** — use that file's version
  enumeration list combined with this file's path wordlists for maximum coverage.
- If shadow/zombie discovery surfaces a GraphQL endpoint, switch to your
  **GraphQL security testing** notes for introspection and query-based discovery
  techniques, which differ substantially from REST discovery.
- If a discovered zombie endpoint accepts unauthenticated state-changing
  requests, continue with your **Broken Authentication (API2)** and **BFLA
  (API5)** notes.
