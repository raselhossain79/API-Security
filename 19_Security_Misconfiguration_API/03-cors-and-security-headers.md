# 03 — CORS and Security Header Misconfiguration on API Endpoints

## Part A: API-Specific CORS Misconfiguration

### A.1 Scope note — read this before the rest of the file

The CORS mechanism itself (same-origin policy, what a preflight is, why `Access-Control-Allow-
Origin` exists, how the browser decides whether to expose a response to requesting JS) is fully
covered in the web app series' CORS notes and is not repeated here. This file assumes that
mechanism is understood and focuses only on **how CORS misconfiguration shows up differently on
API endpoints** compared to a traditional server-rendered web app, and the three patterns most
common in APIs specifically.

### A.2 Why CORS misconfiguration is more consequential on APIs than on typical web apps

A traditional web app's CORS surface is usually a handful of AJAX endpoints bolted onto an
otherwise server-rendered site. An API-first architecture (SPA frontend + separate API origin,
mobile app backend, third-party-consumable API) makes **every single endpoint** a CORS decision
point, because the entire application is consumed cross-origin by design (the SPA on
`app.example.com` calling `api.example.com`). This means:

- The credential typically at risk is a **bearer token or API key returned in a JSON body**, not
  just a session cookie — CORS misconfiguration on a login or token-refresh endpoint can leak the
  token itself into an attacker-controlled origin's JavaScript, not just let the attacker ride an
  existing session.
- API teams frequently implement CORS **dynamically** (reflecting whatever `Origin` header is
  sent, rather than checking it against an allow-list) because the API is meant to serve many
  different frontend deployments (staging, preview branches, multiple client apps) — this
  dynamic-by-convenience pattern is exactly what creates the reflected-origin bug in §A.3.

### A.3 Reflected origin misconfiguration

**Mechanism (API framing).** The server takes whatever value the client sends in the `Origin`
request header and echoes it back verbatim in `Access-Control-Allow-Origin`, instead of validating
it against a fixed allow-list. Combined with `Access-Control-Allow-Credentials: true`, this tells
the browser: "any origin that asks is trusted, and may read the response with credentials/tokens
attached."

**Piece-by-piece exploitation:**

1. Identify an authenticated API endpoint that returns sensitive data (e.g., `GET
   /api/v1/account` returning profile data, an API key, or a token).
2. Send the request with an arbitrary attacker-controlled `Origin` header:
   ```
   GET /api/v1/account HTTP/1.1
   Host: api.example.com
   Origin: https://attacker.com
   Cookie: session=...
   ```
3. **Read the response headers.** If you see:
   ```
   Access-Control-Allow-Origin: https://attacker.com
   Access-Control-Allow-Credentials: true
   ```
   — the value after `Access-Control-Allow-Origin` is *exactly* the value you sent in `Origin`,
   not a fixed domain. That is the misconfiguration: the server is trusting the request instead of
   validating it.
4. Build a proof-of-concept page hosted on any attacker-controlled origin that issues a
   `fetch()`/`XMLHttpRequest` with `credentials: 'include'` to the vulnerable endpoint. Because the
   browser sees a matching `Access-Control-Allow-Origin` for its own origin and
   `Access-Control-Allow-Credentials: true`, it releases the response body to the attacker's page
   JavaScript — this is the step that turns a header misconfiguration into actual data theft, and
   it only works because the browser, not the server, is the enforcement point (see file 01, §3).

**API-specific nuance:** because API responses are JSON rather than rendered HTML, the stolen
response is typically **directly machine-parseable** by the attacker's script — no scraping DOM
elements, just `response.json()` and read the token/PII field straight out.

### A.4 Null origin bypass

**Mechanism (API framing).** Some server-side CORS configurations explicitly allow-list the
literal string `null` as a trusted origin — usually a leftover from testing against a locally
opened HTML file (`file://` origins send `Origin: null`) or a misunderstanding that `null` is a
"safe default" rather than an attacker-obtainable value.

**Piece-by-piece exploitation:**

1. Confirm the server trusts `null`:
   ```
   GET /api/v1/data HTTP/1.1
   Host: api.example.com
   Origin: null
   ```
   Response containing `Access-Control-Allow-Origin: null` with `Access-Control-Allow-Credentials:
   true` confirms it.
2. An attacker doesn't need to control a domain to send `Origin: null` — a browser sends `null` as
   the origin automatically for requests originating from a **sandboxed iframe** (`<iframe
   sandbox src="...">` without `allow-same-origin`) or a `data:` URI. This means the "attacker
   origin" for this bypass can be a throwaway sandboxed iframe embedded anywhere, with no domain
   registration required at all.
3. The exploit page hosts a sandboxed iframe whose content makes the cross-origin request; because
   the iframe's origin serializes to `null`, and the server explicitly trusts `null`, the same
   data-exfiltration flow from §A.3 step 4 applies.

**API-specific nuance:** API teams sometimes add `null` to an allow-list specifically to support
testing tools like Postman or curl scripts run locally during development, then ship that
allow-list entry to production without realizing `null` is trivially forgeable by any attacker,
not just their own local tools.

### A.5 Wildcard with credentials

**Mechanism (API framing).** Per the CORS spec, browsers **refuse** to honor
`Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` — this
combination is invalid and the browser will not expose the response. This is worth testing for
explicitly rather than assuming it's exploitable on sight, because it commonly is *not*:

**Piece-by-piece: the two ways this actually plays out in APIs**

1. **True wildcard, no credentials** (`Access-Control-Allow-Origin: *`, no
   `Access-Control-Allow-Credentials` header at all): this is often *intentional and safe* for a
   genuinely public, unauthenticated API (e.g., a public read-only pricing or reference-data
   endpoint). Confirm there is no session/token/API-key-based access control on the endpoint before
   flagging this as a finding — a wildcard on data that's public to everyone anyway is not a
   vulnerability.
2. **Wildcard attempted alongside credentials, server misconfigured to work around the browser
   restriction:** some frameworks/gateways (misconfigured reverse proxies especially) end up
   emitting a *literal* wildcard while still trying to support credentialed requests by having a
   separate code path that reflects the origin instead of using `*` whenever a credential-bearing
   header (`Authorization`, `Cookie`) is present in the request — in practice, this collapses back
   into the reflected-origin case in §A.3, and testing should follow that flow: send a request with
   `Origin` + `Cookie`/`Authorization` and check whether the *credentialed* response actually
   reflects your origin instead of returning `*`.
3. **API-key-in-header architectures are a distinct trap.** Many API-first apps authenticate via
   `Authorization: Bearer <token>` rather than cookies, and mistakenly believe CORS credential
   rules don't apply to them because they're "not using cookies." This is incorrect — if a request
   requires a custom header, it's already a preflighted request regardless of credentials mode, and
   if the response is readable by a wildcard-trusted origin, the token used to make the request is
   still exposed via the JSON response body even without `Access-Control-Allow-Credentials` being
   involved, **provided the attacker's page can trigger a request that includes a valid bearer
   token in the first place** — which is why this pattern matters most in combination with a
   reflected/null origin bug rather than a pure wildcard.

### A.6 CORS testing checklist for API endpoints specifically

1. Test every authenticated endpoint with `Origin: https://<random-attacker-domain>` — not just
   the login endpoint. Token-refresh, account, and admin-adjacent endpoints are the highest-value
   targets since their responses often carry more sensitive JSON than the login response itself.
2. Test `Origin: null` separately — some implementations allow-list it even when they correctly
   reject random domains.
3. Test with and without credentials (`Cookie` / `Authorization` header) present, since some
   implementations behave differently based on whether the request "looks" credentialed.
4. Check `Vary: Origin` is present alongside a non-wildcard `Access-Control-Allow-Origin` — its
   absence indicates a caching layer (CDN, gateway cache) may serve one origin's CORS-approved
   response to a different origin's client, an API-specific caching interaction worth flagging
   separately even if the CORS logic itself is otherwise correct.
5. Re-test preflight (`OPTIONS`) responses independently of the actual `GET`/`POST` — some
   backends validate origin correctly on the real request but the gateway in front of them answers
   `OPTIONS` with an overly permissive static response, since `OPTIONS` handling is often
   configured separately at the gateway layer.

---

## Part B: Missing Security Headers on API Responses

### B.1 Why "use the standard header checklist" is the wrong approach for APIs

A generic security-header checklist (CSP, X-Frame-Options, etc.) is written for HTML-serving
responses. Applying it uncritically to a pure JSON API wastes review time on headers that don't
apply and, more importantly, **misses the headers that actually matter for APIs**. Go through
each header on its actual relevance to a JSON response:

| Header | Relevant to APIs? | Why |
|---|---|---|
| `Content-Type: application/json` (correct, explicit) | **Yes — critical** | If missing or wrong (e.g., `text/html`, or missing `charset`), some browsers will content-sniff the response. A JSON body containing attacker-influenced data (reflected error messages, user-supplied fields) can be sniffed and rendered as HTML/script in certain legacy browser contexts, turning a JSON API response into an XSS vector. |
| `X-Content-Type-Options: nosniff` | **Yes — critical for APIs** | Directly closes the sniffing risk above. This is arguably the single most API-relevant header on this whole list, more so than for a normal HTML page, precisely because JSON responses are the ones most likely to be misinterpreted if sniffing is allowed. |
| `Cache-Control` / `Pragma` on sensitive responses | **Yes** | Missing `Cache-Control: no-store` on an endpoint returning tokens, PII, or account data means intermediate caches (CDN, corporate proxy, shared gateway cache) may store and later replay that response to a different user — an API-specific data-leak vector distinct from CORS. |
| `Access-Control-*` family | **Yes** | Covered in Part A. |
| `Strict-Transport-Security` | Yes, but not API-specific | Applies equally to any HTTPS service; enforce it, but it's not a pattern unique to APIs. |
| `X-Frame-Options` / `frame-ancestors` (CSP) | **Usually not relevant** | Clickjacking requires a renderable, interactive HTML surface to frame. A pure JSON endpoint returning `application/json` is not framable in any way that matters — don't spend review time flagging its absence on a JSON-only route (cross-reference the web app Clickjacking series for where this *does* matter — any API-adjacent HTML page, like an OAuth consent screen or a Swagger UI page, is back in scope for this header). |
| Full `Content-Security-Policy` | **Usually not relevant** for pure JSON | CSP governs what a *rendered page* is allowed to load/execute. A JSON API response is not rendered. It becomes relevant again for any HTML surface the API server also happens to host (docs pages, error pages rendered as HTML instead of JSON — see file 04). |
| `Access-Control-Expose-Headers` (over-scoped) | **Yes, an API-specific nuance** | By default, JS reading a cross-origin response can only see a small safelisted set of response headers. If a server sets `Access-Control-Expose-Headers: *` or explicitly exposes headers carrying rate-limit internals, request IDs tied to internal tracing, or debug information, this is a self-inflicted expansion of what a permitted cross-origin caller can read — worth checking specifically on APIs because they use custom response headers (`X-RateLimit-*`, `X-Request-ID`) far more than typical web apps do. |

### B.2 Piece-by-piece: testing the two that matter most

**`X-Content-Type-Options` + `Content-Type` combined check:**
```
GET /api/v1/search?q=<script>alert(1)</script> HTTP/1.1
Host: api.example.com
```
If the response reflects the query in an error body and:
- `Content-Type` is missing, or is `text/plain`/`text/html` instead of `application/json`, **and**
- `X-Content-Type-Options: nosniff` is absent,

then a victim tricked into navigating directly to that URL (not via `fetch`, but via a full
navigation — e.g., a crafted link) may have the response content-sniffed and rendered, executing
the reflected payload. This is the API equivalent of reflected XSS and should be tested and
reported using the same severity framing as reflected XSS on a web page, cross-referencing the
web app XSS series for exploitation/impact framing.

**Cache-control on token/PII-bearing endpoints:**
```
GET /api/v1/token/refresh HTTP/1.1
Authorization: Bearer <token>
```
Check the response for `Cache-Control: no-store, no-cache`. Its absence, combined with the
endpoint sitting behind a shared CDN or reverse-proxy cache, means a subsequent unauthenticated (or
differently-authenticated) request routed to the same cache node could receive a cached copy of
another user's token response — confirm this is actually happening (not just theoretically
possible) by sending two requests with different credentials through the same cache path and
diffing the responses, rather than reporting cache-control absence alone as if it were guaranteed
exploitable.

## Part C: WAF / API Gateway Relevance for This File

As stated in file 01 §3, and repeated here because it applies to the whole file: **CORS is
enforced entirely by the browser.** A WAF or API gateway sitting in front of the API can add or
strip CORS response headers (many gateways have a built-in "CORS policy" plugin, e.g., Kong's
`cors` plugin), but it cannot detect or "block" a CORS misconfiguration attack the way it blocks
an injection payload — there is no malicious string in a cross-origin `fetch()` request for a
WAF to pattern-match. The correct framing when testing an API behind a gateway is:

- Determine whether CORS headers are being set by the **application code** or by a **gateway
  plugin** — send the same request directly to the backend origin (if reachable) and compare;
  divergent behavior tells you which layer owns the misconfiguration and therefore where the fix
  needs to land.
- Missing security headers are the same story: a gateway response-transformation policy can inject
  `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` centrally for every route it
  fronts — this is a **defensive configuration control**, not something to "bypass." If you find
  the header present when talking to the gateway but absent when reaching the backend directly,
  that's evidence the gateway is doing the job the backend should also be doing natively (worth
  noting as a resilience gap even if not currently exploitable, since bypassing the gateway itself,
  e.g., via SSRF into an internal network, would then reach an unprotected backend).

## Part D: PortSwigger Web Security Academy Lab Mapping

**Apprentice**
1. *CORS vulnerability with basic origin reflection* — directly matches §A.3.
2. *CORS vulnerability with trusted null origin* — directly matches §A.4.

**Practitioner**
3. *CORS vulnerability with trusted insecure protocols* — trusts any origin on `http://`
   regardless of subdomain, a variant of the allow-list-too-loose pattern; relevant if an API
   allow-lists by weak pattern matching rather than exact origin comparison.

**Expert**
4. *CORS vulnerability with internal network pivot attack* — combines a CORS misconfiguration on
   an internal-network-reachable endpoint with SSRF-adjacent pivoting; useful once you've found a
   reflected-origin bug on an API that also has internal-network-only routes, since it demonstrates
   chaining rather than treating CORS as an isolated finding.

**Gap disclosure:** PortSwigger has no lab specifically modeling the `Access-Control-Expose-
Headers: *` over-exposure pattern from §B.1, nor the cache-poisoning-via-missing-cache-control
interaction from §B.2 — both are tested manually using the methodology above rather than against a
dedicated lab. **crAPI** includes endpoints with permissive CORS on token-bearing responses and is
a reasonable supplement for the API-specific credential-theft framing in §A.2.

## Part E: Real-World Notes

- Reflected-origin CORS misconfiguration on token-issuing or account endpoints is one of the
  highest-paying, most frequently reported API bug classes on bug bounty platforms specifically
  because SPA/API architectures make dynamic-origin-reflection a tempting shortcut for supporting
  multiple frontend deployments (prod, staging, PR-preview environments) without maintaining an
  allow-list.
- `X-Content-Type-Options: nosniff` missing on a JSON API has repeatedly been the deciding factor
  in whether a "just an error message reflection" finding escalates to an actual XSS report — this
  header is underrated relative to how often reviewers skip it on "it's just an API" grounds.
- Cache-control gaps on token endpoints tend to be missed because they only manifest under real
  shared-cache infrastructure (CDN, corporate proxy) that isn't present in most local test/lab
  environments — worth explicitly asking a client during scoping whether production sits behind a
  CDN, since a finding that looks theoretical in a lab may be directly exploitable in their real
  deployment.

## Part F: Remediation Summary

- Validate `Origin` against a strict, exact-match allow-list server-side; never reflect it
  verbatim, never trust `null`.
- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
  (browsers block this, but don't rely on browser enforcement as your only safety net — some
  proxies/gateways have historically had bugs here).
- Set `Content-Type: application/json; charset=utf-8` explicitly on every API response and pair it
  with `X-Content-Type-Options: nosniff`.
- Set `Cache-Control: no-store` on every endpoint returning tokens, credentials, or PII.
- Scope `Access-Control-Expose-Headers` to only the specific headers a legitimate client needs;
  never wildcard it on a credentialed endpoint.
