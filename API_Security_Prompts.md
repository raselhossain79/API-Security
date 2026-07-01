# API Security Notes — Ready-to-Paste Prompts (All 24 Topics)

Each prompt below is complete — copy the entire code block into a new chat. No editing
needed. Each builds a self-contained note series with README, multiple files, command
breakdowns, PortSwigger lab mappings (or alternative labs where PortSwigger doesn't
cover the topic), and real-world notes.

Topics are numbered in recommended learning order (same as the API_Security_Notes
README). Build them in this order if possible, since later topics assume you understand
earlier ones (especially BOLA, auth, and REST methodology).

---

## [ ] 1. API Recon & Endpoint Discovery

```
I'm building a comprehensive, GitHub-ready note series on API Reconnaissance and
Endpoint Discovery — the mandatory first step before any API penetration test. I already
have a web application security note series (covering SQLi, XSS, SSRF, etc.) and want
this API Security series built to the same depth and structure.

Requirements:
- Cover passive recon (Swagger/OpenAPI spec exposure, JS file mining for API endpoints,
  Google dorking for API docs, Wayback Machine for old endpoints, certificate
  transparency for API subdomains)
- Cover active discovery (directory/endpoint brute-forcing, HTTP method enumeration,
  parameter discovery, content-type fuzzing, response-based endpoint inference)
- Cover shadow API and zombie endpoint identification (deprecated /v1/ still live,
  undocumented admin endpoints, test/debug endpoints left in production)
- Cover API documentation analysis (reading OpenAPI/Swagger specs, Postman collections,
  GraphQL schemas to understand the full attack surface before testing begins)
- I practice on PortSwigger Web Security Academy where relevant — map any applicable
  labs in correct difficulty-progression sequence; note that this topic has limited
  direct lab coverage there and reference crAPI/DVAPI/HackTheBox as alternative
  practice environments instead
- Break into multiple separate files: overview/methodology, passive recon techniques,
  active discovery techniques, a dedicated tooling file covering "kiterunner" (endpoint
  brute-forcing), "Arjun" (parameter discovery), "ffuf" for API fuzzing, and
  "Amass/Subfinder" for API subdomain recon (full flag-by-flag breakdown for each), and
  a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command shown must be broken down piece by piece — explain exactly
  what each flag/parameter does and why. Never give a command as just "run this."

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 2. BOLA — Broken Object Level Authorization (IDOR in APIs)

```
I'm building a comprehensive, GitHub-ready note series on BOLA (Broken Object Level
Authorization) — OWASP API Security Top 10 2023 #1, the single most common API
vulnerability globally. I already have a web application security note series and want
this built to the same depth.

Requirements:
- Explain the difference between BOLA (API-specific term) and IDOR (older web app term)
  — same root cause, different context and testing methodology
- Cover testing BOLA across all ID types: sequential integers, UUIDs, hashed IDs,
  GUIDs, encoded IDs — and techniques for each (enumeration for sequential,
  disclosure-based for hashed/UUID)
- Cover horizontal privilege escalation (user A accessing user B's objects) and
  cross-tenant BOLA (in multi-tenant SaaS APIs) separately, since cross-tenant is
  higher severity and different scope
- Cover BOLA in non-obvious locations: indirect object references in request bodies
  (not just URL path), references hidden in response fields used in subsequent requests,
  and BOLA via HTTP methods (GET allowed, POST/PUT/DELETE also vulnerable but untested)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence; also reference crAPI labs where PortSwigger coverage is limited
- Break into multiple separate files: overview/concept, testing methodology (manual
  step-by-step), common bypass techniques (encoded IDs, indirect references), a
  Burp-Suite-based testing workflow file, and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example and script shown must be broken down piece by piece —
  explain exactly what's being changed and why it bypasses the authorization check.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 3. Broken Authentication (API-specific)

```
I'm building a comprehensive, GitHub-ready note series on Broken Authentication in APIs
— OWASP API Security Top 10 2023 #2. I already have a web application security note
series and want this built to the same depth.

Requirements:
- Cover API-specific authentication flaws: missing authentication on endpoints that
  require it, weak token entropy, token reuse across sessions, insecure token
  transmission (tokens in URLs, query params instead of headers), missing token
  expiration/revocation
- Cover credential stuffing and brute-force testing methodology for APIs (different
  from web form brute-forcing — rate limit detection, response-based detection,
  Intruder vs Turbo Intruder choice)
- Cover authentication bypass techniques: removing auth headers entirely, swapping
  token formats, HTTP method switching to find unprotected paths to the same resource
- Cover sensitive action re-authentication gaps (changing email/password without
  requiring current password — an OWASP API2:2023 specific addition)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence; reference crAPI for authentication-specific API lab practice
- Break into multiple separate files: overview/classification, token security testing,
  credential-based attack techniques, authentication bypass techniques, and a final
  cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example and tool command must be broken down piece by piece.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 4. JWT Attacks (Deep Dive)

```
I'm building a comprehensive, GitHub-ready note series on JWT (JSON Web Token) Attack
Techniques — covering API authentication exploitation in depth. I already have a web
application security note series (which has a basic JWT section in Cryptographic
Failures) and want this as a dedicated, deeper API-focused treatment of the same topic.

Requirements:
- Cover the JWT structure in detail (header.payload.signature — what each part is,
  base64 encoding, JSON structure) before exploitation — mechanism-first approach
- Cover alg:none attack (removing the signature requirement)
- Cover weak secret brute-forcing (HS256 with weak secret, using hashcat/jwt_tool)
- Cover algorithm confusion attacks: RS256→HS256 confusion (using the server's public
  key as the HMAC secret), PS256 variants
- Cover JWK header injection (embedding a malicious JWK in the token header to make
  the server trust your own key)
- Cover kid (Key ID) injection: path traversal via kid parameter, SQL injection via
  kid parameter
- Cover JWT claim manipulation (changing sub, role, admin, exp claims after bypassing
  signature validation)
- Cover token expiry bypass and token refresh flow abuse
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence (PortSwigger has an excellent dedicated JWT lab set — map all of them)
- Break into multiple separate files: overview/JWT structure, alg:none and weak secret
  attacks, algorithm confusion attacks, header injection attacks (JWK/kid), claim
  manipulation, a dedicated "jwt_tool" complete usage file (full flag-by-flag), and a
  final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every payload and tool command must be broken down piece by piece — explain
  exactly what each part of the JWT structure and each attack step does.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 5. OAuth 2.0 Attack Techniques

```
I'm building a comprehensive, GitHub-ready note series on OAuth 2.0 Attack Techniques
— covering API and web authentication flow exploitation. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover OAuth 2.0 flows clearly first (Authorization Code, Client Credentials, Device
  Flow, Implicit — what each is and when it's used) — mechanism-first before attacks
- Cover authorization code interception via redirect_uri manipulation (open redirect
  chaining, subdomain takeover chaining, redirect_uri validation bypass techniques)
- Cover state parameter bypass (CSRF on OAuth flows — missing or predictable state)
- Cover scope elevation (requesting more permissions than intended through parameter
  manipulation)
- Cover token leakage (authorization codes/tokens in Referer headers, browser history,
  logs)
- Cover account linking/account takeover via OAuth (linking a victim's account to an
  attacker-controlled OAuth provider, or vice versa)
- Cover PKCE bypass (when PKCE is implemented but bypassable)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence (PortSwigger has excellent OAuth lab coverage — map all of them)
- Break into multiple separate files: overview/OAuth flows explained, redirect_uri
  attacks, state parameter/CSRF attacks, scope and token leakage attacks, account
  takeover via OAuth chains, and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example must be broken down piece by piece — explain exactly
  which parameter is being manipulated, why the server trusts it, and what the result is.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 6. BFLA — Broken Function Level Authorization

```
I'm building a comprehensive, GitHub-ready note series on BFLA (Broken Function Level
Authorization) — OWASP API Security Top 10 2023 #5. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Explain the difference between BOLA (#1, object-level) and BFLA (#5, function-level)
  clearly upfront — BOLA is about accessing another user's data object; BFLA is about
  executing admin/privileged functions you shouldn't have access to at all
- Cover discovery methodology: finding admin/privileged endpoints (path guessing,
  JS source mining, API docs, response field inference), testing non-admin credentials
  against those endpoints
- Cover common BFLA patterns: HTTP method switching (GET works, but PUT/DELETE/POST to
  admin action also works), endpoint path manipulation (/user/ vs /admin/user/),
  parameter-based role manipulation
- Cover vertical privilege escalation (regular user → admin) and lateral escalation
  (user A → user B's admin panel)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence; reference crAPI for BFLA-specific practice
- Break into multiple separate files: overview/concept, discovery methodology, common
  BFLA patterns, testing with Burp (manual workflow), and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example must be broken down piece by piece — explain exactly
  what's being tested and why the authorization check fails.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 7. BOPLA — Broken Object Property Level Authorization

```
I'm building a comprehensive, GitHub-ready note series on BOPLA (Broken Object Property
Level Authorization) — OWASP API Security Top 10 2023 #3, which merges Excessive Data
Exposure and Mass Assignment from the 2019 list. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Cover Excessive Data Exposure: APIs returning full database objects when only specific
  fields are needed, sensitive fields exposed in responses (passwords, tokens, internal
  IDs, PII) even if the UI doesn't display them
- Cover Mass Assignment: injecting extra JSON fields that the API binds to internal
  object properties (e.g. "isAdmin":true, "role":"admin", "balance":999999 in a
  registration/update request)
- Cover testing methodology: comparing what the API returns vs. what the UI shows,
  systematically testing extra fields on every POST/PUT/PATCH endpoint, comparing
  responses across different user roles
- Cover filter bypass for mass assignment (when some fields are blocked, alternate
  field names, nested objects, different content types)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence; reference crAPI for BOPLA-specific practice
- Break into multiple separate files: overview/concept (explaining both sub-types),
  Excessive Data Exposure testing, Mass Assignment testing, and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example must be broken down piece by piece — explain exactly
  which field is being added/exposed and why the API processes it unexpectedly.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 8. REST API-Specific Testing Methodology

```
I'm building a comprehensive, GitHub-ready note series on REST API-Specific Testing
Methodology — the core procedural framework for testing any REST API. I already have a
web application security note series and want this built to the same depth.

Requirements:
- Cover how to approach a REST API systematically: reading API specs first, mapping
  all endpoints and HTTP methods, setting up Burp/Postman correctly for API testing,
  establishing a baseline of normal behavior before testing
- Cover HTTP method abuse: testing all methods (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD)
  on every endpoint regardless of what the spec says, checking for unintended method
  allowances
- Cover API versioning attacks: older versions (/v1/ vs /v3/) remaining accessible with
  fewer security controls, version enumeration techniques
- Cover content-type manipulation: switching between application/json, application/xml,
  text/plain and observing behavior changes, injection via content-type switching
- Cover response differential analysis: same endpoint tested with different roles,
  different content-types, different parameter values — systematic comparison to find
  information leakage or authorization differences
- Cover parameter fuzzing methodology for APIs (different from web form fuzzing — JSON
  body structure, nested objects, array injection)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence where applicable
- Break into multiple separate files: overview/setup methodology, HTTP method testing,
  versioning attacks, content-type manipulation, response differential analysis, and a
  final methodology checklist file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every command and request example must be broken down piece by piece —
  explain exactly what each header/parameter change tests and why.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 9. API Injection Testing

```
I'm building a comprehensive, GitHub-ready note series on Injection Testing via APIs —
covering how SQLi, NoSQL injection, Command injection, and other injection classes apply
specifically through API endpoints (JSON bodies, query parameters, headers) rather than
traditional HTML form inputs. I already have separate web app note series covering each
injection class in depth; this series focuses on the API-specific delivery context and
methodology differences.

Requirements:
- Cover why API injection testing differs from web app injection: JSON body delivery,
  nested object parameters, array-based injection, GraphQL field injection, different
  encoding requirements
- Cover SQLi via API (JSON body injection, Burp-based testing for API endpoints vs.
  forms)
- Cover NoSQL injection via API (MongoDB operator injection in JSON bodies — $ne, $gt,
  $regex — which is the most common API-specific variant)
- Cover Command injection via API (shell-out parameters in REST API bodies)
- Cover SSTI via API (template expression injection through API string parameters)
- Cover XXE via API (when an API accepts XML content-type even if JSON is the default)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence where applicable
- Break into multiple separate files: overview/API injection context, SQLi via API,
  NoSQL injection via API, Command injection via API, and a final methodology +
  cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every payload must be broken down piece by piece — explain the JSON
  structure and exactly how the injected value breaks out of its intended context.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 10. Unrestricted Resource Consumption

```
I'm building a comprehensive, GitHub-ready note series on Unrestricted Resource
Consumption — OWASP API Security Top 10 2023 #4 (previously "Lack of Resources and
Rate Limiting"). I already have a web application security note series and want this
built to the same depth.

Requirements:
- Cover detection of missing or weak rate limiting (response-based detection, header
  analysis for X-RateLimit-* headers, timing-based detection)
- Cover resource exhaustion via API: pagination limit abuse (requesting millions of
  records in one call), file upload size abuse, regex complexity attacks, expensive
  computation endpoint abuse
- Cover third-party spending limit abuse (APIs that trigger paid third-party calls
  with no limit — SMS, email, payment API calls triggerable without restriction)
- Cover enumeration enabled by absent rate limiting (user enumeration, credential
  stuffing, brute force — cross-reference with Broken Authentication notes)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence; reference crAPI for rate limiting-specific practice
- Break into multiple separate files: overview/concept, detection methodology, resource
  exhaustion techniques, third-party spending abuse, and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request/script example must be broken down piece by piece — explain
  exactly what resource is being exhausted and why the API has no protection.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 11. API Rate Limit & Bot Protection Bypass

```
I'm building a comprehensive, GitHub-ready note series on API Rate Limit and Bot
Protection Bypass — going deeper than simply "rate limiting is missing" (covered in
topic 10) to focus on bypassing rate limits that DO exist. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover header-based IP spoofing for rate limit bypass: X-Forwarded-For, X-Real-IP,
  X-Originating-IP, CF-Connecting-IP — which headers different platforms trust, and
  how to rotate them to bypass per-IP rate limits
- Cover account-level rate limit bypass: distributing requests across multiple accounts
  to stay under per-account limits
- Cover endpoint variation bypass: slight URL variations that bypass rate limit counters
  (/api/v1/login vs /api/v1/Login vs /api/v1/login/)
- Cover timing-based bypass: identifying the rate limit window and structuring requests
  to stay just under the threshold per window
- Cover CAPTCHA and bot protection bypass techniques relevant to APIs (not image
  CAPTCHA — API-specific bot detection like behavioral analysis, header fingerprinting)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence where applicable
- Break into multiple separate files: overview/how API rate limits work, header spoofing
  techniques, timing/distribution bypass techniques, and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every technique and header example must be broken down piece by piece —
  explain exactly why the server trusts the header and how the bypass exploits that trust.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 12. GraphQL-Specific Attacks

```
I'm building a comprehensive, GitHub-ready note series on GraphQL Security Testing —
a completely separate attack surface from REST APIs that requires its own testing
methodology. I already have a web application security note series and want this built
to the same depth.

Requirements:
- Cover GraphQL fundamentals needed for testing: queries, mutations, subscriptions,
  introspection, types, resolvers, schema structure — just enough to understand what
  you're testing
- Cover introspection abuse: using __schema queries to extract the full API schema
  when introspection is enabled, and what to do with that schema for further testing
- Cover query batching/alias attacks: sending multiple operations in one request to
  bypass per-request rate limits (brute forcing passwords/OTPs via batched mutation
  aliases)
- Cover query depth and complexity attacks: deeply nested queries causing server resource
  exhaustion
- Cover field suggestion leakage: GraphQL error messages revealing field names that
  don't exist but are "close to" existing ones — information disclosure
- Cover BOLA/BFLA in GraphQL context: authorization testing on GraphQL resolvers
- Cover GraphQL injection: injection through GraphQL variables and inline arguments
- Cover introspection disable bypass techniques (when introspection is disabled but
  field suggestions still work)
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence (PortSwigger has a dedicated GraphQL lab set — map all of them); also
  reference dedicated GraphQL practice environments
- Break into multiple separate files: overview/GraphQL fundamentals for pentesters,
  introspection and schema extraction, batching/alias attacks, depth/complexity attacks,
  authorization testing in GraphQL, injection testing, and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every GraphQL query/mutation payload must be broken down piece by piece —
  explain the syntax and exactly what the attack achieves.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 13. Unrestricted Access to Sensitive Business Flows

```
I'm building a comprehensive, GitHub-ready note series on Unrestricted Access to
Sensitive Business Flows — OWASP API Security Top 10 2023 #6. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover the concept clearly: this is about business workflows that can be automated or
  abused at scale via the API even when individual requests are technically authorized
- Cover common real-world scenarios: ticket/inventory scalping (buying all limited
  inventory via automated API calls), referral reward farming (automating referral
  account creation), gift card/coupon abuse, account enumeration at scale, fake review
  generation, payment flow bypass via workflow step skipping
- Cover detection methodology: identifying business-critical API flows that lack
  automation controls (no CAPTCHA, no behavioral rate limiting, no step validation)
- Cover testing approach: workflow step skipping (sending step 3 of a checkout flow
  without completing step 1-2), parameter manipulation to skip payment steps
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence; reference crAPI business logic labs
- Break into multiple separate files: overview/concept, real-world scenario examples
  (each broken down step by step), detection and testing methodology, and a final
  cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every workflow example must be broken down step by step — explain exactly
  which business rule is being violated and why the API allows it.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 14. SSRF (API-specific)

```
I'm building a comprehensive, GitHub-ready note series on SSRF in API contexts — I
already have a separate SSRF note series in my web application security notes covering
the general technique, but this series focuses specifically on API delivery mechanisms
and API-specific SSRF patterns. Cross-reference the web app SSRF notes for bypass
techniques; this series covers what's unique to the API context.

Requirements:
- Cover SSRF via API URL parameters (parameters in REST API request bodies that accept
  URLs — webhook URLs, avatar URLs, document fetch URLs, callback URLs)
- Cover SSRF via API integrations and third-party service calls that APIs trigger
- Cover cloud metadata endpoint exploitation via API-originated SSRF (AWS/GCP/Azure
  metadata services — same endpoints as web app SSRF but reached via API parameters)
- Cover blind SSRF in API contexts (using Burp Collaborator to detect API-triggered
  out-of-band requests)
- Cross-reference web app SSRF notes for filter bypass techniques rather than
  duplicating them; focus this series on the API-specific delivery and discovery
  methodology
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence
- Break into multiple separate files: overview/API SSRF context, SSRF via webhook/
  callback URLs, cloud metadata exploitation via API, blind SSRF in API context, and
  a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every payload and request example must be broken down piece by piece.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 15. Webhook Security

```
I'm building a comprehensive, GitHub-ready note series on Webhook Security — an
increasingly common and frequently missed API attack surface. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover the webhook model clearly first (what webhooks are, how they work, why they're
  used) — mechanism-first
- Cover SSRF via webhook URL registration: registering a webhook with an internal/
  metadata URL so the server makes requests to internal resources when the webhook fires
- Cover webhook signature validation bypass: missing signature validation, weak HMAC
  secret brute-forcing, timing attack on signature comparison
- Cover replay attacks: capturing a legitimate webhook request and replaying it to
  trigger the action again (payments, deployments, privilege changes)
- Cover parameter tampering: modifying the webhook payload body to alter the action
  (e.g. changing event type, modifying amount fields, escalating privileges via payload
  manipulation)
- Cover webhook endpoint enumeration: discovering webhook receiver endpoints that lack
  authentication
- Real-world industry-standard framing throughout, with specific HackerOne-documented
  real-world examples referenced where possible
- Map relevant labs to PortSwigger Web Security Academy where applicable (note that
  dedicated webhook labs are limited there)
- Break into multiple separate files: overview/webhook model, SSRF via webhook, signature
  bypass and replay attacks, payload tampering, and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every exploit technique must be broken down step by step — explain exactly
  what the webhook mechanism does and why each attack works.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 16. API Key Security

```
I'm building a comprehensive, GitHub-ready note series on API Key Security testing.
I already have a web application security note series and want this built to the same
depth.

Requirements:
- Cover API key leakage discovery: keys exposed in JavaScript bundles, git repos
  (GitHub/GitLab dorking), API responses, error messages, request headers visible in
  browser devtools, mobile app decompilation
- Cover API key entropy and predictability testing: low-entropy keys, sequential keys,
  timestamp-based keys that can be guessed
- Cover API key scope and permission testing: testing what a leaked key can actually
  access, privilege escalation via key substitution, keys with broader scope than needed
- Cover API key rotation gap testing: testing whether old/revoked keys still work
- Cover testing for keys accidentally included in API responses or logs
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence where applicable
- Break into multiple separate files: overview/API key types, leakage discovery
  methodology (with dedicated tooling section covering "truffleHog" and "gitleaks" for
  git-based key discovery — full flag-by-flag breakdown), entropy/scope testing, and a
  final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every tool command must be broken down piece by piece — explain each flag.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 17. Security Misconfiguration (API-specific)

```
I'm building a comprehensive, GitHub-ready note series on API Security Misconfiguration
— OWASP API Security Top 10 2023 #8. I already have a Security Misconfiguration note
series in my web application security notes; this series focuses on API-specific
misconfiguration patterns. Cross-reference the web app series for general
misconfiguration testing; focus here on what's unique to APIs.

Requirements:
- Cover exposed API documentation: Swagger UI left accessible on production, OpenAPI
  specs exposing internal endpoint details, GraphQL introspection enabled in production
- Cover missing or misconfigured CORS on API endpoints (API-specific CORS testing
  nuances — cross-reference CORS notes from web app series for mechanism, focus here
  on API delivery context)
- Cover verbose error messages leaking stack traces, internal paths, DB queries, library
  versions via API error responses
- Cover unnecessary HTTP methods left enabled on API endpoints
- Cover default/test credentials left on API management consoles (Swagger UI,
  API gateways like Kong/Apigee with default admin credentials)
- Cover missing security headers on API responses
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence
- Break into multiple separate files: overview, exposed documentation, CORS/header
  misconfiguration, error message leakage, and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every example must be broken down piece by piece — explain exactly what's
  misconfigured and what information/access it gives an attacker.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 18. Improper Inventory Management

```
I'm building a comprehensive, GitHub-ready note series on Improper Inventory Management
— OWASP API Security Top 10 2023 #9. I already have a web application security note
series and want this built to the same depth.

Requirements:
- Cover the core concept: APIs grow over time, old versions/endpoints get forgotten,
  shadow APIs (never officially documented) get created, and these unmonitored endpoints
  have weaker or no security controls
- Cover API version exploitation: discovering and testing deprecated API versions
  (/v1/, /v2/ when /v4/ is current) that still work but lack security controls applied
  to the current version — rate limiting, auth requirements, BOLA checks often absent
  in old versions
- Cover shadow endpoint discovery: finding endpoints that exist but aren't in any
  documentation (via JS file mining, response inference, brute-forcing)
- Cover zombie endpoint identification: test environments, debug endpoints, internal
  endpoints accidentally exposed to the public
- Cover API documentation vs reality mismatches: what the docs say an endpoint does
  vs. what it actually does when tested
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence; reference crAPI for relevant practice
- Break into multiple separate files: overview/concept, version exploitation, shadow
  and zombie endpoint discovery methodology, documentation gap testing, and a final
  cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every discovery technique and test must be broken down step by step.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 19. WebSocket API Security

```
I'm building a comprehensive, GitHub-ready note series on WebSocket API Security testing
— specifically in the context of APIs that use WebSockets for real-time communication,
which requires different testing methodology than standard REST APIs. I already have a
Cross-Site WebSocket Hijacking (CSWSH) note in my web application security series; this
series covers WebSocket API security more broadly. Cross-reference the CSWSH note for
the hijacking technique; focus here on the full API WebSocket testing methodology.

Requirements:
- Cover WebSocket protocol basics needed for testing: the HTTP upgrade handshake, frame
  structure, ws:// vs wss://, full-duplex communication model — just enough to test
  effectively
- Cover WebSocket message manipulation: intercepting and modifying WebSocket messages
  in Burp Suite, replaying messages, fuzzing message content for injection
- Cover injection attacks via WebSocket messages: SQLi, XSS, Command injection, SSTI
  delivered through WebSocket message payloads (different delivery than HTTP but same
  underlying vulns)
- Cover authentication testing on WebSockets: tokens in handshake headers, tokens in
  first message after connection, testing what happens when auth token is expired/invalid
  mid-connection
- Cover authorization testing on WebSockets: sending messages for actions belonging
  to other users, BOLA via WebSocket
- Cover cross-site WebSocket hijacking (origin validation bypass) — reference the
  CSWSH web app note for the full technique, include a summary here in context
- Real-world industry-standard framing throughout
- Map relevant labs to PortSwigger Web Security Academy in correct difficulty-progression
  sequence (PortSwigger has WebSocket labs — map all of them)
- Break into multiple separate files: overview/WebSocket fundamentals for pentesters,
  message manipulation and injection, authentication and authorization testing, origin
  bypass (summary, cross-reference CSWSH notes), and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every Burp-based workflow and payload must be broken down piece by piece.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 20. Unsafe Consumption of APIs

```
I'm building a comprehensive, GitHub-ready note series on Unsafe Consumption of APIs —
OWASP API Security Top 10 2023 #10. I already have a web application security note
series and want this built to the same depth.

Requirements:
- Cover the core concept clearly: applications that consume third-party APIs often
  trust the responses from those APIs without validation — if the third-party is
  compromised or returns unexpected data, the consuming application processes it
  unsafely
- Cover injection via third-party API responses: if a third-party API returns data that
  gets used in a database query, template, or shell command without sanitization, the
  attacker who controls the third-party can inject into the consuming application
- Cover SSRF via third-party API integrations: URLs returned by third-party APIs that
  get fetched server-side
- Cover data integrity issues: consuming applications that don't validate schema/type
  of third-party responses, leading to unexpected behavior
- Cover testing methodology: how to identify that an application consumes third-party
  APIs, and how to test for unsafe handling of those responses (requires understanding
  the application architecture)
- Real-world industry-standard framing — note that this is a harder category to test
  in black-box scenarios and is more commonly found in white-box/grey-box assessments
  or via source code review
- Map relevant labs to PortSwigger Web Security Academy where applicable; note if
  coverage is limited
- Break into multiple separate files: overview/concept, testing methodology (black-box
  vs grey-box approaches), injection via third-party response scenarios, and a final
  checklist file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every scenario example must be broken down step by step.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 21. SOAP/XML API Attacks

```
I'm building a comprehensive, GitHub-ready note series on SOAP/XML API Security Testing
— relevant for legacy and enterprise API engagements. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Cover SOAP/WSDL basics needed for testing: SOAP envelope structure, WSDL service
  description files, SOAP actions — just enough to navigate and test effectively
- Cover XXE via SOAP: XML external entity injection through SOAP request bodies
  (cross-reference XXE web app notes for technique; focus here on SOAP delivery context)
- Cover SOAP injection: injecting SOAP tags/elements into parameters to alter the
  SOAP message structure
- Cover WS-Security bypass techniques: weak/missing WS-Security headers, replay attacks
  on timestamped SOAP messages
- Cover WSDL enumeration: extracting full API method/parameter information from exposed
  WSDL files
- Cover SQL injection via SOAP parameters
- Cover tooling: "wsdl2postman" for converting WSDL to testable Postman collections,
  SoapUI for SOAP-specific testing (full usage breakdown)
- Real-world industry-standard framing; note that SOAP is primarily relevant for
  enterprise/legacy engagements and is rare in modern public bug bounty programs
- Map relevant labs where they exist; note if coverage is limited
- Break into multiple separate files: overview/SOAP fundamentals for pentesters,
  XXE via SOAP, SOAP injection and WS-Security, tooling (SoapUI), and a final
  cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every payload must be broken down piece by piece — explain the XML/SOAP
  structure and exactly what the injection achieves.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 22. gRPC & Protocol-Level Attacks

```
I'm building a comprehensive, GitHub-ready note series on gRPC Security Testing —
increasingly relevant in microservices environments. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Cover gRPC protocol basics for testers: Protocol Buffers (protobuf), service
  definition files (.proto), gRPC vs REST differences, how gRPC traffic looks in
  Burp Suite — just enough to navigate and test
- Cover gRPC reflection: services that expose their own service definitions at runtime
  (the equivalent of GraphQL introspection / Swagger for gRPC) — how to enumerate all
  available RPCs using reflection
- Cover protobuf manipulation: intercepting and modifying serialized protobuf messages
  in Burp Suite, changing field values, injecting test values
- Cover authorization testing on gRPC: testing if each RPC method enforces auth/authz
  correctly (BOLA/BFLA patterns applied to gRPC methods)
- Cover injection via gRPC fields: delivering SQLi, command injection, SSTI through
  gRPC string fields
- Cover tooling: "grpcurl" (the curl equivalent for gRPC — full flag-by-flag breakdown),
  Burp Suite gRPC interception setup, "grpc-dump" for traffic capture
- Real-world industry-standard framing; note that gRPC is primarily relevant for
  internal microservices testing; rare in external bug bounty scope
- Map relevant labs where they exist; note if coverage is limited
- Break into multiple separate files: overview/gRPC fundamentals for pentesters, service
  enumeration via reflection, protobuf manipulation, authorization testing, injection
  testing, tooling (grpcurl), and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every command and payload must be broken down piece by piece.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 23. Microservices & Service-to-Service Security

```
I'm building a comprehensive, GitHub-ready note series on Microservices Security
Testing — focused on service-to-service communication security within a microservices
architecture. I already have a web application security note series and want this built
to the same depth.

Requirements:
- Cover the microservices attack surface: why microservices have more internal API
  endpoints, how internal service communication differs from external-facing APIs,
  what trust assumptions microservices commonly make about each other
- Cover service identity and authentication: mTLS (mutual TLS) — what it is and how to
  test for weak/missing mTLS between services, JWT-based service tokens
- Cover service impersonation: testing whether internal service endpoints perform
  authorization checks assuming "only other services can reach here anyway"
- Cover lateral movement via internal APIs: using access to one compromised/reachable
  internal service as a pivot to enumerate and attack other internal services
  (typically via SSRF as an initial foothold)
- Cover API gateway bypass: whether internal API endpoints are accessible if you bypass
  the API gateway (common in misconfigured Kubernetes/ECS deployments)
- Real-world industry-standard framing; note that microservices security testing is
  primarily relevant for internal/whitebox pentest engagements — very rare in external
  bug bounty scope
- Map relevant labs where they exist; note if coverage is limited
- Break into multiple separate files: overview/microservices architecture for pentesters,
  mTLS and service authentication testing, service impersonation and lateral movement,
  API gateway bypass, and a final checklist file
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every technique must be broken down step by step — explain exactly what
  trust assumption is being exploited.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## [ ] 24. API Automation & Tooling

```
I'm building a comprehensive, GitHub-ready note series on API Security Testing
Automation and Tooling — a reference for the tools used across all other API security
note series in this directory. I already have a web application security note series
and want this built to the same depth.

Requirements:
- Cover each major API testing tool with a DEDICATED section per tool (not a brief
  mention) — same depth as the sqlmap file in my SQLi notes, meaning full flag-by-flag
  breakdown of commonly used commands:
  - Postman/Newman (API collection setup, environment variables, automated test runs)
  - Burp Suite for API testing (configuring for JSON/GraphQL/gRPC, useful extensions
    for API testing: Autorize, InQL for GraphQL, HTTP Request Smuggler, Param Miner)
  - ffuf for API endpoint/parameter fuzzing (API-specific wordlists, JSON fuzzing mode)
  - kiterunner (API endpoint brute-forcing using real-world API route wordlists)
  - Arjun (HTTP parameter discovery)
  - jwt_tool (JWT attack automation — cross-reference the JWT notes; full usage here)
  - nuclei with API-specific templates
  - truffleHog/gitleaks for API key leakage discovery in git repos
- Cover API-specific wordlists worth knowing: SecLists API-specific lists,
  assetnote API wordlists — what they contain and when to use each
- Cover OWASP crAPI setup as the practice environment for API security testing (how
  to run it locally, what vulnerabilities it contains, which notes they map to)
- Real-world industry-standard framing throughout
- Note that this is a "read in parallel with other notes" reference file — no PortSwigger
  lab mapping needed, since this is pure tooling reference
- Break into multiple separate files: overview/when to use which tool, one file per
  major tool or tool cluster, a wordlist reference file, and a final quick-reference
  cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- CRITICAL: every single command shown must be broken down flag by flag — this is
  the entire purpose of this series. No command should appear without full explanation
  of every flag/argument/option used.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```

---

## How to Use This File

1. Check off `[ ]` when a topic is complete.
2. Follow the numbered order — later topics reference earlier ones.
3. Build topic #24 (Tooling) in parallel with other notes, not necessarily last —
   you'll want the tools set up while practicing the techniques.
4. For practice: set up crAPI locally before starting topic #2 (BOLA) — it's the
   primary lab environment for most OWASP API Top 10 topics.
