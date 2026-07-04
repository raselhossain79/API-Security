# API Security — All 27 Topic Prompts + Capstone (Final Verified Version)

Complete, fully verified prompt set. Every prompt has:
- PortSwigger lab mapping with correct difficulty-progression sequence (Apprentice →
  Practitioner → Expert), or an explicit named alternative practice environment when
  PortSwigger coverage is limited (crAPI, HackTheBox, TryHackMe, vendor-based labs)
- Command/payload breakdown requirement (CRITICAL line) in every single prompt
- Automation tool file requirement with full flag-by-flag breakdown
- A dedicated WAF/API Gateway bypass consideration in every prompt — either a real
  bypass section, or an explicit statement of why it does not apply to that topic
- ZIP delivery instruction
- Real-world notes requirement
- README requirement

## What Changed From the Previous Version

Three genuinely missing topics were added after review:
- **Topic 10 — HTTP/2 Attack Techniques** (Rapid Reset, HTTP/2 downgrade smuggling,
  HPACK abuse)
- **Topic 13 — Race Conditions (API-Specific)** (previously just a lab-name mention,
  now a full dedicated topic covering multi-step API chain races, GraphQL batching
  races, idempotency key abuse)
- **Topic 20 — API Gateway Security** (gateway auth bypass, gateway-level rate limit
  bypass, API Gateway Cache Poisoning as a subsection, default credentials)

Three existing topics were enhanced:
- **Topic 7 (BOPLA)** — added CSV/Formula Injection via data export as a section
  (confirmed via real 2025 CVEs, e.g. CVE-2025-11279, CVE-2025-12249)
- **Topic 22 (WebSocket)** — added Server-Sent Events (SSE) as a related section
- **Topic 27 (Tooling)** — added httpx, katana, jq, and a brief mention of RESTler

Build in numbered order — later topics reference earlier ones.

---

---

## [ ] 1. API Recon & Endpoint Discovery

```
I'm building a comprehensive, GitHub-ready note series on API Reconnaissance and
Endpoint Discovery — the mandatory first step before any API penetration test. I
already have a web application security note series (SQLi, XSS, SSRF, etc.) and want
this API security series built to the same depth and structure.

Requirements:
- Cover passive recon: Swagger/OpenAPI spec exposure (common paths: /swagger,
  /api-docs, /openapi.json), JavaScript file mining for API endpoints, Google dorking
  for API documentation, Wayback Machine for historical endpoints, certificate
  transparency logs for API subdomains
- Cover active discovery: directory and endpoint brute-forcing, HTTP method
  enumeration on discovered endpoints, parameter discovery, content-type fuzzing,
  response-based endpoint inference (404 vs 401 vs 403 differences revealing endpoint
  existence)
- Cover shadow API and zombie endpoint identification: deprecated /v1/ still live when
  /v3/ is current, undocumented admin endpoints, test/debug endpoints left in
  production
- Cover API documentation analysis: reading OpenAPI/Swagger specs to extract every
  endpoint, parameter, and data type before testing begins
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence as they appear on the Academy (Apprentice →
  Practitioner → Expert). Note that this topic has limited direct PortSwigger lab
  coverage; reference crAPI (OWASP's deliberately vulnerable API) and HackTheBox API
  challenges as primary alternative practice environments and explain what each covers
- Break into multiple separate files:
  1. Overview and methodology
  2. Passive recon techniques
  3. Active discovery techniques
  4. Dedicated tooling file covering: kiterunner (API endpoint brute-forcing — full
     flag-by-flag breakdown), Arjun (parameter discovery — full flag-by-flag), ffuf
     for API fuzzing (API-specific flags and wordlists — full breakdown), Amass and
     Subfinder for API subdomain recon (full flag-by-flag)
  5. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file (how this differs from lab environments,
  common mistakes, what actually works on real targets)
- CRITICAL: every single command shown must be broken down flag by flag — explain
  exactly what each flag/argument does and why it is used. Never write a command as
  just "run this." I need to understand every part.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 2. BOLA — Broken Object Level Authorization

```
I'm building a comprehensive, GitHub-ready note series on BOLA (Broken Object Level
Authorization) — OWASP API Security Top 10 2023 #1. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Explain the difference between BOLA (API-specific term) and IDOR (web app term) —
  same root cause, different context and testing methodology
- Cover testing across all ID types: sequential integers (enumeration), UUIDs
  (disclosure-based discovery from other responses), hashed IDs (hash type
  identification, rainbow table use), GUIDs, base64-encoded IDs
- Cover horizontal privilege escalation (user A accessing user B's object) and
  cross-tenant BOLA in multi-tenant SaaS APIs separately
- Cover BOLA in non-obvious locations: object references in request bodies (not just
  URL path parameters), references hidden in response fields used in subsequent
  requests, BOLA via HTTP methods (GET protected but POST/DELETE not tested)
- Cover testing methodology using Burp Suite's Autorize extension for automated
  cross-role BOLA detection
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). PortSwigger
  has IDOR/access control labs directly applicable here — map all of them in order.
  Also reference crAPI challenges (Challenges 1-3 are BOLA-focused) as supplementary
  practice and explain what each covers
- Break into multiple separate files:
  1. Overview and concept (BOLA vs IDOR distinction)
  2. Testing methodology (manual step-by-step)
  3. ID type bypass techniques (sequential, UUID, hashed, encoded)
  4. Autorize extension complete usage guide (setup, configuration, interpreting
     results — full breakdown)
  5. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example and tool configuration must be broken down piece by
  piece — explain exactly what is being changed and why it bypasses the authorization
  check. Never write an example as just "change this value."
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 3. Broken Authentication (API-specific)

```
I'm building a comprehensive, GitHub-ready note series on Broken Authentication in APIs
— OWASP API Security Top 10 2023 #2. I already have a web application security note
series and want this built to the same depth.

Requirements:
- Cover API-specific authentication flaws: missing authentication on endpoints that
  require it, weak token entropy, token reuse across sessions, insecure token
  transmission (tokens in URLs or query parameters instead of headers), missing
  token expiration and revocation, sensitive action re-authentication gaps (changing
  email or password without requiring current password verification)
- Cover credential stuffing and brute-force methodology for APIs: rate limit detection
  before attacking, response-based detection (error message differences), choosing
  between Burp Intruder and Turbo Intruder based on rate limiting presence
- Cover authentication bypass techniques: removing Authorization header entirely to
  find unprotected endpoints, HTTP method switching to find unprotected paths, token
  format manipulation
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Authentication
  lab sections are directly applicable — map all of them in order. Also reference
  crAPI authentication challenges as supplementary practice and explain what each covers
- Break into multiple separate files:
  1. Overview and classification of API authentication flaws
  2. Token security testing (entropy, transmission, expiry, revocation)
  3. Credential-based attacks (brute force, stuffing, Burp Intruder vs Turbo Intruder
     — full flag-by-flag breakdown for both)
  4. Authentication bypass techniques
  5. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example and tool command must be broken down piece by piece
  — explain every flag, parameter, and decision. Never write a command as just "run
  this."
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 4. JWT Attacks (Deep Dive)

```
I'm building a comprehensive, GitHub-ready note series on JWT Attack Techniques.
I already have a web application security note series and want this as a dedicated,
deep API-focused treatment.

Requirements:
- Cover JWT structure in full detail before any attacks: header, payload, signature
  — what each part contains, how base64url encoding works, what each standard claim
  means (sub, exp, iat, iss, aud) — mechanism first
- Cover alg:none attack: removing the signature entirely by setting algorithm to none
- Cover weak secret brute-forcing: HS256 with weak/common secrets using hashcat and
  jwt_tool — explain every flag used
- Cover RS256 to HS256 algorithm confusion: using the server's public key as the HMAC
  secret — explain exactly why this works at the cryptographic level
- Cover JWK header injection: embedding a malicious JWK set in the token header to
  make the server use an attacker-controlled key for verification
- Cover kid parameter injection: path traversal via kid to point to a known file,
  SQL injection via kid parameter
- Cover JWT claim manipulation: changing sub, role, admin, exp after bypassing
  signature validation
- Cover token expiry bypass and refresh token abuse
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map ALL JWT labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). PortSwigger
  has an excellent dedicated JWT lab set — map every single lab in the correct order
- Break into multiple separate files:
  1. JWT structure deep dive (mechanism first)
  2. alg:none and weak secret attacks
  3. Algorithm confusion attacks (RS256→HS256, PS256 variants)
  4. Header injection attacks (JWK injection, kid injection)
  5. Claim manipulation techniques
  6. Complete jwt_tool usage guide (every flag broken down, all attack modes)
  7. Final cheatsheet and lab mapping
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every payload and every jwt_tool/hashcat command must be broken down
  piece by piece. Explain what each part of the JWT structure does and why each
  attack bypasses signature validation. Never write a command without explaining
  every flag.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 5. OAuth 2.0 Attack Techniques

```
I'm building a comprehensive, GitHub-ready note series on OAuth 2.0 Attack Techniques.
I already have a web application security note series and want this built to the same
depth.

Requirements:
- Cover OAuth 2.0 flows clearly before any attacks: Authorization Code, Client
  Credentials, Device Flow, Implicit — what each is, when it is used, how each
  flow looks as raw HTTP requests — mechanism first
- Cover authorization code interception via redirect_uri manipulation: open redirect
  chaining, subdomain takeover chaining, redirect_uri validation bypass techniques
  (adding extra paths, using different encoding, parameter pollution)
- Cover state parameter bypass: what the state parameter protects against, how to
  detect missing or predictable state, CSRF on OAuth flows
- Cover scope elevation: requesting additional permissions through parameter
  manipulation
- Cover token leakage: authorization codes and tokens in Referer headers, browser
  history, server logs, error messages
- Cover account takeover via OAuth: linking a victim account to an attacker-controlled
  OAuth provider, pre-account-takeover via email claim trust
- Cover PKCE implementation bypass
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map ALL OAuth labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). PortSwigger
  has excellent OAuth lab coverage — map every single lab in the correct order
- Break into multiple separate files:
  1. OAuth 2.0 flows explained as raw HTTP (mechanism first)
  2. redirect_uri attacks and bypass techniques
  3. State parameter and CSRF attacks
  4. Scope elevation and token leakage
  5. Account takeover via OAuth chains
  6. PKCE bypass
  7. Final cheatsheet and lab mapping
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example must be broken down line by line — explain which
  parameter is being manipulated, what the server does with it, and why that produces
  the vulnerability. Never write an example as just "change this parameter."
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 6. BFLA — Broken Function Level Authorization

```
I'm building a comprehensive, GitHub-ready note series on BFLA (Broken Function Level
Authorization) — OWASP API Security Top 10 2023 #5. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Clearly explain the difference between BOLA (#1, object-level) and BFLA (#5,
  function-level): BOLA is accessing another user's data object; BFLA is executing
  admin or privileged functions that should be entirely inaccessible to the user role
- Cover discovery methodology: finding admin and privileged endpoints via path guessing,
  JavaScript source mining, API documentation gaps, response field inference
- Cover testing non-admin credentials against discovered privileged endpoints
- Cover common BFLA patterns: HTTP method switching (GET allowed but DELETE/PUT to
  admin action also works), endpoint path manipulation (/user/ vs /admin/user/),
  parameter-based role manipulation in request body
- Cover vertical privilege escalation (regular user to admin) and lateral escalation
  (user A accessing user B's admin panel)
- Cover Autorize extension for automated BFLA detection across all endpoints
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant access control
  and privilege escalation labs in correct difficulty-progression sequence (Apprentice
  → Practitioner → Expert). Also reference crAPI BFLA challenges as supplementary
  practice and explain what each covers
- Break into multiple separate files:
  1. Overview and concept (BOLA vs BFLA distinction explained clearly)
  2. Discovery methodology
  3. Common BFLA patterns and bypass techniques
  4. Autorize extension for BFLA testing (full setup and usage breakdown)
  5. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example must be broken down piece by piece — explain exactly
  what is being tested and why the authorization check fails in each case.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 7. BOPLA — Broken Object Property Level Authorization

```
I'm building a comprehensive, GitHub-ready note series on BOPLA (Broken Object Property
Level Authorization) — OWASP API Security Top 10 2023 #3, which merges Excessive Data
Exposure and Mass Assignment from the 2019 list. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Cover Excessive Data Exposure: APIs returning full database objects when only specific
  fields are needed, sensitive fields exposed in responses (password hashes, tokens,
  internal IDs, PII) even when the UI does not display them, response field comparison
  across different user roles
- Cover Mass Assignment: injecting extra JSON fields that the API binds to internal
  object properties (isAdmin, role, balance, verified) — explain why ORMs and
  frameworks bind all incoming fields by default if not explicitly whitelisted
- Cover testing methodology: comparing API response fields vs UI-displayed fields,
  systematically testing extra fields on every POST/PUT/PATCH endpoint, comparing
  responses across roles
- Cover Mass Assignment filter bypass: alternate field names, nested object injection,
  content-type switching to bypass field filtering
- Cover CSV/Formula Injection as a data-export-specific property exposure issue: when an API endpoint exports object data to CSV/Excel (common in admin dashboards and reporting features), unsanitized user-controlled fields (name, notes, comments) can contain spreadsheet formulas (starting with =, +, -, @) that execute when the exported file is opened — explain the mechanism, how to test for it safely, and reference real 2025 CVEs demonstrating escalation to RCE via this exact pattern
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Also reference
  crAPI BOPLA challenges as supplementary practice and explain what each covers
- Break into multiple separate files:
  1. Overview and concept (both sub-types explained clearly)
  2. Excessive Data Exposure testing methodology
  3. Mass Assignment testing methodology
  4. Mass Assignment filter bypass techniques
  5. CSV/Formula Injection via data export features
  6. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example must be broken down piece by piece — explain exactly
  which field is being added or exposed and why the API processes it unexpectedly.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 8. REST API-Specific Testing Methodology

```
I'm building a comprehensive, GitHub-ready note series on REST API Testing Methodology
— the core procedural framework for testing any REST API. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover systematic approach: reading API specs first, mapping all endpoints and HTTP
  methods, setting up Burp and Postman correctly for API testing, establishing normal
  behavior baseline before testing begins
- Cover HTTP method abuse: testing all methods (GET/POST/PUT/PATCH/DELETE/OPTIONS/
  HEAD) on every endpoint regardless of what the spec says, checking for unintended
  method allowances and what each unintended method exposes
- Cover API versioning attacks: older versions (/v1/ vs /v3/) remaining accessible
  with fewer security controls, version enumeration techniques
- Cover content-type manipulation: switching between application/json, application/xml,
  text/plain and observing behavioral changes, injection opportunities via content-type
  switching
- Cover response differential analysis: same endpoint tested with different roles,
  different content-types, different parameter values — systematic comparison to find
  information leakage or authorization differences
- Cover parameter fuzzing methodology specific to APIs: JSON body structure, nested
  object fuzzing, array injection, hidden parameter discovery
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Note which
  PortSwigger labs are most applicable to REST methodology; also reference crAPI as
  supplementary practice and explain what each challenge covers
- Break into multiple separate files:
  1. Overview and pre-testing setup methodology
  2. HTTP method testing
  3. Versioning attacks
  4. Content-type manipulation
  5. Response differential analysis
  6. Parameter fuzzing methodology for APIs
  7. Final methodology checklist and cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request example and Burp workflow must be broken down piece by piece
  — explain exactly what each header or parameter change tests and why.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 9. API Injection Testing

```
I'm building a comprehensive, GitHub-ready note series on Injection Testing via APIs
— covering how SQLi, NoSQL injection, Command injection, and other injection classes
apply through API endpoints. I already have separate web app note series covering each
injection class in depth; this series focuses on the API-specific delivery context,
methodology differences, and WAF bypass in the API context.

Requirements:
- Cover why API injection differs from web app injection: JSON body delivery, nested
  object parameters, array-based injection, different encoding requirements, WAF
  behavior differences for JSON vs form-encoded content
- Cover SQLi via API: injecting through JSON body string values, Burp-based testing
  workflow for API endpoints, sqlmap usage with JSON body (--data flag with JSON,
  --level and --risk for API contexts) — all flags broken down
- Cover NoSQL injection via API: MongoDB operator injection in JSON bodies ($ne, $gt,
  $regex, $where) — explain each operator and why it bypasses authentication or
  extracts data
- Cover Command injection via API: shell-out parameters in REST API request bodies,
  blind command injection detection via time delay and OOB
- Cover SSTI via API: template expression injection through API string parameters
- Cover XXE via API: switching Content-Type to XML on endpoints that accept it
- Cover a dedicated WAF bypass section for API injection: how WAFs inspect JSON
  bodies differently from form-encoded data, JSON-specific bypass techniques
  (Unicode escaping in JSON strings, nested JSON to bypass keyword detection,
  content-type switching to evade JSON-specific WAF rules)
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant injection labs
  in correct difficulty-progression sequence (Apprentice → Practitioner → Expert)
  that apply to the API injection context. Cross-reference existing injection note
  series for technique detail; focus lab mapping here on API delivery context
- Break into multiple separate files:
  1. Overview and API injection context (why it differs)
  2. SQLi via API (including sqlmap for JSON bodies — full flag breakdown)
  3. NoSQL injection via API
  4. Command injection via API
  5. SSTI and XXE via API (combined file, delivery context focus)
  6. WAF bypass for API injection (dedicated file)
  7. Final methodology cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every payload and every tool command must be broken down piece by piece
  — explain the JSON structure, what each injection operator does, and why it works
  in this delivery context. Never write a payload without full explanation.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 10. HTTP/2 Attack Techniques

```
I'm building a comprehensive, GitHub-ready note series on HTTP/2 Attack Techniques —
increasingly relevant since most modern APIs and API gateways run over HTTP/2. I
already have a web application security note series (including HTTP Request Smuggling
for HTTP/1.1) and want this built to the same depth, focused specifically on HTTP/2
protocol-level attacks.

Requirements:
- Cover HTTP/2 protocol fundamentals needed for testing: binary framing layer, stream
  multiplexing (multiple requests over one connection), header compression (HPACK),
  and how HTTP/2 traffic differs from HTTP/1.1 in Burp Suite — mechanism first
- Cover HTTP/2 Rapid Reset (CVE-2023-44487 pattern): rapidly opening and cancelling
  streams to exhaust server resources — explain exactly why stream cancellation
  timing creates the resource exhaustion condition, and how this differs from
  traditional rate-limiting-based DoS
- Cover HTTP/1.1 to HTTP/2 downgrade smuggling: request smuggling that occurs when a
  front-end speaks HTTP/2 to the client but downgrades to HTTP/1.1 to communicate
  with the backend — explain the desync mechanism, cross-reference the existing HTTP
  Request Smuggling notes for the general CL.TE/TE.CL concept and focus here on what
  is unique to the HTTP/2 downgrade context
- Cover HPACK header compression abuse: header injection via compression table
  manipulation, CRLF-equivalent attacks in a binary framing context
- Cover stream multiplexing abuse: request interleaving issues, resource exhaustion
  via excessive concurrent streams on a single connection
- Cover tooling: h2spec (HTTP/2 conformance testing — full flag breakdown), Burp
  Suite's HTTP/2 support and how to enable/inspect it, "h2csmuggler" for HTTP/2
  smuggling testing (full usage breakdown)
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability,
  include a dedicated section covering common detection methods and realistic bypass
  considerations. If WAF/Gateway bypass is not meaningfully relevant to a specific
  sub-technique, explicitly state why.
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert); PortSwigger's
  HTTP Request Smuggling lab section includes HTTP/2-specific labs, map those directly.
  Note that Rapid Reset-style DoS testing is not something to actively test against
  live/production targets without explicit written authorization for availability
  testing — flag this clearly as a real-world engagement consideration
- Break into multiple separate files:
  1. HTTP/2 protocol fundamentals for pentesters (mechanism first)
  2. Rapid Reset and stream-based resource exhaustion
  3. HTTP/1.1 to HTTP/2 downgrade smuggling
  4. HPACK compression abuse
  5. Tooling file (h2spec, h2csmuggler, Burp HTTP/2 configuration — full breakdowns)
  6. Final cheatsheet and lab mapping
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file, including an explicit caution about testing
  DoS-style techniques (Rapid Reset) only in authorized, scoped engagements with
  availability testing explicitly permitted
- CRITICAL: every technique and tool command must be broken down piece by piece —
  explain exactly what each part of the HTTP/2 frame or command does and why it
  produces the vulnerability. Never write an example as just "send this."
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 11. Unrestricted Resource Consumption

```
I'm building a comprehensive, GitHub-ready note series on Unrestricted Resource
Consumption — OWASP API Security Top 10 2023 #4. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Cover detection of missing or weak rate limiting: response-based detection (X-RateLimit-*
  headers, Retry-After headers), timing-based detection, behavior difference between
  rate-limited and unlimited endpoints
- Cover resource exhaustion via API: pagination limit abuse (requesting millions of
  records in one call), file upload size abuse, regex complexity attacks (ReDoS via
  API), expensive computation endpoint abuse
- Cover third-party spending limit abuse: APIs that trigger paid third-party calls
  (SMS, email, payment processing) with no rate limiting — each trigger costs real money
- Cover enumeration enabled by absent rate limiting: user enumeration, credential
  stuffing, BOLA enumeration — cross-reference Broken Authentication notes
- Cover testing with Burp Intruder and Turbo Intruder for resource exhaustion — all
  flags and configuration broken down
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Also reference
  crAPI rate limiting challenges as supplementary practice and explain what each covers
- Break into multiple separate files:
  1. Overview and concept
  2. Detection methodology
  3. Resource exhaustion techniques
  4. Third-party spending abuse
  5. Burp Intruder and Turbo Intruder for resource testing (full breakdown)
  6. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every request and script example must be broken down piece by piece —
  explain exactly what resource is being exhausted and why the API has no protection.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 12. API Rate Limit & Bot Protection Bypass

```
I'm building a comprehensive, GitHub-ready note series on API Rate Limit and Bot
Protection Bypass — focused on bypassing rate limits that DO exist, not just finding
absent ones (that is covered in topic 10). I already have a web application security
note series and want this built to the same depth.

Requirements:
- Cover header-based IP spoofing for rate limit bypass: X-Forwarded-For, X-Real-IP,
  X-Originating-IP, CF-Connecting-IP, True-Client-IP — explain which headers different
  platforms and frameworks trust, why they trust them, and how rotating these values
  bypasses per-IP rate limits
- Cover account-level rate limit bypass: distributing requests across multiple test
  accounts to stay under per-account limits
- Cover endpoint variation bypass: slight URL variations that reset rate limit counters
  (/api/v1/login vs /api/v1/Login vs /api/v1/login/ with trailing slash)
- Cover timing-based bypass: identifying the rate limit window duration and structuring
  requests to stay just under the threshold per window
- Cover WAF and bot protection evasion techniques: rotating User-Agent strings,
  randomizing request timing, header fingerprint variation
- Cover Turbo Intruder for rate limit bypass attacks — all script parameters and
  concurrency settings broken down fully
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Race condition
  and authentication brute force labs are directly applicable — map all of them in
  order. Also reference crAPI as supplementary practice
- Break into multiple separate files:
  1. Overview and how API rate limits work technically
  2. Header-based IP spoofing bypass techniques
  3. Timing, distribution, and endpoint variation bypass
  4. WAF and bot protection evasion
  5. Turbo Intruder for rate limit bypass (full script breakdown)
  6. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every header example and Turbo Intruder script must be broken down piece
  by piece — explain exactly why the server trusts the header and how each bypass
  exploits that trust.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 13. Race Conditions (API-Specific)

```
I'm building a comprehensive, GitHub-ready note series on Race Condition
vulnerabilities specifically in API contexts — I already have a Race Conditions note
series in my web application security notes covering the general TOCTOU concept and
Turbo Intruder basics; cross-reference that series for the core mechanism and do not
duplicate it. This series focuses on what is unique to exploiting race conditions
through APIs specifically.

Requirements:
- Cover why APIs are especially prone to race conditions: stateless request handling,
  microservice architectures with distributed state, and how JSON-based batch/array
  operations create new race windows not present in traditional web forms
- Cover multi-step API chain race conditions: exploiting a race window that spans
  multiple sequential API calls (e.g. a "check balance" call and a "withdraw" call
  that are separate API requests, rather than a single form submission)
- Cover GraphQL-specific race conditions: using batched mutations/aliases (cross-
  reference the GraphQL notes) to fire many state-changing operations in a single
  HTTP request, which sidesteps connection-level timing challenges entirely and is
  often more reliable than the single-packet technique for winning races
- Cover idempotency key abuse: testing whether idempotency keys (common in payment
  APIs) are actually enforced correctly, and whether concurrent requests with the
  same or different idempotency keys can be raced against each other
- Cover API-specific real-world scenarios: double-spending via concurrent payment API
  calls, coupon/discount code redemption races, concurrent account balance
  modification, limited-resource claim races (ticket/inventory APIs)
- Cover the single-packet attack technique (via Turbo Intruder) applied specifically
  to API endpoints, and when the GraphQL batching approach is preferable
- I practice on PortSwigger Web Security Academy — map ALL Race Condition labs in
  correct difficulty-progression sequence (Apprentice → Practitioner → Expert).
  PortSwigger has a dedicated Race Condition lab set — map every lab in the correct
  order, noting which ones translate directly to API testing scenarios. Also
  reference crAPI race condition challenges as supplementary practice
- Break into multiple separate files:
  1. Overview — why APIs are especially prone to race conditions (mechanism first,
     cross-reference web app Race Conditions notes for TOCTOU basics)
  2. Multi-step API chain race conditions
  3. GraphQL batching-based race exploitation
  4. Idempotency key abuse
  5. Real-world scenario walkthroughs (payment, coupon, inventory races)
  6. Turbo Intruder for API race conditions (full script breakdown, API-specific
     configuration)
  7. Final cheatsheet and lab mapping
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- Where WAF or API Gateway-level defenses are relevant (some gateways add
  micro-delays or queue requests in ways that affect race timing), include a section
  on how to detect and account for this. If not relevant to a specific sub-technique,
  state why explicitly.
- CRITICAL: every technique and Turbo Intruder script must be broken down piece by
  piece — explain exactly what creates the race window, what the timing requirements
  are, and why the API context makes this specific technique work.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 14. GraphQL-Specific Attacks

```
I'm building a comprehensive, GitHub-ready note series on GraphQL Security Testing —
a completely separate attack surface from REST APIs requiring its own methodology.
I already have a web application security note series and want this built to the same
depth.

Requirements:
- Cover GraphQL fundamentals needed for testing before any attacks: queries, mutations,
  subscriptions, introspection, types, resolvers, schema structure, variables —
  mechanism first, just enough to test effectively
- Cover introspection abuse: using __schema and __type queries to extract the full API
  schema, and how to use that schema to discover privileged mutations not exposed in
  the UI
- Cover introspection disable bypass: field suggestion leakage when introspection is
  disabled (GraphQL error messages suggest valid field names close to what you typed)
- Cover query batching and alias attacks: sending multiple operations in one request
  to bypass per-request rate limits — walk through an OTP brute force example step
  by step
- Cover query depth and complexity attacks: deeply nested queries causing server
  resource exhaustion
- Cover BOLA and BFLA in GraphQL context: testing authorization on resolvers, not
  just the endpoint
- Cover GraphQL injection: injecting through GraphQL variables and inline arguments
- Cover dedicated tooling: InQL Burp extension (full setup and usage breakdown),
  graphql-cop (GraphQL security scanner — full flag breakdown)
- Cover WAF bypass for GraphQL: how WAFs detect GraphQL attacks and evasion techniques
  (query obfuscation, fragment abuse, alias obfuscation)
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map ALL GraphQL labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). PortSwigger
  has a dedicated GraphQL lab set — map every single lab in the correct order
- Break into multiple separate files:
  1. GraphQL fundamentals for pentesters (mechanism first)
  2. Introspection and schema extraction
  3. Batching and alias attacks (rate limit bypass and brute force)
  4. Depth, complexity, and DoS attacks
  5. Authorization testing in GraphQL (BOLA/BFLA on resolvers)
  6. Injection testing in GraphQL
  7. WAF bypass for GraphQL
  8. Tooling file (InQL + graphql-cop — full breakdowns)
  9. Final cheatsheet and lab mapping
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every GraphQL query, mutation, and tool command must be broken down piece
  by piece — explain the syntax, what each field does, and exactly what the attack
  achieves.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 15. Unrestricted Access to Sensitive Business Flows

```
I'm building a comprehensive, GitHub-ready note series on Unrestricted Access to
Sensitive Business Flows — OWASP API Security Top 10 2023 #6. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover the core concept: business workflows that can be automated or abused at scale
  via the API even when individual requests are authorized — the API does nothing wrong
  per-request but allows harmful patterns at scale
- Cover real-world scenarios, each broken down step by step: ticket and inventory
  scalping (buying all limited stock via automated calls), referral reward farming
  (automated account creation for referral bonuses), gift card and coupon stacking
  abuse, account enumeration at scale, payment flow bypass via workflow step skipping,
  voting or rating manipulation
- Cover detection: identifying business-critical API flows that lack automation
  controls (no CAPTCHA, no behavioral rate limiting, no step sequence validation)
- Cover workflow step skipping: sending step 3 of a checkout flow without completing
  steps 1 and 2, parameter manipulation to skip payment verification steps
- Cover Turbo Intruder for business flow automation testing — all script configuration
  broken down
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant business logic
  labs in correct difficulty-progression sequence (Apprentice → Practitioner → Expert).
  PortSwigger's business logic lab section is directly applicable — map all of them in
  order. Also reference crAPI business flow challenges as supplementary practice
- Break into multiple separate files:
  1. Overview and concept
  2. Real-world scenario examples (each broken down step by step)
  3. Detection and testing methodology
  4. Workflow step skipping techniques
  5. Turbo Intruder for business flow testing (full breakdown)
  6. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every workflow example must be broken down step by step — explain exactly
  which business rule is being violated and why the API allows it.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 16. SSRF (API-specific)

```
I'm building a comprehensive, GitHub-ready note series on SSRF in API contexts. I
already have a separate SSRF note series in my web application security notes covering
the general technique and bypass methods — cross-reference that series for bypass
techniques and do not duplicate them here. This series focuses on what is unique to
the API context: API delivery mechanisms, API-specific SSRF patterns, and how SSRF
chains with other API vulnerabilities.

Requirements:
- Cover SSRF via API URL parameters: parameters in REST API request bodies that accept
  URLs — webhook URLs, avatar URLs, document fetch URLs, callback URLs, import URLs —
  and how to identify them during recon
- Cover SSRF via API integrations: third-party service calls that APIs trigger based
  on user-supplied URLs
- Cover cloud metadata endpoint exploitation via API-originated SSRF: AWS (169.254.169.254
  and newer IMDSv2 endpoints), GCP, Azure metadata services — explain the specific
  paths and what credentials they return
- Cover blind SSRF in API contexts: using Burp Collaborator to detect API-triggered
  out-of-band DNS and HTTP requests, what to do after confirming blind SSRF
- Cover SSRF to internal service pivot: using API-originated SSRF to reach internal
  APIs, databases, or admin interfaces not accessible externally
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map ALL SSRF labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Map every
  lab in order. Note which labs are most relevant to the API delivery context
- Break into multiple separate files:
  1. Overview and API SSRF context (what differs from web app SSRF)
  2. SSRF via webhook and callback URL parameters
  3. Cloud metadata exploitation via API SSRF
  4. Blind SSRF in API context (Burp Collaborator workflow breakdown)
  5. SSRF to internal service pivot
  6. Final cheatsheet and lab mapping
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every payload and Burp Collaborator workflow must be broken down piece
  by piece — explain exactly what each URL component does and what the server-side
  request retrieves.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 17. Webhook Security

```
I'm building a comprehensive, GitHub-ready note series on Webhook Security — an
increasingly common and frequently missed API attack surface. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover the webhook model clearly first: what webhooks are, how they work (event
  triggers a server-to-server HTTP call), why they are used, what the typical
  registration and delivery flow looks like as raw HTTP — mechanism first
- Cover SSRF via webhook URL registration: registering a webhook with an internal IP,
  localhost, or cloud metadata URL so the server makes requests to internal resources
  when the webhook fires — walk through the full attack step by step
- Cover webhook signature validation bypass: what HMAC-based webhook signatures
  protect against, testing for missing signature validation, timing attack on
  signature comparison (constant-time vs non-constant-time comparison), weak secret
  brute-forcing
- Cover replay attacks: capturing a legitimate webhook request and replaying it to
  trigger the action multiple times — what protects against this (timestamps,
  nonces) and how to test if protection is absent
- Cover payload parameter tampering: modifying the webhook event payload body to
  alter the triggered action (changing event type, modifying amount fields, escalating
  privileges via payload manipulation)
- Cover webhook endpoint enumeration: discovering webhook receiver endpoints that
  lack authentication
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Note that
  dedicated webhook labs are limited on PortSwigger; reference real HackerOne disclosed
  webhook vulnerability reports as practical examples instead and explain what each
  demonstrates
- Break into multiple separate files:
  1. Overview and webhook model (mechanism first)
  2. SSRF via webhook registration
  3. Signature bypass and replay attacks
  4. Payload tampering and endpoint enumeration
  5. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every exploit technique must be broken down step by step — explain what
  the webhook mechanism does at each stage and why each attack works.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 18. API Key Security

```
I'm building a comprehensive, GitHub-ready note series on API Key Security testing.
I already have a web application security note series and want this built to the same
depth.

Requirements:
- Cover API key leakage discovery: keys exposed in JavaScript bundles (how to search
  minified JS), git repositories (GitHub search dorking, leaked commit history), API
  responses and error messages, browser devtools Network tab, Postman collections
  shared publicly
- Cover API key entropy and predictability testing: identifying low-entropy keys,
  sequential keys, timestamp-based keys, how to test predictability
- Cover API key scope and permission testing: testing what a discovered key can
  actually access, whether it has broader permissions than its documented purpose,
  privilege escalation via key substitution
- Cover API key rotation gap testing: testing whether old or supposedly revoked keys
  still function
- Cover dedicated tooling: truffleHog (git and filesystem secret scanning — full
  flag-by-flag breakdown), gitleaks (full flag-by-flag breakdown), nuclei templates
  for API key detection
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Note that
  dedicated API key labs are limited on PortSwigger; reference HackTheBox API
  challenges and real HackerOne disclosed key leakage reports as supplementary
  practice and explain what each demonstrates
- Break into multiple separate files:
  1. Overview and API key types
  2. Leakage discovery methodology
  3. Entropy, scope, and permission testing
  4. Tooling file (truffleHog + gitleaks + nuclei — full flag breakdowns)
  5. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every tool command must be broken down flag by flag — explain what each
  flag does and why it is used. Never write a command as just "run this."
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 19. Security Misconfiguration (API-specific)

```
I'm building a comprehensive, GitHub-ready note series on API Security Misconfiguration
— OWASP API Security Top 10 2023 #8. I already have a Security Misconfiguration note
series in my web application security notes; this series focuses on API-specific
misconfiguration patterns only. Cross-reference the web app series for general
misconfiguration testing.

Requirements:
- Cover exposed API documentation: Swagger UI accessible in production (common paths
  to check), OpenAPI specs exposing internal endpoint details, GraphQL introspection
  enabled in production — explain what each exposes and how to exploit it
- Cover missing or misconfigured CORS on API endpoints: reflected origin
  misconfiguration, null origin bypass, wildcard with credentials — API-specific CORS
  testing nuances (cross-reference CORS notes from web app series for mechanism;
  focus here on API delivery and the specific CORS patterns most common in APIs)
- Cover verbose error messages: stack traces in API error responses, internal paths,
  DB query fragments, library versions exposed in 500 errors — how to trigger and
  extract
- Cover unnecessary HTTP methods left enabled on API endpoints
- Cover default and test credentials on API management consoles: Swagger UI default
  auth, API gateways (Kong, Apigee, AWS API Gateway) with default admin credentials
- Cover missing security headers on API responses: which headers matter for APIs
  specifically and what each missing header enables
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Note which
  PortSwigger labs cover API misconfiguration patterns specifically
- Break into multiple separate files:
  1. Overview and API-specific misconfiguration categories
  2. Exposed documentation exploitation
  3. CORS and header misconfiguration
  4. Error message and information leakage
  5. Default credentials and unnecessary methods
  6. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every example must be broken down piece by piece — explain exactly what
  is misconfigured and what information or access it gives an attacker.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 20. API Gateway Security

```
I'm building a comprehensive, GitHub-ready note series on API Gateway Security
testing — covering the security of the gateway layer itself (Kong, AWS API Gateway,
Apigee, Azure API Management, Nginx-based gateways), which sits in front of almost
every modern production API and is frequently misconfigured. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover the API gateway's role clearly first: authentication offloading, rate
  limiting enforcement, request routing, response caching, and why a misconfigured
  gateway can create a false sense of security even when the backend API is
  reasonably well protected — mechanism first
- Cover gateway authentication bypass: testing whether backend services are directly
  reachable if the gateway is bypassed (common in misconfigured cloud deployments
  where the backend has a public IP or an internal-only assumption that turns out to
  be wrong), path-based routing confusion between gateway and backend
- Cover gateway-level rate limiting bypass: testing whether rate limits are enforced
  per-route consistently, exploiting route normalization differences between the
  gateway and backend (trailing slashes, case sensitivity, URL encoding differences
  that the gateway and backend interpret differently)
- Cover API Gateway Cache Poisoning: gateways that cache responses based on a subset
  of the request (similar to web cache poisoning but at the gateway layer) —
  identifying unkeyed inputs that the gateway ignores for caching purposes but the
  backend uses to generate different content, and using this to serve poisoned
  responses to other API consumers; cross-reference the Web Cache Poisoning notes
  for the general "unkeyed input" concept and focus here on gateway-specific behavior
- Cover default credentials and exposed admin interfaces on common gateway products
  (Kong Admin API default exposure, AWS API Gateway misconfigured resource policies,
  Apigee management UI)
- Cover gateway-to-backend trust exploitation: headers the gateway adds that the
  backend blindly trusts (X-Gateway-Authenticated, X-User-Id set by the gateway after
  auth) — testing whether these can be spoofed if the backend is reachable directly
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert); the Web Cache
  Poisoning lab section is directly relevant to the gateway cache poisoning sub-topic,
  map those labs and explain how they translate to a gateway context. Note that
  dedicated API gateway product labs are limited on PortSwigger; reference vendor
  documentation-based lab setups (running Kong or AWS API Gateway locally with
  intentionally weak configuration) as supplementary practice
- Break into multiple separate files:
  1. Overview — API gateway role and why misconfiguration matters (mechanism first)
  2. Gateway authentication bypass and backend direct-access testing
  3. Gateway-level rate limit bypass
  4. API Gateway Cache Poisoning (cross-reference Web Cache Poisoning notes)
  5. Default credentials and exposed admin interfaces (product-specific: Kong,
     AWS API Gateway, Apigee)
  6. Gateway-to-backend header trust exploitation
  7. Final cheatsheet and lab mapping
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every technique must be broken down step by step — explain exactly what
  trust assumption between the gateway and backend is being exploited and why it
  exists in typical gateway deployments.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 21. Improper Inventory Management

```
I'm building a comprehensive, GitHub-ready note series on Improper Inventory Management
— OWASP API Security Top 10 2023 #9. I already have a web application security note
series and want this built to the same depth.

Requirements:
- Cover the core concept: APIs grow and change over time, old versions get forgotten,
  shadow APIs get created without security review, and these unmonitored endpoints
  have weaker or absent security controls
- Cover API version exploitation: discovering and testing deprecated API versions
  (/v1/ still live when /v4/ is current) that lack security controls applied to
  current versions — walk through a concrete example of finding and exploiting a
  deprecated endpoint with missing authentication
- Cover shadow endpoint discovery: finding endpoints that exist but are not in any
  documentation — via JS file mining, response inference, brute-forcing, error
  message analysis
- Cover zombie endpoint identification: test and debug endpoints left in production,
  internal endpoints accidentally exposed externally
- Cover API documentation vs reality mismatches: systematically testing what an
  endpoint actually does versus what documentation says it does
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map all relevant labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Also reference
  crAPI inventory management challenges as supplementary practice and explain what each
  covers
- Break into multiple separate files:
  1. Overview and concept
  2. API version exploitation (step-by-step methodology)
  3. Shadow and zombie endpoint discovery
  4. Documentation gap testing
  5. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every discovery technique must be broken down step by step — explain what
  signal reveals the endpoint exists and why deprecated versions have fewer controls.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 22. WebSocket API Security

```
I'm building a comprehensive, GitHub-ready note series on WebSocket API Security
testing. I already have a Cross-Site WebSocket Hijacking (CSWSH) note in my web
application security series — cross-reference it for the hijacking technique and do
not duplicate it fully here. This series covers the complete WebSocket API testing
methodology.

Requirements:
- Cover WebSocket protocol basics needed for testing: the HTTP upgrade handshake (what
  each header does), frame structure, ws:// vs wss://, full-duplex model, how
  WebSocket traffic appears in Burp Suite's WebSocket history tab — mechanism first
- Cover WebSocket message manipulation in Burp: intercepting and modifying messages,
  replaying messages, fuzzing message content for injection vulnerabilities
- Cover injection attacks via WebSocket messages: SQLi, XSS, Command injection, SSTI
  delivered through WebSocket JSON payloads — explain why delivery via WebSocket does
  not protect against these vulnerabilities
- Cover authentication testing: tokens sent in handshake headers vs first message
  after connection, testing behavior when token is missing, expired, or belongs to
  another user
- Cover authorization testing: sending messages that perform actions belonging to
  other users (BOLA via WebSocket), privilege escalation via WebSocket message
  manipulation (BFLA via WebSocket)
- Cover origin validation bypass (CSWSH): provide a summary here and clearly reference
  the CSWSH note in the web app security series for the full technique
- Cover Server-Sent Events (SSE) as a related real-time API pattern: how SSE differs from WebSocket (one-way server-to-client stream over plain HTTP rather than a bidirectional protocol upgrade), authentication testing for SSE endpoints, and information disclosure risks specific to SSE (long-lived connections exposing data across session boundaries if not properly scoped per connection)
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map ALL WebSocket labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). PortSwigger
  has dedicated WebSocket labs — map every single lab in the correct order
- Break into multiple separate files:
  1. WebSocket protocol fundamentals for pentesters (mechanism first)
  2. Message manipulation and injection testing
  3. Authentication and authorization testing
  4. Origin bypass summary (cross-reference CSWSH notes)
  5. Server-Sent Events (SSE) security testing
  6. Final cheatsheet and lab mapping
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every Burp-based workflow and payload must be broken down piece by piece
  — explain what each part of the WebSocket message does and why the vulnerability
  exists in this delivery context.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 23. Unsafe Consumption of APIs

```
I'm building a comprehensive, GitHub-ready note series on Unsafe Consumption of APIs
— OWASP API Security Top 10 2023 #10. I already have a web application security note
series and want this built to the same depth.

Requirements:
- Cover the core concept clearly: applications that consume third-party APIs often
  trust responses without validation — if the third-party is compromised or returns
  unexpected data, the consuming application processes it unsafely
- Cover injection via third-party API responses: if a third-party API returns data that
  gets used in a database query, template, or shell command without sanitization —
  explain exactly how an attacker who controls the third-party can inject into the
  consuming application
- Cover SSRF via third-party API integrations: URLs returned by third-party API
  responses that get fetched server-side without validation
- Cover data integrity issues: consuming applications that do not validate schema or
  type of third-party responses, leading to unexpected behavior (type confusion, null
  dereference, logic bypass)
- Cover testing methodology from both black-box and grey-box perspectives — explain
  honestly that this is harder to find in pure black-box testing and more commonly
  found in grey-box or white-box assessments with source code access
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Note explicitly
  that this category has limited direct PortSwigger lab coverage; reference grey-box
  CTF challenges and HackTheBox scenarios as supplementary practice and explain what
  each demonstrates
- Break into multiple separate files:
  1. Overview and concept
  2. Injection via third-party response
  3. SSRF via third-party response
  4. Testing methodology (black-box vs grey-box)
  5. Final checklist
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every scenario example must be broken down step by step — explain exactly
  what the third-party returns, how the consuming application processes it, and why
  that processing is unsafe.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 24. SOAP/XML API Attacks

```
I'm building a comprehensive, GitHub-ready note series on SOAP/XML API Security
Testing — relevant for legacy and enterprise API engagements. I already have a web
application security note series and want this built to the same depth.

Requirements:
- Cover SOAP and WSDL basics needed for testing: SOAP envelope structure (Envelope,
  Header, Body — what each section is for), WSDL file structure and how to read it,
  SOAPAction header, common SOAP endpoints — mechanism first, just enough to test
  effectively
- Cover XXE via SOAP: XML external entity injection through SOAP request bodies —
  cross-reference XXE web app notes for full technique; focus here on SOAP-specific
  delivery, how to identify injectable parameters, and how to structure the XXE
  payload within SOAP envelope syntax
- Cover SOAP injection: injecting SOAP XML tags and elements into parameters to alter
  the SOAP message structure — walk through a concrete example
- Cover WS-Security: what WS-Security headers provide (authentication, signing,
  encryption), testing for missing WS-Security, replay attacks on timestamped SOAP
  messages
- Cover WSDL enumeration: extracting all available methods and parameters from exposed
  WSDL files, converting WSDL to testable format
- Cover SQLi and Command injection via SOAP parameters
- Cover dedicated tooling: SoapUI for SOAP-specific testing (full usage breakdown),
  wsdl2postman for converting WSDL to Postman collections (full breakdown)
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Note that
  dedicated SOAP labs are limited on PortSwigger; reference SoapUI's built-in practice
  services and TryHackMe SOAP-related rooms as supplementary practice and explain what
  each covers
- Break into multiple separate files:
  1. SOAP and WSDL fundamentals for pentesters (mechanism first)
  2. XXE via SOAP
  3. SOAP injection and WS-Security attacks
  4. WSDL enumeration and injection testing methodology
  5. Tooling file (SoapUI + wsdl2postman — full breakdowns)
  6. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every XML payload and tool command must be broken down piece by piece —
  explain the SOAP envelope structure and exactly what each injection achieves.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 25. gRPC & Protocol-Level Attacks

```
I'm building a comprehensive, GitHub-ready note series on gRPC Security Testing —
increasingly relevant in microservices environments. I already have a web application
security note series and want this built to the same depth.

Requirements:
- Cover gRPC protocol basics needed for testing: Protocol Buffers (protobuf) — what
  they are and how they serialize data, service definition files (.proto) — how to
  read them, gRPC vs REST differences, how gRPC traffic appears in Burp Suite (binary,
  requires plugin), HTTP/2 transport — mechanism first, just enough to test effectively
- Cover gRPC service reflection: what reflection exposes (all available RPC methods and
  their input/output types), how to use it to enumerate attack surface when .proto files
  are not available
- Cover protobuf message manipulation: intercepting and decoding protobuf messages in
  Burp Suite, modifying field values, injecting test values — walk through with the
  Burp gRPC plugin
- Cover authorization testing on gRPC: testing if each RPC method enforces
  authentication and authorization (BOLA and BFLA patterns applied to gRPC methods)
- Cover injection via gRPC fields: delivering SQLi, Command injection, and SSTI through
  gRPC string fields after decoding
- Cover dedicated tooling: grpcurl (full flag-by-flag breakdown for all common
  operations — listing services, describing methods, calling methods), Burp gRPC
  plugin setup and usage
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Note that
  gRPC has minimal PortSwigger coverage; reference HackTheBox gRPC challenges and
  TryHackMe gRPC rooms as supplementary practice and explain what each covers
- Break into multiple separate files:
  1. gRPC fundamentals for pentesters (mechanism first)
  2. Service enumeration via reflection
  3. Protobuf manipulation in Burp
  4. Authorization testing (BOLA and BFLA on gRPC methods)
  5. Injection testing via gRPC fields
  6. Tooling file (grpcurl + Burp gRPC plugin — full breakdowns)
  7. Final cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every grpcurl command and Burp workflow must be broken down piece by piece
  — explain every flag and exactly what each step achieves.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 26. Microservices & Service-to-Service Security

```
I'm building a comprehensive, GitHub-ready note series on Microservices Security
Testing — focused on service-to-service communication security within a microservices
architecture. I already have a web application security note series and want this
built to the same depth.

Requirements:
- Cover the microservices attack surface: why microservices have a larger internal API
  surface, how internal service communication differs from external-facing APIs, what
  trust assumptions microservices commonly make about each other, and why these
  assumptions are dangerous
- Cover service identity and authentication: mutual TLS (mTLS) — what it is, how it
  works, how to test for weak or missing mTLS between services, JWT-based service
  tokens and their specific weaknesses in service-to-service context
- Cover service impersonation: testing whether internal service endpoints enforce
  authorization or assume "only internal services can reach this" — walk through
  a concrete SSRF-to-internal-service-impersonation example step by step
- Cover lateral movement via internal APIs: using access to one internal service
  (gained via SSRF or a compromised external endpoint) to enumerate and access other
  internal services
- Cover API gateway bypass: whether internal API endpoints are accessible when the
  API gateway is bypassed — common in misconfigured Kubernetes, ECS, or Docker
  deployments — explain how to identify and test this
- Where WAF or API Gateway-level defenses are relevant to this specific vulnerability, include a dedicated section covering common detection methods (how WAFs/gateways typically identify this attack pattern) and realistic bypass considerations. If WAF/Gateway bypass is not meaningfully relevant to this particular topic, explicitly state why in the overview file rather than omitting the consideration silently.
- I practice on PortSwigger Web Security Academy — map any applicable labs in correct
  difficulty-progression sequence (Apprentice → Practitioner → Expert). Note that
  microservices security has minimal PortSwigger coverage and is primarily relevant for
  internal and whitebox pentest engagements; reference HackTheBox Pro Labs and
  internal-network-focused TryHackMe rooms as supplementary practice and explain what
  each covers
- Break into multiple separate files:
  1. Microservices architecture and attack surface for pentesters
  2. mTLS and service authentication testing
  3. Service impersonation and lateral movement
  4. API gateway bypass
  5. Final checklist
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every technique must be broken down step by step — explain exactly what
  trust assumption is being exploited and why it exists in microservices architectures.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

---

## [ ] 27. API Automation & Tooling

```
I'm building a comprehensive, GitHub-ready note series on API Security Testing
Automation and Tooling — a reference for all tools used across the other 23 API
security topics in this directory. I already have a web application security note
series and want this built to the same depth.

Requirements:
- Cover each tool with a DEDICATED section — same depth as the sqlmap file in my SQLi
  notes, meaning full flag-by-flag breakdown of every commonly used command:
  - Postman and Newman: collection setup, environment variables, automated collection
    runs, pre-request scripts, test scripts for chaining — every feature broken down
  - Burp Suite for API testing: configuring for JSON and GraphQL, key extensions for
    API testing (Autorize setup and usage, InQL for GraphQL, JWT Editor, HTTP Request
    Smuggler, Param Miner) — each extension broken down
  - ffuf for API endpoint and parameter fuzzing: API-specific flags, JSON body fuzzing
    mode, wordlist selection — every flag broken down
  - kiterunner: API endpoint brute-forcing using real-world API route wordlists —
    every flag broken down
  - Arjun: HTTP parameter discovery — every flag broken down
  - jwt_tool: all attack modes — every flag broken down (cross-reference JWT notes)
  - nuclei with API-specific templates: running API security templates, writing a
    basic custom template — every option broken down
  - truffleHog and gitleaks: API key and secret discovery in git repos — every flag
    broken down
  - graphql-cop: GraphQL security scanner — every flag broken down
  - grpcurl: gRPC interaction — every flag broken down (cross-reference gRPC notes)
  - httpx: fast HTTP probing and endpoint validation — checking which discovered endpoints are live, extracting status codes/titles/tech stack at scale — every flag broken down
  - katana: web and API endpoint crawling for discovery — how it differs from ffuf's brute-force approach (crawling vs guessing) — every flag broken down
  - jq: command-line JSON parsing, filtering, and querying — essential for processing API responses in scripts and pipelines (piping curl/httpx output through jq for field extraction) — every flag and filter syntax broken down
  - RESTler (Microsoft Research's REST API fuzzer): automated stateful fuzzing that learns API dependencies from the OpenAPI spec — brief coverage as an additional automated option beyond manual/semi-automated tools
- Cover API-specific wordlists: SecLists API-specific lists, Assetnote API wordlists,
  what each contains and when to use which one
- Cover crAPI setup: how to run it locally with Docker, what vulnerabilities it
  contains mapped to which API security topics they practice
- WAF/Gateway bypass discussion is not applicable to this topic since it is a pure tooling reference rather than a vulnerability class — note this explicitly in the overview file rather than omitting the consideration silently
- Note explicitly: this topic has no PortSwigger lab mapping needed since it is a
  pure tooling reference. crAPI is the primary practice environment for most tools
  covered here
- Break into multiple separate files:
  1. Overview and tool selection guide (when to use which tool)
  2. Burp Suite for APIs (extensions and configuration)
  3. Fuzzing tools (ffuf, kiterunner, Arjun)
  4. Authentication tools (jwt_tool, truffleHog, gitleaks)
  5. Scanning tools (nuclei API templates, graphql-cop, RESTler)
  6. Protocol tools (grpcurl, Postman/Newman)
  7. Endpoint probing and JSON processing (httpx, katana, jq — full breakdown)
  8. Wordlist reference and crAPI setup
  9. Final quick-reference cheatsheet
- Include a README.md indexing all files
- Write everything in full English only
- Include real-world notes in each file
- CRITICAL: every single command shown must be broken down flag by flag. This is the
  entire purpose of this note series — no command should appear without full explanation
  of every flag, argument, and option used.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

---

## [ ] 28. CAPSTONE — Real-World API Exploitation & Chaining

```
I'm building a final, capstone note series called "API Security — Real-World
Exploitation and Vulnerability Chaining" — meant to be built AFTER completing all
27 individual API security note series topics (including HTTP/2 Attack Techniques,
Race Conditions, and API Gateway Security). This is not about any single
vulnerability type. It covers combining individual API vulnerabilities into
high-impact chains, real-world API attack methodology, multi-role testing workflow,
Postman-based chain documentation, and API-specific report writing.

I already have a web application security capstone (Real_World_Chaining_Notes/)
covering general chaining methodology and report writing structure. Cross-reference
it for overlapping concepts — do not duplicate. Focus entirely on what is unique
to API security.

Requirements:

PART 1 — API-SPECIFIC CHAIN PATTERNS:
Cover each of the following real-world API exploit chains, broken down step by step
(what bug A produces, how bug B consumes it, why the combination is critical, what
the final impact is):
  - BOLA + BFLA → full account takeover
  - JWT algorithm confusion → claim manipulation → BFLA → remote code execution
  - OAuth redirect_uri bypass → authorization code theft → account takeover
  - GraphQL introspection → hidden admin mutations → BFLA → privilege escalation
  - Webhook registration → SSRF → cloud metadata endpoint → AWS credential theft
    → cloud environment lateral movement
  - Improper inventory management (deprecated API version) + missing authentication
    → authentication bypass → BOLA → mass data exfiltration
  - API key leakage in git repository → BOLA enumeration → full database scrape
  - BOPLA mass assignment + BFLA → admin role privilege escalation
  - Rate limit bypass via header spoofing + Broken Authentication → admin brute
    force → full compromise
  - GraphQL batching alias attack → OTP brute force → MFA bypass → account takeover

PART 2 — MULTI-ROLE API TESTING METHODOLOGY:
Cover systematic multi-role testing workflow:
  - Setting up multiple role sessions in Burp Suite (session tokens, macros)
  - Setting up multi-role environments in Postman (environment variables per role)
  - The systematic cross-role test loop: test every endpoint as role A, repeat as
    role B, diff responses — this is the core BOLA and BFLA discovery process
  - How to identify and test role-specific endpoints efficiently

PART 3 — CHAIN BUILDING METHODOLOGY:
Cover the thinking process for building chains from individual findings:
  - Mapping the full API attack surface before attempting to chain
  - Tracking low-severity individual findings and why they matter for chaining
  - Finding where one vulnerability's output becomes another vulnerability's input
  - API-specific chain opportunities not present in web apps: versioning mismatches,
    shadow endpoints, service-to-service trust

PART 4 — POSTMAN COLLECTION-BASED CHAIN DOCUMENTATION:
Cover using Postman to document and reproduce multi-step exploit chains:
  - Structuring a collection as a step-by-step exploit chain with named steps
  - Using test scripts to extract tokens and IDs from responses and pass them to
    subsequent requests automatically — walk through a concrete chaining example with
    actual script code, broken down line by line
  - Exporting a collection as PoC evidence for client reports
  - The difference between a testing collection and a PoC documentation collection

PART 5 — API-SPECIFIC REPORT WRITING:
Cover how API pentest reporting differs from web app reporting:
  - Documenting BOLA and BFLA findings to demonstrate actual impact (not just
    "authorization check missing")
  - CVSS v3.1 scoring for API-specific findings with worked examples
  - Documenting multi-step chains: step-by-step reproduction with inputs, outputs,
    and cumulative impact statement
  - Evidence requirements: raw HTTP requests in Burp, Postman collection export,
    response diffs showing cross-role access
  - Executive summary writing for API pentest findings for non-technical stakeholders

PART 6 — REAL-WORLD ADAPTATION:
Cover how real API targets differ from lab environments:
  - WAF and API gateway behavior on real targets vs clean lab environments
  - Handling short-lived tokens mid-chain (token refresh automation in Postman)
  - Rate limiting during multi-step chains
  - Identifying when a chain should work but does not due to environmental factors

File breakdown — break into these separate files:
  1. Overview and chaining mindset (how API chains differ from web app chains)
  2. API exploit chain patterns (all 10 from Part 1, each fully documented)
  3. Multi-role testing methodology
  4. Chain building methodology
  5. Postman chain documentation (with full script code, broken down line by line)
  6. API-specific report writing
  7. Real-world adaptation
  8. README.md indexing all files

Additional requirements:
- I practice on PortSwigger Web Security Academy — where individual chain steps map
  to PortSwigger labs, reference those labs by name in the chain documentation so I
  know which lab to practice that specific technique on. Note where alternative
  practice (crAPI, HackTheBox) applies instead
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every chain example must be broken down step by step — explain exactly
  what each step does, what it produces, and how it feeds into the next step. Every
  Postman script must be broken down line by line. Never describe a chain as just
  "A leads to B" without explaining the connecting mechanism.
- When all files are complete, provide them as a single ZIP file for direct download.

Please plan the file breakdown first, then build each file.
```

## Build Order & Priority Reference

| # | Topic | Priority | Notes |
|---|---|---|---|
| 1 | API Recon & Endpoint Discovery | 🔴 | Do this first — everything else depends on finding endpoints |
| 2 | BOLA | 🔴 | Most common finding globally |
| 3 | Broken Authentication | 🔴 | Foundation for auth-related chains |
| 4 | JWT Attacks | 🔴 | PortSwigger has full lab set — do all labs |
| 5 | OAuth 2.0 | 🔴 | PortSwigger has full lab set — do all labs |
| 6 | BFLA | 🔴 | Pairs directly with BOLA for chaining |
| 7 | BOPLA | 🔴 | Very common on API-backed apps; now includes CSV injection |
| 8 | REST Methodology | 🔴 | Core methodology — reference throughout |
| 9 | API Injection | 🔴 | High impact, WAF bypass section included |
| 10 | HTTP/2 Attack Techniques | 🔴 | Increasingly relevant — most API gateways run HTTP/2 by default |
| 11 | Unrestricted Resource Consumption | 🟡 | crAPI has good coverage |
| 12 | Rate Limit Bypass | 🟡 | Pairs with auth attacks |
| 13 | Race Conditions (API-specific) | 🔴 | High payout, trending heavily in bug bounty |
| 14 | GraphQL | 🔴 | PortSwigger has full lab set — do all labs |
| 15 | Business Flow Abuse | 🟡 | PortSwigger business logic labs apply |
| 16 | SSRF API-specific | 🔴 | PortSwigger has full lab set |
| 17 | Webhook Security | 🟡 | HackerOne reports as practice |
| 18 | API Key Security | 🟡 | Git leakage very common in real targets |
| 19 | Security Misconfiguration | 🟡 | Quick wins during recon phase |
| 20 | API Gateway Security | 🔴 | Sits in front of nearly every production API — high real-world relevance |
| 21 | Improper Inventory | 🟡 | Pairs with recon methodology |
| 22 | WebSocket (+ SSE) | 🟡 | PortSwigger has labs |
| 23 | Unsafe API Consumption | ⚪ | Grey-box/whitebox focused |
| 24 | SOAP/XML | ⚪ | Enterprise/legacy engagements only |
| 25 | gRPC | ⚪ | Microservices engagements |
| 26 | Microservices | ⚪ | Internal/whitebox engagements |
| 27 | Tooling (+ httpx, katana, jq) | 🔴 | Read in parallel with all other topics |
| 28 | Capstone | 🔴 | Build LAST — after all 27 topics complete |

## Important Separate Note — OWASP Top 10 (Web App) Updated to 2025

Unrelated to this API prompt set, but worth knowing: OWASP released a major update to
the general **web application** OWASP Top 10 in November 2025 (finalized January 2026)
— this is separate from the OWASP **API** Security Top 10 used throughout this file
(which remains the 2023 edition and is still current, maintained by a different OWASP
team on its own release cycle). The web app Top 10 2025 merged SSRF into Broken Access
Control, promoted Security Misconfiguration to #2, renamed "Vulnerable and Outdated
Components" to "Software Supply Chain Failures," and added a new "Mishandling of
Exceptional Conditions" category. This affects the category numbering used in your
main web application security repo (built on the 2021 edition), not this API repo —
flagging it here so it does not get missed, but not making changes to either repo for
it right now unless you want that separately.
