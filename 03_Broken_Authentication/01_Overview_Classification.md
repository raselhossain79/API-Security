# API Broken Authentication — Overview & Classification

**OWASP API Security Top 10 2023 — API2:2023 Broken Authentication**

---

## 1. Why This Is Different From Web App Authentication

In a traditional web application, authentication is mostly about one thing: the login form and the session cookie that follows it. The browser handles a lot of the heavy lifting — it stores cookies, attaches them automatically, and enforces some baseline protections (`HttpOnly`, `SameSite`, same-origin policy).

APIs remove almost all of that safety net. An API is consumed by:

- Mobile apps (which embed tokens in local storage on the device)
- Single-page applications (which often store tokens in JavaScript-accessible storage)
- Other backend services (machine-to-machine, using API keys or client-credential OAuth flows)
- Third-party integrations (partners calling your API directly)

None of these consumers get browser-level protections for free. The API itself — every single endpoint — has to independently enforce "is this request authenticated, and is the token still valid, and was it issued to this caller for this purpose." When even one endpoint forgets to check, the whole authentication scheme is broken for that endpoint, regardless of how well login itself is implemented.

This is why OWASP frames Broken Authentication as its own API-specific category rather than folding it into general web authentication guidance: the attack surface is every endpoint's independent enforcement decision, not just the login page.

---

## 2. Classification of API Authentication Flaws

This series groups API authentication flaws into four testable categories. Each maps to one of the following files.

### 2.1 Missing Authentication Enforcement
An endpoint exists that should require a valid token/credential, but does not check for one, or checks incorrectly (e.g., checks for presence of an `Authorization` header but never validates its contents).

**Where it hides:** admin sub-paths, internal-only endpoints exposed by accident, newer endpoints added after the main auth middleware was written, endpoints reachable via an alternate HTTP method.

### 2.2 Weak Token Design (Entropy, Predictability)
Tokens (session tokens, API keys, refresh tokens, password-reset tokens) that are short, sequential, based on predictable inputs (timestamp, incrementing user ID, weakly-seeded random number generator), or otherwise guessable/brute-forceable.

### 2.3 Insecure Token Handling (Transmission, Storage, Lifecycle)
Covers:
- Tokens sent in URL query strings or path segments instead of headers (logged in server access logs, browser history, proxy logs, Referer headers)
- Tokens that never expire, or that remain valid after logout/revocation
- No mechanism to revoke a specific token (e.g., a stolen refresh token can be used forever)
- Tokens reused across unrelated sessions or issued as long-lived when they should be short-lived

### 2.4 Credential Verification Gaps
Covers both:
- **Sensitive-action re-authentication gaps** — changing email, password, or MFA settings without re-verifying the current password or a fresh authentication factor
- **Credential-attack surface** — brute force and credential stuffing against login/authentication endpoints, which succeed specifically because of missing/weak rate limiting and verbose error responses

### 2.5 Authentication Bypass Techniques
Distinct from "missing authentication" (2.1) in that these are techniques testers use to *discover* 2.1 and other gaps: removing the `Authorization` header, switching HTTP methods, manipulating token format/structure, and exploiting inconsistent enforcement between an API gateway and the backend service it fronts.

---

## 3. Where WAF / API Gateway Defenses Fit In This Topic

**This is addressed directly, per your requirement, rather than skipped.**

Broken Authentication is fundamentally different from injection-style vulnerabilities (SQLi, XSS, SSTI) when it comes to WAF/Gateway relevance:

- A WAF is a pattern-matching engine. It is effective against attacks that have a recognizable *payload signature* — a `UNION SELECT`, a `<script>` tag, a `../../` sequence. Broken authentication attacks generally **do not have a malicious payload to sign on** in this sense. A request to `GET /api/v1/admin/users` with no `Authorization` header is not "malicious-looking" — it's a normal, well-formed HTTP request. The vulnerability is not in *what* was sent; it's in the *backend's failure to check* what was (or wasn't) sent.
- Where WAFs and Gateways **do** contribute meaningfully to this category:
  - **Rate limiting / brute-force detection** (relevant to file 3 — credential-based attacks). This is the one sub-area where Gateway/WAF-layer defense is central to the vulnerability itself, so it gets full treatment there, including detection logic and realistic bypass methods (distributed source IPs, header spoofing, credential batching, timing jitter).
  - **Gateway-vs-backend enforcement mismatch.** In modern API architectures, the Gateway (Kong, Apigee, AWS API Gateway, Azure APIM) is often the layer that terminates authentication (validates the JWT, checks the API key) before proxying to the backend microservice. This creates a distinct, gateway-specific bypass class: if the backend service is reachable directly (misconfigured internal routing, exposed internal DNS, a debug port left open) or if the Gateway forwards a request it *failed* to authenticate but still trusts, the backend may process it as authenticated because it assumes "if it reached me, the Gateway already checked." This is covered in file 4 (Authentication Bypass Techniques) as a distinct bypass primitive, not a WAF signature-evasion exercise.
- **What genuinely does NOT apply here:** classic WAF *payload* evasion techniques (encoding tricks, case manipulation, comment injection to break regex signatures) are not meaningfully relevant to Broken Authentication, because there is no injected payload for a WAF to pattern-match against in most of these flaws (missing auth checks, weak token entropy, missing expiry). We are stating this explicitly rather than manufacturing a WAF-bypass section that wouldn't reflect real-world testing.

---

## 4. Real-World Context

- **T-Mobile API breach (2023)** — an unauthenticated API endpoint exposed customer PII for over a year before discovery; the root cause was a missing authentication check on one specific endpoint added after the main auth layer was implemented, not a flaw in the login system itself.
- **Peloton API (2021)** — the `/api/user/{id}` endpoint returned private profile data for **any** authenticated user querying **any** user ID, illustrating that "authentication" and "authorization" are frequently conflated; here authentication worked fine, but this series is scoped to the authentication half of that boundary.
- **Parler API (Jan 2021)** — posts were retrievable via sequentially predictable post IDs with no meaningful authentication gate on the retrieval endpoint, enabling mass scraping — an example of missing-endpoint-level enforcement at scale.
- Bug bounty programs (HackerOne, Bugcrowd) consistently rank Broken Authentication among the top 3 most-rewarded API categories because it frequently grants direct account takeover rather than requiring a chained exploit.

---

## 5. How This Series Is Structured

| File | Covers |
|---|---|
| `01_Overview_Classification.md` | This file |
| `02_Token_Security_Testing.md` | Entropy analysis, transmission channel testing, expiration/revocation testing |
| `03_Credential_Based_Attacks.md` | Rate limit detection, response-based detection, Burp Intruder vs Turbo Intruder |
| `04_Authentication_Bypass_Techniques.md` | Header removal, method switching, token format manipulation, gateway/backend mismatch |
| `05_Final_Cheatsheet.md` | Condensed reference + full PortSwigger/crAPI lab map |

Continue to `02_Token_Security_Testing.md`.
