# 01 — Overview and Classification: API2:2023 Broken Authentication

## 1. Definition

OWASP API Security Top 10 2023 defines **API2:2023 Broken Authentication** as the failure to correctly implement or enforce mechanisms that verify a user's or system's identity when interacting with an API. This includes both the absence of authentication checks and the presence of authentication checks that are implemented weakly enough to be bypassed, guessed, or replayed.

This is distinct from **API1:2023 Broken Object Level Authorization (BOLA)** and **API5:2023 Broken Function Level Authorization**, which assume the attacker is already authenticated (or holds *a* valid identity) and is instead abusing insufficient checks on *what that identity is allowed to access*. Broken Authentication is the layer beneath authorization — if authentication itself is broken, authorization checks become irrelevant because the attacker can simply become any identity they want, or act with no identity at all.

## 2. Authentication vs. Authorization — Why This Distinction Matters for Testing

This distinction gets blurred constantly in casual conversation but must stay precise during testing, because it changes what you are trying to prove:

- **Authentication** answers: *"Who are you?"* — Testing here targets login endpoints, token issuance, token validation, session establishment, and credential handling.
- **Authorization** answers: *"What are you allowed to do?"* — Testing here (BOLA, BFLA) assumes a valid authenticated identity already exists and targets whether that identity's permissions are enforced correctly on objects and functions.

A practical test to classify a finding: if you can reproduce the bug **without ever supplying valid credentials or a valid token**, it is an authentication flaw. If you need a valid token but that token grants access it should not, it is an authorization flaw. Some real-world bugs straddle both — for example, a token confusion bug (Section 4.3 in file 02) can start as an authentication weakness and end as unauthorized access to another user's data.

## 3. Why API Authentication Breaks Differently Than Web Application Authentication

Web application authentication testing assumes a fairly narrow interaction surface: a login form, a session cookie, maybe CSRF tokens, and browser-enforced same-origin behavior. API authentication testing has to account for a wider and less browser-constrained surface:

- **No browser safety net.** Cookies get `HttpOnly`, `Secure`, and `SameSite` flags enforced by the browser. API clients (mobile apps, `curl`, Postman, third-party integrations) have no such enforcement — a token can be logged, cached, embedded in a URL, or stored in plaintext local storage with nothing stopping it.
- **Multiple auth mechanisms in the same system.** A single API often supports API keys for server-to-server calls, JWTs or opaque bearer tokens for user sessions, and OAuth 2.0 flows for third-party access — sometimes on the *same* set of endpoints, with inconsistent validation between them.
- **Auth checks are duplicated per-endpoint, not centralized by browser navigation.** In a traditional web app, unauthenticated users are often redirected before they reach a protected page. In an API, every single endpoint has to independently enforce its own check. It only takes one route where a developer forgot to attach the auth middleware.
- **Tokens are self-contained and inspectable.** JWTs in particular carry claims that are readable (though not necessarily *writable* without the signing key) by anyone who intercepts them. This creates entire attack classes — algorithm confusion, weak secret brute-forcing — that have no direct equivalent in opaque session-cookie-based web auth.
- **Machine clients don't behave like browsers under brute-force load.** Automated API clients can hammer authentication endpoints at a rate no human using a web form ever would, which changes how rate-limiting and lockout mechanisms need to be tested (covered in depth in file 03).

## 4. Root Causes Covered in This Series

This series maps to four practical root-cause categories, each covered in a dedicated file:

1. **Weak or missing token security** (file 02) — tokens with insufficient entropy, tokens reused across multiple sessions or users, tokens transmitted insecurely (URLs, query strings, logs), and tokens with no expiration or server-side revocation capability.
2. **Weak credential-based defenses** (file 03) — APIs vulnerable to credential stuffing and brute-force because rate limiting, lockout, or anomaly detection was built for the web login form and never extended to API-consumed auth endpoints.
3. **Authentication bypass through inconsistent enforcement** (file 04) — endpoints that skip auth checks entirely, accept a different token format than expected, or expose the same resource through an HTTP method that was never wired up to the auth middleware.
4. **Missing re-authentication on sensitive actions** (file 04) — an OWASP API2:2023-specific addition where an already-authenticated session is allowed to change account-critical information (password, email, MFA settings) without re-proving identity via current password or step-up authentication.

## 5. Real-World Industry Framing

Broken API authentication is not a theoretical category — it is one of the most consistently reported root causes in publicized API breaches over the past several years:

- **Peloton (2021)** — the API allowed unauthenticated requests to retrieve private account data for any user by ID; while the headline issue was authorization (BOLA-adjacent), the underlying enabling factor was that certain endpoints had no authentication requirement at all, a textbook API2:2023 pattern.
- **T-Mobile (multiple incidents, 2021–2023)** — several disclosed breaches involved API endpoints reachable without proper authentication enforcement, exposing customer PII at scale through automated scraping once the missing-auth endpoint was discovered.
- **Bug bounty reports (HackerOne/Bugcrowd, general pattern)** — a recurring high-value finding class is JWTs signed with weak, guessable, or leaked secrets (often committed to a public repository or reused from a tutorial), allowing an attacker to forge tokens for arbitrary users. This is covered mechanically in file 02.
- **Mobile-app-backed APIs** — a very common finding pattern in mobile-first products is that the mobile app's backend API duplicates web functionality but was assumed to be "private" since it's not linked from a browser. Testers who intercept mobile traffic with Burp routinely find that these endpoints have weaker or entirely absent authentication compared to their web counterparts, because the development team assumed obscurity was sufficient protection.

The common thread: broken API authentication is rarely a single dramatic bug. It is usually a gap in *consistency* — one endpoint, one token type, or one code path that didn't inherit the same auth enforcement as the rest of the system.

## 6. PortSwigger and crAPI Coverage — Honest Disclosure

PortSwigger Web Security Academy's authentication category is built primarily around **web application** login flows (password brute-forcing, 2FA bypass, logic flaws in multi-step login). It does **not** have a dedicated API-authentication learning path, and labs involving JWT attacks live under the **JWT** category rather than under "API" specifically. Where a PortSwigger lab is genuinely transferable to an API context (e.g., JWT algorithm confusion, brute-force protection bypass logic), it is mapped explicitly in files 02–04.

For gaps where no PortSwigger lab exists — most notably token reuse across sessions, insecure token transmission patterns, missing revocation, and sensitive-action re-authentication — this series points to **crAPI**, which was purpose-built by OWASP to cover these exact scenarios in a realistic microservice API context (a vehicle-telemetry-style application with a community, forum, and vehicle-management API). crAPI's authentication-related challenges are referenced by module name in the relevant files.

This honest gap disclosure is intentional: presenting a loosely-related PortSwigger lab as coverage for a technique it doesn't actually test would misrepresent your own hands-on practice depth, which matters both for your own skill development and for how this reference reads to anyone reviewing your GitHub.

## 7. What's Next

File 02 begins the technical testing methodology, starting with how to assess token entropy and identify insecure transmission patterns.
