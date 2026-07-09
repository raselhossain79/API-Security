# 01 — Overview: API-Specific Security Misconfiguration (API8:2023)

## 1. Why this gets its own series instead of living in the web app Misconfiguration notes

The web application Security Misconfiguration series covers the *general* mechanism: unnecessary
features left enabled, default installs, verbose platform banners, missing hardening baselines,
directory listing, and so on. That mechanism doesn't change when the target is an API. What
changes is **delivery**:

- A misconfigured web app leaks information through rendered HTML, comments, and visible pages.
  A misconfigured API leaks the *same class* of information through response headers, JSON error
  bodies, and machine-readable schema/spec files that were never meant to survive into production.
- A web app's attack surface is discovered by crawling pages. An API's attack surface is often
  discovered by finding **one file** — an OpenAPI spec or a GraphQL introspection response — that
  hands you the entire endpoint map, parameter names, and data types in a single request.
- Web app CORS misconfiguration is usually about protecting a session cookie used by a browser
  UI. API CORS misconfiguration is usually about protecting a bearer token or API key used by a
  single-page app talking to a separate API origin — the credential model and the blast radius
  differ even though the underlying CORS mechanism is identical.

This series treats the underlying mechanisms (CORS, HTTP semantics, error handling) as already
understood from the web app series and other series in this library, and focuses entirely on the
patterns that are distinctive to APIs.

## 2. The API-specific misconfiguration category map

| Category | What it is | File |
|---|---|---|
| Exposed API documentation | Swagger UI / OpenAPI JSON / GraphQL introspection reachable without auth in production | `02-exposed-api-documentation.md` |
| API-specific CORS misconfiguration | Reflected origin, `null` origin trust, wildcard + credentials on API endpoints consumed by JS clients | `03-cors-and-security-headers.md` |
| Missing API-relevant security headers | Headers that matter for JSON/API responses specifically, as opposed to HTML-serving headers | `03-cors-and-security-headers.md` |
| Verbose API error responses | Stack traces, internal paths, DB fragments, library versions returned in JSON error bodies | `04-error-message-information-leakage.md` |
| Unnecessary HTTP methods | Methods left enabled on API routes that expose write/delete/debug functionality or bypass auth logic keyed to method | `05-default-credentials-and-http-methods.md` |
| Default/test credentials on API management surfaces | Swagger UI basic-auth defaults, API gateway admin consoles (Kong, Apigee, AWS API Gateway) left on default creds | `05-default-credentials-and-http-methods.md` |

Each of these is a *configuration* failure, not a *logic* or *injection* failure — nothing here
requires the API to have a bug in its business logic. The vulnerability is that something was
shipped to production in a state meant only for development, internal use, or initial setup.

## 3. Why WAF/API Gateway bypass gets uneven treatment across this series

This is worth stating explicitly rather than leaving it implicit, per the instruction to always
address WAF/Gateway relevance even when the answer is "not applicable."

- **Exposed documentation (file 02)** and **default credentials (file 05)** are not attacks a WAF
  is designed to stop. A WAF inspects requests for malicious *payloads* — injection strings,
  known exploit patterns, anomalous encoding. Requesting `GET /swagger.json` or logging in to a
  Kong admin API with `kong:kong` is a **syntactically normal, semantically valid request**. There
  is no payload for a WAF signature to match against. This is why file 02 states plainly that a
  WAF/bypass section would be misleading there, and instead discusses how **API gateways
  themselves** (not WAFs) can be configured to hide or restrict these surfaces, which is a
  configuration control, not a detection-and-block control.
- **CORS misconfiguration (file 03, CORS half)** is similarly not something a WAF inspects — CORS
  is enforced entirely by the *browser*, not the server or any inline security appliance. A WAF
  sitting in front of the API cannot see or influence what the browser does with an
  `Access-Control-Allow-Origin` response header. File 03 explains this directly instead of
  presenting a bypass narrative that doesn't apply.
- **Missing security headers (file 03, headers half)** — same reasoning. A WAF blocks malicious
  requests; it does not add response headers the backend forgot to set (that's the job of a
  reverse proxy or gateway response-transformation policy, which is a *fix*, not a *defense to
  bypass*).
- **Verbose error messages (file 04)** is the one category in this series where WAF/gateway
  behavior is genuinely relevant both ways: some gateways strip or rewrite backend error bodies
  before they reach the client (a real defense), and some WAFs are tuned to flag inputs that are
  *known to trigger* stack traces (type confusion, oversized integers, null bytes). File 04
  therefore includes a real detection-and-bypass section.
- **Unnecessary HTTP methods (file 05, methods half)** also gets a short WAF/gateway note, because
  some gateways and WAF rulesets do allow-list HTTP methods at the edge — this is a control worth
  testing around, and bypass techniques (method override headers, case manipulation) are relevant.

The pattern to notice: **WAF/gateway bypass sections are included where a request has to pass a
payload-inspection or method-inspection control to succeed, and are explicitly declared
not-applicable where the "attack" is just requesting something that should never have been
reachable in the first place.**

## 4. How to use PortSwigger Web Security Academy for this series

PortSwigger's labs are excellent for the *mechanisms* underneath these misconfigurations (CORS,
information disclosure, GraphQL introspection) but were built API-agnostic or web-app-first —
PortSwigger has no lab that models a real API gateway admin console with default credentials, for
example, because that's a product-specific integration issue rather than a web app vulnerability
class. Each technique file is explicit about:

- Which PortSwigger labs map directly onto the API-specific pattern being taught.
- Which parts of a pattern have **no PortSwigger lab** at all (gateway default creds, OpenAPI spec
  exposure specifically) — stated honestly rather than stretching an unrelated lab to fit.
- Where **crAPI** (the OWASP-adjacent "Completely Ridiculous API" vulnerable API) is a better fit
  as supplementary hands-on practice for the gap.

## 5. Real-world framing

Every one of these misconfiguration categories has appeared repeatedly in public bug bounty
reports and breach post-mortems — not because the underlying idea is exotic, but because CI/CD
pipelines regularly promote development configuration straight into production: Swagger UI
enabled by a framework default, GraphQL introspection left on because it was never explicitly
disabled, a gateway admin API bound to `0.0.0.0` instead of localhost during a rushed deployment.
Each technique file includes a short real-world note grounding the pattern in how it actually
shows up during engagements, not just in a lab environment.
