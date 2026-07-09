# API Security Misconfiguration — OWASP API Security Top 10 2023 (API8)

A focused note series on **API-specific security misconfiguration**, covering the patterns that
appear disproportionately in REST, GraphQL, and gateway-fronted APIs. This series assumes you
already know general misconfiguration testing (default installs, unnecessary features, verbose
platform banners, missing hardening baselines) from the companion **Web Application Security
Misconfiguration** series. Where a mechanism is shared between web apps and APIs, this series
cross-references that content instead of repeating it, and spends its own space on what changes
when the "page" is a JSON or GraphQL endpoint instead of an HTML page.

## Scope

This series covers OWASP API Security Top 10 2023 — **API8:2023 Security Misconfiguration**. It
does not re-cover BOLA (API1), Broken Authentication (API2), BOPLA (API3), Unrestricted Resource
Consumption (API4), BFLA (API5), Unrestricted Access to Sensitive Business Flows (API6), or SSRF
(API7) — those have their own dedicated series in this library.

## Files in this series

| # | File | Covers |
|---|------|--------|
| 1 | [`01-overview.md`](01-overview.md) | What "misconfiguration" means for an API specifically, the API-specific misconfiguration category map, why WAF/gateway bypass matters differently here than for injection-class bugs |
| 2 | [`02-exposed-api-documentation.md`](02-exposed-api-documentation.md) | Swagger UI / OpenAPI specs left live in production, GraphQL introspection enabled, common documentation paths, piece-by-piece exploitation |
| 3 | [`03-cors-and-security-headers.md`](03-cors-and-security-headers.md) | API-specific CORS misconfiguration patterns (reflected origin, null origin, wildcard + credentials), missing API-relevant security headers |
| 4 | [`04-error-message-information-leakage.md`](04-error-message-information-leakage.md) | Stack traces, internal paths, DB fragments, and library versions leaking through API error responses; how to trigger each class |
| 5 | [`05-default-credentials-and-http-methods.md`](05-default-credentials-and-http-methods.md) | Default/test credentials on Swagger UI, Kong, Apigee, AWS API Gateway; unnecessary HTTP methods left enabled on API endpoints |
| 6 | [`06-cheatsheet.md`](06-cheatsheet.md) | Condensed checklist, payload quick-reference, and PortSwigger lab index for this whole series |

## How to use this series

- Read `01-overview.md` first — it sets the category boundaries and explains why some
  sub-topics get a WAF/Gateway bypass section and others explicitly don't.
- Each technique file follows the same structure: **mechanism → how to find it → piece-by-piece
  exploitation walkthrough → impact → WAF/gateway detection & bypass (where relevant) →
  PortSwigger lab mapping → real-world notes → remediation**.
- PortSwigger labs are listed in strict Apprentice → Practitioner → Expert order per topic, with
  honest disclosure of where PortSwigger has no lab for a pattern (several API-gateway-specific
  patterns, like Kong/Apigee default credentials, have no PortSwigger lab — this is stated
  explicitly rather than a lab being invented or a gap being silently skipped).
- **crAPI** (Completely Ridiculous API) is noted as supplementary practice wherever a pattern has
  no PortSwigger lab coverage, since PortSwigger's labs are web-app-first and don't model real
  gateway products.

## Cross-references to other series in this library

- **Security Misconfiguration (web app series)** — general misconfiguration testing methodology,
  default installs, debug consoles, directory listing, cloud storage misconfiguration.
- **CORS (web app series)** — full CORS mechanism, preflight behavior, browser enforcement model.
- **Broken Access Control series** — HTTP method / verb-based access control bypass mechanism.
- **JWT Attacks series** — if exposed API docs or gateway consoles lead to token issuance abuse.
- **GraphQL Security series** (if present) — deeper GraphQL-specific attack techniques beyond
  introspection exposure, which is only covered here as a misconfiguration.
- **API Reconnaissance series** — broader endpoint discovery methodology; this series only covers
  the specific case of discovering documentation/spec files.

## Conventions

- Full English only, no Bangla/Banglish.
- Every payload and request field is broken down piece by piece: what is misconfigured, and
  exactly what information or access it hands an attacker.
- Delivered as a GitHub-ready folder / ZIP archive.
