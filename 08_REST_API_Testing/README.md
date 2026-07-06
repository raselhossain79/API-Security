# REST API Testing Methodology

A procedural framework for systematically testing any REST API — the recon, setup, and testing-order discipline that sits *before* any specific vulnerability class (BOLA, BFLA, JWT, OAuth, injection, etc.) can be tested meaningfully. This series complements the OWASP API Security Top 10 series by covering the methodology layer that every one of those vulnerability-class series assumes you've already done.

## Files in this series

| # | File | Covers |
|---|---|---|
| 01 | [`01-overview-and-setup.md`](01-overview-and-setup.md) | Reading API specs, mapping endpoints/methods, Burp & Postman setup for API testing, establishing a normal-behavior baseline |
| 02 | [`02-http-method-testing.md`](02-http-method-testing.md) | Testing all HTTP methods against every endpoint regardless of spec, method-override header bypass, what each unintended method exposes |
| 03 | [`03-versioning-attacks.md`](03-versioning-attacks.md) | Enumerating and attacking API versions, cross-version authorization/rate-limit differentials, legacy-version weak-auth checks |
| 04 | [`04-content-type-manipulation.md`](04-content-type-manipulation.md) | Switching between JSON/XML/plain-text/form-encoded, injection opportunities via content-type switching, parser fingerprinting |
| 05 | [`05-response-differential-analysis.md`](05-response-differential-analysis.md) | Systematic role/content-type/parameter-value comparison to surface authorization gaps and information leakage |
| 06 | [`06-parameter-fuzzing-methodology.md`](06-parameter-fuzzing-methodology.md) | JSON body structure fuzzing, nested-object fuzzing, array injection, hidden parameter discovery |
| 07 | [`07-methodology-checklist-cheatsheet.md`](07-methodology-checklist-cheatsheet.md) | Full sequential checklist, quick-reference cheatsheet, consolidated PortSwigger/crAPI lab mapping |

## How to use this series

Work through Files 01–06 in order on a new target the first time — each file assumes the previous file's baseline/inventory work is already done. Once familiar with the full methodology, use File 07 as a standalone run-sheet during live testing without re-reading the explanatory files.

## Conventions used throughout

- Mechanism-first explanations before any technique or payload
- Every request example and Burp workflow broken down piece by piece — what each header/parameter change specifically tests and why
- PortSwigger Web Security Academy lab mappings in strict Apprentice → Practitioner → Expert order, with honest disclosure where no PortSwigger lab exists for a given technique
- crAPI referenced as supplementary practice specifically where PortSwigger coverage is absent or incomplete
- WAF/API Gateway relevance addressed explicitly in every file — either a dedicated detection/bypass section, or an explicit statement of why it isn't meaningfully applicable to that file's content
- Real-world framing in every file, tying each technique back to how it plays out in production environments and live engagements
- Full English throughout; no Bangla/Banglish in any note content

## Primary tooling referenced

- **Burp Suite** — JWT Editor, Param Miner, Content Type Converter, OpenAPI Parser
- **Postman** — spec-driven collection generation, environment-variable-based version/token switching, proxied through Burp
- **PortSwigger Web Security Academy** — primary lab environment
- **crAPI** — supplementary practice environment for gaps in PortSwigger's API testing lab coverage

## Related series

This series is designed to be read alongside, not instead of:
- OWASP API Security Top 10 series (BOLA, Broken Authentication, BOPLA, Unrestricted Resource Consumption, BFLA, JWT attacks, OAuth 2.0 attacks)
- Web application vulnerability series (XXE, insecure deserialization, broken access control, mass assignment, prototype pollution) — referenced directly wherever this series' discovery techniques hand off into deeper exploitation covered there
