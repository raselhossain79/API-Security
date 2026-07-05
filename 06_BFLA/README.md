# BFLA — Broken Function Level Authorization
### OWASP API Security Top 10 2023 — API5:2023

A self-contained reference series on Broken Function Level Authorization, built to the same depth and conventions as the accompanying web application security note series. Written for hands-on API security testing practice, primarily against PortSwigger Web Security Academy and OWASP crAPI.

---

## Files in this series

| File | Contents |
|---|---|
| [`01-overview-and-concept.md`](01-overview-and-concept.md) | BOLA vs BFLA distinction, why BFLA is ranked #5, vertical vs lateral escalation, WAF/gateway relevance statement |
| [`02-discovery-methodology.md`](02-discovery-methodology.md) | Path guessing, JavaScript/APK source mining, API documentation gap analysis, response field inference |
| [`03-bfla-patterns-and-bypass-techniques.md`](03-bfla-patterns-and-bypass-techniques.md) | Baseline non-admin credential testing, HTTP method switching, endpoint path manipulation, parameter-based role manipulation, vertical/lateral escalation, WAF/API Gateway bypass considerations |
| [`04-autorize-extension-testing.md`](04-autorize-extension-testing.md) | Full Autorize setup, configuration, workflow, and result validation for automated BFLA sweeps |
| [`05-final-cheatsheet.md`](05-final-cheatsheet.md) | Condensed testing checklist, pattern reference table, full PortSwigger lab map, crAPI challenge map |

---

## Recommended reading/practice order

1. Read `01` for the conceptual model — get the BOLA/BFLA line clear before touching any lab.
2. Read `02`, then actually run discovery techniques against a target (PortSwigger lab or crAPI) before opening `03`.
3. Read `03` and work through the pattern-matched PortSwigger labs in the order listed in `05`'s lab map.
4. Set up Autorize using `04` and re-sweep the same target for anything missed manually.
5. Use `05` as the standing reference during future engagements/bug bounty work.

---

## Conventions used throughout this series

- Mechanism-first explanations — every technique explains *why* the underlying check fails, not just *that* it fails
- Every request example broken down piece by piece: what's being tested, what a vulnerable response looks like, why the authorization check fails
- PortSwigger lab mappings in strict Apprentice → Practitioner → Expert order, with honest disclosure where a tier doesn't exist for this topic
- WAF/API Gateway relevance addressed explicitly, never silently omitted
- crAPI mapped as supplementary practice where it adds API-native testing value beyond PortSwigger's coverage
- All content in full English only

---

## Part of a larger reference library

This BFLA series is one component of an ongoing OWASP API Security Top 10 2023 note collection, alongside completed series on BOLA (API1), Broken Authentication (API2), BOPLA (API3), Unrestricted Resource Consumption (API4), rate limit bypass techniques, REST API testing methodology, API injection techniques, JWT attacks, and OAuth 2.0 attacks — plus a parallel web application vulnerability track covering the OWASP Top 10 and related topics.
