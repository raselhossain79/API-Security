# API Key Security Testing — Note Series

A structured, GitHub-ready reference for testing API key security: how keys leak,
how to test them once found, and the dedicated tooling used to automate discovery.
Built to the same depth and format as the web application and API security series
(BOLA, Broken Authentication, JWT Attacks, OAuth 2.0, API Reconnaissance, etc.).

## Scope

This series treats "API key security" as its own vulnerability class, distinct from
but adjacent to Broken Authentication (API2) and BOLA (API1) in the OWASP API
Security Top 10. An API key is a bearer credential, usually static, usually
long-lived, and frequently mishandled by both developers (leakage) and platform
teams (weak issuance, weak scoping, weak revocation). This series covers all three
failure modes.

## File Index

| # | File | Covers |
|---|------|--------|
| 1 | `01-overview-and-api-key-types.md` | What API keys are, common formats across major providers, threat model, why WAF/Gateway bypass is largely not applicable to this class (with the one exception) |
| 2 | `02-leakage-discovery-methodology.md` | JS bundle recon, GitHub dorking and git history mining, API response/error leakage, DevTools Network tab, public Postman collections |
| 3 | `03-entropy-scope-rotation-testing.md` | Entropy and predictability testing, scope/permission testing, privilege escalation via key substitution, rotation gap testing |
| 4 | `04-tooling-truffleHog-gitleaks-nuclei.md` | truffleHog and gitleaks (full flag-by-flag breakdowns), nuclei templates for API key detection |
| 5 | `05-final-cheatsheet.md` | Condensed command reference and testing checklist |

## Reading Order

Read in numeric order on first pass. Files 2 and 3 assume you've read the key
type/format material in File 1. File 4 assumes you understand *why* you're
scanning (Files 2–3) before you're handed tools that automate it. File 5 is a
quick-reference once you've internalized the rest — not a replacement for reading
the full files.

## Standing Conventions (same as prior series)

- Mechanism explained before technique — you should understand *why* a key leaks
  or *why* an entropy check works before running a command against it.
- Every command is broken down flag by flag. No "just run this."
- WAF/API Gateway relevance is addressed explicitly in every file, even where the
  honest answer is "not applicable, here's why."
- PortSwigger Web Security Academy lab mappings are given in strict
  Apprentice → Practitioner → Expert order, with an honest note that PortSwigger's
  API-key-specific lab coverage is thin — supplemented with HackTheBox API
  challenges and real disclosed HackerOne reports where PortSwigger has no
  equivalent lab.
- Full English only, in all notes and cheat sheets.
- Cross-references point to sibling series (JWT Attacks, OAuth 2.0, BOLA, Broken
  Authentication, API Reconnaissance) instead of repeating their content.

## Primary Practice Platforms

- **PortSwigger Web Security Academy** — primary, despite thin direct coverage of
  API keys as a named topic (see File 1 for why, and where labs *do* apply).
- **HackTheBox** — API-focused boxes/challenges, used to fill the gap PortSwigger
  leaves for hands-on key discovery/abuse scenarios.
- **crAPI** — supplementary, self-hosted, for realistic API key issuance/scope
  scenarios end to end.
- **HackerOne Hacktivity (disclosed reports)** — real-world confirmation that these
  aren't academic issues; used as case studies, not as a lab environment.

## Prerequisites

- API Fundamentals notes (from the prerequisite folder)
- API Reconnaissance series (this series assumes you can already enumerate
  endpoints and identify where keys are transmitted — header vs query string vs
  body)
- Basic familiarity with Burp Suite (Proxy, Repeater, Intruder) — used throughout
