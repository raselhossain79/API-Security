# API Broken Authentication — OWASP API Security Top 10 2023 (API2:2023)

Comprehensive note series on Broken Authentication in APIs, built to match the depth and conventions of the accompanying web application security note series. Written entirely in English.

## Contents

| # | File | Description |
|---|---|---|
| 1 | [`01_Overview_Classification.md`](./01_Overview_Classification.md) | What Broken Authentication means in an API context, taxonomy of flaw categories, and an explicit discussion of where WAF/API Gateway defenses are (and are not) relevant to this vulnerability class |
| 2 | [`02_Token_Security_Testing.md`](./02_Token_Security_Testing.md) | Token entropy analysis, insecure transmission (URL/query-string tokens), missing expiration, missing revocation — full command breakdowns |
| 3 | [`03_Credential_Based_Attacks.md`](./03_Credential_Based_Attacks.md) | Rate limit detection methodology, response-based enumeration detection, and a full flag-by-flag breakdown of Burp Intruder vs Turbo Intruder with a tool-selection decision framework |
| 4 | [`04_Authentication_Bypass_Techniques.md`](./04_Authentication_Bypass_Techniques.md) | Authorization header removal, HTTP method switching, JWT/token format manipulation, Gateway/backend enforcement mismatches, sensitive-action re-authentication gaps |
| 5 | [`05_Final_Cheatsheet.md`](./05_Final_Cheatsheet.md) | Condensed testing checklist, tool-selection quick-reference, full PortSwigger Web Security Academy authentication lab map (Apprentice → Practitioner → Expert), crAPI supplementary practice map, reporting severity guide |

## Conventions Used Throughout

- Every command and request example is broken down flag-by-flag / parameter-by-parameter — no "just run this" instructions.
- PortSwigger labs are mapped in official difficulty-progression order with honest notes on how directly each lab's mechanism transfers to API-specific testing.
- Each file includes a real-world / industry-context section connecting the technique to actual disclosed incidents or bug bounty patterns.
- This series is intended for authorized testing (bug bounty programs in scope, engagements with written authorization, or self-hosted deliberately vulnerable targets like crAPI) only.

## Prerequisites

Best read after (or alongside) the companion **Web Application Security** note series, since several concepts (JWT structure, rate-limit detection, response-based enumeration) build on shared fundamentals rather than being re-derived from scratch here.

## Suggested Reading/Practice Order

1. Read files 01 → 04 in sequence.
2. Work through the PortSwigger Authentication labs in the order given in file 05, §3.
3. Move to crAPI's authentication-relevant challenges (file 05, §4) for API-specific hands-on practice.
4. Use file 05 as your standing reference during live testing/bug bounty work.
