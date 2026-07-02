# API Broken Authentication — OWASP API Security Top 10 2023 (API2:2023)

A structured, GitHub-ready technical reference on Broken Authentication in APIs. This series is written for penetration testers and bug bounty hunters who already understand web application authentication flaws and need to extend that knowledge to API-specific contexts, where the attack surface, tooling, and detection methodology differ meaningfully from traditional web form-based testing.

This series assumes familiarity with core API fundamentals (REST/JSON structure, HTTP methods, status codes, Burp Suite basics) and builds directly on top of general web application authentication testing knowledge. Where a concept overlaps with web app auth testing, this series calls that out explicitly rather than re-explaining it from scratch.

---

## Why This Matters

Broken Authentication is ranked #2 in the OWASP API Security Top 10 2023, up from a broader "Broken Authentication" category in the 2019 list that has since been refined to focus specifically on how APIs implement (and misimplement) identity verification. APIs are disproportionately vulnerable here because:

- APIs are frequently consumed by mobile apps, SPAs, third-party integrations, and internal microservices — each with different assumptions about who is responsible for enforcing authentication.
- Authentication logic is often duplicated or inconsistently applied across dozens or hundreds of endpoints, especially in microservice architectures where each service may implement its own auth check (or forget to).
- API tokens (JWTs, API keys, OAuth bearer tokens) introduce failure modes that session cookies do not: client-side decodability, algorithm confusion, weak signing secrets, and long-lived tokens with no server-side revocation.
- Rate limiting and brute-force protections are frequently built for the web login form and never extended to the API endpoints that mobile apps or partners use to authenticate.

## File Index

| File | Contents |
|---|---|
| `01-overview-and-classification.md` | API2:2023 definition, authentication vs. authorization distinction, root causes, real-world breach context |
| `02-token-security-testing.md` | Token entropy analysis, token reuse across sessions, insecure transmission channels, missing expiration/revocation |
| `03-credential-based-attack-techniques.md` | Credential stuffing methodology, API-specific brute-force detection, Intruder vs. Turbo Intruder decision criteria |
| `04-authentication-bypass-techniques.md` | Auth header removal, token format swapping, HTTP method switching, sensitive-action re-authentication gaps |
| `05-cheatsheet.md` | Consolidated quick-reference: commands, payloads, checklists |

## Testing Environments Referenced

- **PortSwigger Web Security Academy** — used where labs exist that map cleanly to a technique. Coverage of pure API auth flaws on PortSwigger is limited; gaps are disclosed honestly rather than force-fitted.
- **crAPI (Completely Ridiculous API)** — OWASP's intentionally vulnerable API training platform, purpose-built for API-specific vulnerability classes including broken authentication. Used as the primary hands-on complement where PortSwigger coverage is thin.
- **Burp Suite Community Edition** — primary tool throughout. Turbo Intruder (free extension via BApp Store) is referenced where Community Edition's rate-limited Intruder becomes a bottleneck.

## Conventions Used in This Series

- Every request example and tool command is broken down piece by piece — no unexplained flags or payloads.
- PortSwigger labs are mapped in official difficulty-progression order. Where no lab exists for a technique, that gap is stated directly instead of stretching an unrelated lab to fit.
- Every file includes a real-world industry framing section connecting the technique to actual breach patterns or bug bounty report classes.
- Written in full English throughout, structured for direct GitHub upload.

## Suggested Reading Order

1. Start with `01-overview-and-classification.md` to establish the mental model.
2. Move to `02-token-security-testing.md` and `03-credential-based-attack-techniques.md` — these can be read in either order.
3. Read `04-authentication-bypass-techniques.md` last among the technique files, since it assumes familiarity with how tokens and credentials are validated (covered in files 2 and 3).
4. Use `05-cheatsheet.md` as a field reference during live engagements.
