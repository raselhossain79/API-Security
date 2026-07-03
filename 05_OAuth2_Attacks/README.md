# OAuth 2.0 Attack Techniques — Note Series

A mechanism-first reference series covering OAuth 2.0 authentication flow exploitation, built for penetration testing and bug bounty work. Part of a broader security note library also covering OWASP API Security Top 10, JWT attacks, and general web application vulnerability classes.

## How This Series Is Organized

Every file follows the same structure: mechanism explained first, attacks second, every request example broken down parameter by parameter with an explicit note on *why the server trusts the value being manipulated*, real-world industry framing, and honest disclosure of what is and isn't covered by an existing PortSwigger Web Security Academy lab.

Read in order — each file builds on assumptions established in the ones before it, especially File 1.

## File Index

| # | File | Summary |
|---|------|---------|
| 1 | [`01-oauth-fundamentals-and-flows.md`](./01-oauth-fundamentals-and-flows.md) | Roles, client registration, and full mechanism walkthroughs of Authorization Code, Implicit, Client Credentials, and Device flows. Read this first — everything else assumes it. |
| 2 | [`02-redirect-uri-attacks.md`](./02-redirect-uri-attacks.md) | Authorization code interception via redirect_uri manipulation: validation bypass techniques, open redirect chaining, proxy-page chaining, subdomain takeover chaining. The highest-value attack surface in this series. |
| 3 | [`03-state-parameter-csrf-attacks.md`](./03-state-parameter-csrf-attacks.md) | CSRF on the OAuth flow itself: missing/predictable/unbound state, forced account linking, login CSRF. Covers precisely why state stops this class of attack but not File 2's. |
| 4 | [`04-scope-and-token-leakage-attacks.md`](./04-scope-and-token-leakage-attacks.md) | Scope elevation via unvalidated re-submission at token exchange, plus authorization code/token leakage through Referer headers, browser history, and server/APM logs. |
| 5 | [`05-pkce-bypass.md`](./05-pkce-bypass.md) | What PKCE is specifically designed to stop (File 2's core attack), and the four concrete misconfiguration patterns that leave it bypassable even when "implemented." |
| 6 | [`06-account-takeover-oauth-chains.md`](./06-account-takeover-oauth-chains.md) | Full multi-step chains combining Files 2–5 into realistic account takeover paths, plus a testing-priority checklist for real engagements. |
| 7 | [`07-cheatsheet.md`](./07-cheatsheet.md) | Condensed quick reference: checklists, payload templates, and the full PortSwigger lab index — for use during active testing, not for learning from scratch. |

## Standing Conventions (Consistent Across This Whole Library)

- Mechanism explained before any attack technique.
- Every request/payload broken down piece by piece — which parameter is manipulated, why the server trusts it, what the result is.
- PortSwigger Web Security Academy labs mapped in official difficulty-progression order, with honest disclosure of any technique that doesn't currently have a dedicated lab.
- Real-world industry framing in every file — how the technique actually shows up in bug bounty triage and production incidents, not just lab theory.
- Full English only, no shorthand or non-English text.

## PortSwigger Lab Coverage at a Glance

| Difficulty | Lab | Covered in |
|---|---|---|
| Apprentice | Authentication bypass via OAuth implicit flow | File 1 |
| Practitioner | Forced OAuth profile linking | File 3, File 6 |
| Practitioner | OAuth account hijacking via redirect_uri | File 2, File 6 |
| Practitioner | SSRF via OpenID dynamic client registration | Noted as adjacent/OIDC, out of core scope |
| Expert | Stealing OAuth access tokens via an open redirect | File 2, File 6 |
| Expert | Stealing OAuth access tokens via a proxy page | File 2, File 4, File 6 |

This table reflects the core OAuth authentication labs confirmed at the time this series was written. PortSwigger updates the Web Security Academy periodically — check `portswigger.net/web-security/all-labs` for the current list before assuming this table is exhaustive, particularly for scope elevation and PKCE bypass, which are covered here as testing methodology drawn from written topic content rather than from a dedicated standalone lab.

## Prerequisites

Comfort with intercepting and modifying HTTP requests in Burp Suite (or equivalent), and the fundamentals covered in this library's Web Fundamentals and API Fundamentals note sets. No prior OAuth-specific knowledge assumed — File 1 builds it from the ground up.
