# OAuth 2.0 Attack Techniques — Note Series

A mechanism-first, GitHub-ready reference on OAuth 2.0 attack techniques, written to the same depth and structure as the accompanying web application vulnerability series. Every attack is preceded by an explanation of the legitimate mechanism it abuses, and every request example is broken down parameter by parameter — what's being changed, what the server does with it, and why that produces the vulnerability.

## Files in This Series

| # | File | Covers |
|---|---|---|
| 1 | [`01-oauth-flows-http-mechanics.md`](01-oauth-flows-http-mechanics.md) | Authorization Code, Client Credentials, Device Code, and Implicit flows explained as raw HTTP, mechanism first — the required baseline for every attack file that follows |
| 2 | [`02-redirect-uri-attacks.md`](02-redirect-uri-attacks.md) | redirect_uri validation bypass (path/encoding/pollution/localhost tricks), open redirect chaining, subdomain takeover chaining, plus WAF/gateway detection and bypass considerations |
| 3 | [`03-state-parameter-csrf.md`](03-state-parameter-csrf.md) | What `state` actually protects against, detecting missing/weak state, login CSRF, and forced account-linking CSRF |
| 4 | [`04-scope-elevation-token-leakage.md`](04-scope-elevation-token-leakage.md) | Scope upgrade attacks (code flow and implicit flow) and code/token leakage via Referer headers, browser history, server logs, and error messages |
| 5 | [`05-account-takeover-oauth-chains.md`](05-account-takeover-oauth-chains.md) | Full account-takeover chains: attacker-controlled provider linking, pre-account-takeover via unverified email claims, and redirect_uri interception carried through to a real login |
| 6 | [`06-pkce-bypass.md`](06-pkce-bypass.md) | PKCE mechanics and its implementation bypasses: `plain`-method downgrade, non-enforced PKCE, and mobile custom-URL-scheme interception |
| 7 | [`07-cheatsheet-lab-mapping.md`](07-cheatsheet-lab-mapping.md) | Consolidated quick-reference cheatsheet and full PortSwigger Web Security Academy OAuth lab mapping in official Apprentice → Practitioner → Expert order, with honest gap disclosure |

## Reading Order

Read in numeric order on a first pass — file 1 is a hard prerequisite for everything else, since every subsequent file assumes fluency in reading a raw OAuth HTTP exchange. After the first pass, file 7 works as a standalone quick-reference and lab-practice guide.

## Conventions Used Throughout

- **Mechanism first.** Every attack file explains the legitimate flow/parameter/protection being targeted before describing how to break it.
- **Line-by-line request breakdowns.** No example says "modify this parameter" without explaining what the parameter does, what the server does with the modified value, and why that produces the vulnerability.
- **PortSwigger lab mapping in official difficulty order**, with explicit disclosure where no matching lab currently exists for a technique covered.
- **WAF/API Gateway relevance addressed explicitly per topic** — either with concrete detection methods and realistic bypasses, or with an explicit statement of why edge-level defenses aren't the meaningful control for that particular vulnerability class.
- **Real-world notes** in every file, tying the technique to documented bug bounty patterns or industry incidents rather than treating it as a purely academic exercise.

## Scope Note

This series covers core OAuth 2.0 protocol-level attacks. It does not cover OpenID Connect-specific vulnerabilities (ID token validation flaws, dynamic client registration SSRF, JWKS confusion) in depth, since those extend beyond OAuth 2.0 proper — file 7 flags where an OpenID-adjacent PortSwigger lab appears in the same topic category for completeness, with a pointer to where its exploitation mechanics are better covered.
