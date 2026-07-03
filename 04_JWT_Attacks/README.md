# JWT (JSON Web Token) Attack Techniques

A dedicated, API-focused deep dive into JWT authentication exploitation. This series
assumes the reader already understands general web application security concepts
(see the companion Web Application Security note series, Cryptographic Failures
section, for the introductory-level JWT coverage). This series goes significantly
deeper and is scoped specifically to API authentication attack surface.

## Scope and Relationship to Other Series

The Web Application Security series covers JWT briefly as one example of a
cryptographic failure. This series treats JWT as a first-class API security topic:
structural mechanics, every major attack class against JWT-based authentication,
full tool usage, and a consolidated cheatsheet for engagement use.

## File Index

| # | File | Covers |
|---|------|--------|
| 1 | `01-jwt-structure-and-fundamentals.md` | Header.Payload.Signature structure, Base64URL encoding, JSON claims, signing algorithms, how verification actually works |
| 2 | `02-alg-none-and-weak-secret-attacks.md` | `alg:none` signature-stripping attack, HS256 weak secret brute-forcing with hashcat and jwt_tool |
| 3 | `03-algorithm-confusion-attacks.md` | RS256 → HS256 key confusion, PS256 variants, why asymmetric/symmetric confusion is exploitable |
| 4 | `04-header-injection-attacks-jwk-kid.md` | JWK header injection (embedded attacker key), `kid` parameter path traversal, `kid` parameter SQL injection |
| 5 | `05-claim-manipulation-and-expiry-bypass.md` | Post-bypass claim tampering (`sub`, `role`, `admin`), `exp` manipulation, refresh token flow abuse |
| 6 | `06-jwt-tool-complete-usage-guide.md` | Full flag-by-flag jwt_tool reference across every mode and option relevant to the above attacks |
| 7 | `07-cheatsheet.md` | Consolidated one-page reference: decision tree, payloads, commands |

## Conventions Used Throughout This Series

- **Mechanism-first**: every attack file explains *why* the underlying mechanism
  allows the exploit before showing the exploit itself.
- **Flag-by-flag**: every tool command and every payload is broken into its
  constituent parts with an explanation of what each part does.
- **PortSwigger lab mapping**: labs are mapped in PortSwigger's own
  difficulty-progression order, with an honest note wherever a technique in this
  series is *not* covered by an existing PortSwigger lab (gaps are disclosed, not
  glossed over).
- **Real-world framing**: each file includes a "Real-World Notes" section
  connecting the lab-scale technique to how it shows up in production APIs,
  bug bounty reports, and CTFs.
- **Primary lab environment**: PortSwigger Web Security Academy, using Burp Suite
  Community Edition as the interception/manipulation tool, and jwt_tool /
  hashcat for offline and automated attacks.

## Suggested Reading Order

Read files 1 through 5 in order — each builds on the mental model from the
previous one. File 6 (jwt_tool reference) and file 7 (cheatsheet) are reference
material meant to be consulted while working through files 2–5 or during a live
engagement.
