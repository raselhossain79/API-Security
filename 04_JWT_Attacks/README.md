# JWT Attack Techniques — API Security Note Series

A dedicated, deep-dive API security treatment of JWT (JSON Web Token) attack
techniques, written as a companion series to a separate web application
security note repository. Mechanism-first throughout: every attack file
assumes you understand *why* the underlying trust model exists before showing
you how it gets broken.

## How to Use This Series

Read in numeric order. Each file states its prerequisites at the top. File 01
is mandatory background for everything else — do not skip it even if you
already know JWTs, since every later exploit is explained in terms of exactly
which step from File 01 §6 (the verification flow) is being violated.

## File Index

| File | Contents |
|---|---|
| `01-jwt-structure-deep-dive.md` | Header, payload, signature — full mechanism. Base64url encoding explained precisely. Standard claims (`sub`, `exp`, `iat`, `iss`, `aud`, `nbf`, `jti`). HMAC vs. RSA signing math. The six-step correct verification flow every attack in this series violates one step of. |
| `02-alg-none-and-weak-secret-attacks.md` | The `alg:none` signature-stripping attack, piece by piece. HS256 weak-secret brute-forcing with hashcat (mode 16500, every flag) and jwt_tool (`-C`, `-d`, `-S`, `-p`, `-T`, every flag). WAF/gateway detection and bypass considerations included. |
| `03-algorithm-confusion-attacks.md` | RS256→HS256 confusion — the precise cryptographic reason using a public key as an HMAC secret produces a valid-looking signature. PS256 variant notes. `sig2n` two-token public key derivation when no key is exposed. Explicit explanation of why WAF/gateway defenses are *not* meaningfully relevant here. |
| `04-header-injection-attacks.md` | JWK header injection, JKU header injection, and `kid` parameter injection (path traversal and SQL injection variants), each piece by piece. Full WAF/gateway detection and realistic bypass section. |
| `05-claim-manipulation-techniques.md` | Manipulating `sub`, `role`, `admin`, `exp` once a signature bypass is achieved. Token expiry bypass (both forgery-based and missing-enforcement variants). Refresh token abuse patterns (reuse, revocation, scope enforcement). |
| `06-jwt-tool-complete-usage-guide.md` | Standalone consolidated reference — every jwt_tool flag across every mode (decode, tamper, sign, crack, exploit `-X` modes, live-target testing), cross-referenced back to the file where each attack was originally explained. |
| `07-cheatsheet-and-lab-mapping.md` | Attack decision tree, one-line cheatsheet per attack, complete PortSwigger Web Security Academy JWT lab mapping (all 8 labs, Apprentice → Practitioner → Expert, in official order) with honest gap disclosure for techniques not covered by an official lab. |

## Conventions Used Throughout

- **Mechanism first.** No attack payload is shown before explaining the
  underlying trust assumption it violates.
- **Every command/payload is broken down flag by flag / piece by piece.** No
  command is presented without an explanation of every component.
- **PortSwigger lab mappings** are given in official difficulty-progression
  order, with explicit disclosure whenever a documented technique has no
  corresponding official lab, rather than silently implying full lab
  coverage.
- **WAF/API Gateway sections** appear in every attack file. Where gateway-
  level defense is genuinely relevant, detection methods and realistic bypass
  considerations are covered in full. Where it is not meaningfully relevant
  to a given vulnerability class (e.g., algorithm confusion — a pure
  application-logic flaw), that is stated explicitly with reasoning, rather
  than omitted.
- **Real-world notes** close every file, distinguishing lab-conditions
  findings from what actually turns up in production APIs and bug bounty
  programs.
- Written entirely in English.

## Scope Note

This series is API/backend-focused and assumes JWTs used for session or
API authentication (bearer tokens, session cookies containing a JWT). It does
not cover JWE (encrypted JWTs) in depth, nor ECDSA-specific malleability
research, both of which are noted as out-of-scope extensions where relevant
rather than silently ignored.
