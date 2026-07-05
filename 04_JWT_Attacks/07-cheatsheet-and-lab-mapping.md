# 07 — Final Cheatsheet and Complete PortSwigger Lab Mapping

---

## 1. Attack Decision Tree (Quick Triage)

Use this when you first decode an unfamiliar JWT (File 06 §3: run jwt_tool
with no flags first to see this information):

1. **Does `alg` say `none`, or can it be changed to `none` and still get
   accepted?** → Test File 02, Part A first. Fastest possible win, zero
   cracking/crypto required.
2. **Is `alg` HS256/384/512 with no unusual header fields (`jwk`, `jku`,
   `kid` pointing anywhere unusual)?** → Go straight to File 02, Part B
   (weak secret brute-force via hashcat/jwt_tool).
3. **Is `alg` RS256/PS256, and is a public key or JWKS endpoint discoverable
   anywhere (response headers, `.well-known`, client-side JS, `jku` in a
   legitimate token)?** → Test File 03 (algorithm confusion). If no key is
   exposed, try the `sig2n` two-token derivation before giving up on this
   path.
4. **Does the header contain a `jwk` field?** → Test File 04, Part A (embed
   your own key, sign with matching private key).
5. **Does the header contain a `jku` field?** → Test File 04, Part B (host
   your own JWKS, point `jku` at it).
6. **Does the header contain a `kid` field?** → Test File 04, Part C — try
   path traversal (`../../../dev/null` and similar) first, then SQLi markers
   if traversal fails and a database-backed lookup seems plausible.
7. **Regardless of whether any of the above succeed** → Always separately
   test File 05: does the application enforce `exp` server-side at all
   (replay an old/expired token directly against the API)? Does it trust
   `role`/`admin`/custom claims directly for authorization once *any*
   signature bypass is achieved?

---

## 2. One-Line Cheatsheet Per Attack

| Attack | One-line test |
|---|---|
| alg:none | Set `alg` to `none`, blank the signature, keep the trailing dot. |
| Weak secret | `hashcat -a 0 -m 16500 jwt.txt wordlist.txt` |
| Algorithm confusion | Sign HS256 token using the server's RSA **public key PEM bytes** as the HMAC secret. |
| JWK injection | Embed your own JWK in the header, sign with your matching private key. |
| JKU injection | Host your own JWKS at a URL you control, point `jku` at it, sign with your matching private key. |
| kid traversal | Set `kid` to `../../../../dev/null`, sign using an **empty string** as the HMAC secret. |
| kid SQLi | Set `kid` to a UNION-based payload returning an attacker-known value, sign using that known value as the secret. |
| Claim manipulation | Edit `sub`/`role`/`admin`/`exp` after achieving any signature bypass above. |
| Expiry bypass (no forgery) | Replay a captured, genuinely expired, unmodified token directly against the API. |
| Refresh token abuse | Test reuse after logout/password change; test reuse detection; test scope/audience enforcement on token exchange. |

---

## 3. Complete PortSwigger Web Security Academy JWT Lab Mapping

PortSwigger's JWT topic (`portswigger.net/web-security/jwt`) contains **8
labs** across all three difficulty tiers. This is the complete, officially
correct progression order — solve them in this sequence:

### Apprentice

**1. JWT authentication bypass via unverified signature**
`portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature`
- Maps to: File 05 mechanically (edit `sub` directly), but conceptually
  demonstrates the File 01 §6 verification-flow failure at its root — the
  server never checks the signature at all, so any claim edit succeeds with
  zero forgery technique required.

**2. JWT authentication bypass via flawed signature verification**
`portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification`
- Maps to: File 02, Part A (alg:none). The server specifically mishandles
  unsigned tokens — set `alg` to `none`, strip the signature, edit `sub`.

### Practitioner

**3. JWT authentication bypass via weak signing key**
`portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key`
- Maps to: File 02, Part B in full — hashcat mode 16500 brute-force, then
  jwt_tool to forge a new token with the cracked secret.

**4. JWT authentication bypass via jwk header injection**
`portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection`
- Maps to: File 04, Part A exactly — generate your own key pair, embed the
  public half as `jwk`, sign with your private key.

**5. JWT authentication bypass via jku header injection**
`portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection`
- Maps to: File 04, Part B exactly — host a JWKS on the PortSwigger exploit
  server, point `jku` at it.

**6. JWT authentication bypass via kid header path traversal**
`portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal`
- Maps to: File 04, Part C (traversal variant) — point `kid` at `/dev/null`,
  sign with an empty-string HMAC secret.

### Expert

**7. JWT authentication bypass via algorithm confusion**
`portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion`
- Maps to: File 03, §2 in full — public key is directly exposed via a
  standard endpoint; use it as the HMAC secret for a forged HS256 token.

**8. JWT authentication bypass via algorithm confusion with no exposed key**
`portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key`
- Maps to: File 03, §4 in full — no key is exposed directly; use `sig2n`
  against two legitimately-issued tokens to derive candidate public keys,
  test each empirically, then proceed identically to Lab 7 once the correct
  candidate is identified.

### Honest Gap Disclosure

This series' File 04, Part C also documents a **`kid` SQL injection**
variant, and File 05 documents **expiry-bypass-without-forgery** and
**refresh token abuse** as distinct real-world/API-security concepts. None of
these three have a dedicated, standalone PortSwigger Web Security Academy
lab under the JWT topic as of this writing — they are documented here because
they are well-established techniques you will encounter in real bug bounty
and pentest engagements (and in broader OWASP API Security Top 10 material)
that extend past what the current 8-lab PortSwigger set covers. Don't expect
to find a lab titled exactly for these; treat the labs above as your hands-on
practice ground for the underlying mechanisms, and apply those same
mechanisms to the SQLi/expiry/refresh scenarios when you encounter them in
real targets.

---

## 4. Tooling Quick Reference

| Task | Command |
|---|---|
| Decode any token, no target interaction | `python3 jwt_tool.py <token>` |
| Crack HS256 secret (hashcat) | `hashcat -a 0 -m 16500 jwt.txt wordlist.txt` |
| Crack HS256 secret (jwt_tool) | `python3 jwt_tool.py <token> -C -d wordlist.txt` |
| Forge with known secret | `python3 jwt_tool.py <token> -S hs256 -p "<secret>" -T` |
| alg:none automation | `python3 jwt_tool.py <token> -X a` |
| Algorithm confusion automation | `python3 jwt_tool.py <token> -X k -pk public_key.pem` |
| JWK injection automation | `python3 jwt_tool.py <token> -X i -pk attacker_private.pem` |
| Two-token public key derivation | `docker run --rm -it portswigger/sig2n <token1> <token2>` |
| Manual HMAC verification (sanity check) | `echo -n "<header>.<payload>" \| openssl dgst -sha256 -hmac "<secret>" -binary \| base64` |

Full flag-by-flag explanations for every jwt_tool command above are in File
06 — this table is a lookup aid only, not a replacement for understanding
what each flag does.

---

## 5. Reporting Note (Real-World Framing)

When writing these up for a client report or bug bounty submission, always
state:
1. **Which of the six verification steps (File 01 §6) actually failed** —
   this is the root cause a developer needs to fix, not just "JWT is
   vulnerable."
2. **Whether the fix belongs in application code vs. gateway/WAF
   configuration** — as covered per-file, some classes (weak secrets, header
   injection) have genuine gateway-level mitigations worth recommending,
   while others (algorithm confusion, claim-trust logic) are structurally
   application-layer issues where a WAF recommendation would be misleading.
3. **The realistic blast radius** — a cracked HMAC secret compromises every
   token that secret ever signs, indefinitely, until rotated; a single
   claim-tampering bypass on one endpoint may or may not extend to other
   services depending on whether `aud`/`iss` are properly scoped (File 05).
