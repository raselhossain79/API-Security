# 04 — Header Injection Attacks (JWK Injection, JKU Injection, kid Injection)

> Prerequisite: File 01 §2 (header fields), File 03 (public/private key trust
> model). These attacks target the **key resolution step** of verification —
> "which key should I use to check this signature?" — rather than the
> algorithm-selection step covered in Files 02/03.

---

## Part A — JWK Header Injection

### 1. The Mechanism

The JWS spec permits an optional `jwk` header parameter: the token can carry
its **own** public key, embedded directly, formatted as a JSON Web Key (JWK)
object:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "attacker-key-1",
    "n": "<attacker's modulus, base64url>",
    "e": "AQAB"
  }
}
```

This parameter exists for legitimate cases (e.g., an identity provider rotating
keys frequently and wanting self-describing tokens). The vulnerability is a
**missing trust check**: a correctly implemented server must verify that the
key embedded in `jwk` is one the server *itself already trusts* (e.g., it
matches a `kid` in the server's own pre-approved key store) before using it to
verify the signature. A vulnerable server instead does something like:

```
key = header.jwk           # attacker fully controls this object
verify(token, key)          # verifying the token against a key the attacker chose
```

This is circular and meaningless as a security check: **the attacker is
allowed to supply both the signature and the key used to check that
signature.** Any RSA key pair the attacker generates locally will produce a
signature that verifies successfully against its own embedded public half,
every time, by definition.

### 2. Building the Attack, Piece by Piece

**Step 1 — Generate a fresh RSA key pair locally.**
```bash
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem
```
- `genrsa` generates a new RSA private key.
- `-out attacker_private.pem` writes it to this file.
- `2048` is the key size in bits — 2048 is the practical minimum used in
  testing; the size doesn't need to match the server's key size at all,
  since this is an entirely attacker-owned key pair.
- The second command derives the corresponding public key (`-pubout`) from the
  private key file.

**Step 2 — Convert the public key to JWK format** (Burp's JWT Editor extension
does this automatically via "New RSA Key" → "Generate"; manually, this means
extracting the modulus `n` and exponent `e` from the PEM and base64url-encoding
them per RFC 7518 §6.3).

**Step 3 — Modify the token header** to include the attacker's JWK inline:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": { "kty": "RSA", "kid": "evil-key", "n": "...", "e": "AQAB" }
}
```

**Step 4 — Modify the payload** (e.g., `sub` → `administrator`).

**Step 5 — Sign the new token using the attacker's own private key** — not the
server's key at all:
```bash
python3 jwt_tool.py <token> -X i -pk attacker_private.pem
```
(`-X i` = jwt_tool's built-in **JWK injection exploit mode**; `-pk` supplies
the attacker's private key to sign with. Full flag reference in File 06.)

The server, upon receiving this token, extracts the embedded `jwk` from the
header, converts it to a usable public key object, and verifies the signature
against it — which will always succeed, because the attacker signed with the
matching private half. Verification technically "passes" honestly at the math
level; the flaw is entirely in **which key the server chose to trust**.

---

## Part B — JKU Header Injection

### 1. The Mechanism

`jku` (JWK Set URL) is a variant: instead of embedding the key directly, the
header supplies a **URL** the server should fetch a JWK Set from:

```json
{ "alg": "RS256", "typ": "JWT", "kid": "1", "jku": "https://attacker.exploit-server.net/jwks.json" }
```

If the server fetches whatever URL is given without validating it against a
domain allowlist, the attacker can host their own JWK Set on infrastructure
they control (e.g., a PortSwigger exploit server, or any attacker-owned HTTPS
endpoint) and point the server directly at it.

### 2. Building the Attack, Piece by Piece

**Step 1 — Generate an RSA key pair** (same as Part A, §2 Step 1).

**Step 2 — Host a JWK Set at a URL you control**, containing your public key:
```json
{
  "keys": [
    { "kty": "RSA", "kid": "1", "use": "sig", "alg": "RS256", "n": "...", "e": "AQAB" }
  ]
}
```
Note the `kid` value here should match the `kid` you place in the token header
so the server's lookup-by-`kid`-within-the-fetched-set logic resolves to your
key.

**Step 3 — Set the `jku` header parameter** in the forged token to the URL
hosting this JWK Set.

**Step 4 — Sign the token with your own private key**, same mechanism as Part
A — the server fetches your JWK Set, finds the key matching `kid`, and
verifies against it, succeeding because you hold the matching private key.

### 3. Why This Is Arguably Worse Than JWK Injection
JWK injection at least requires the server to accept a key **embedded in the
token itself** — some implementations do restrict `jwk` but still allow `jku`,
assuming "fetching from a URL" is inherently safer. It isn't, unless the fetch
target is validated against a strict allowlist of the server's own trusted
domains. URL-parsing discrepancies (the same class of bug covered in SSRF
topics) can sometimes bypass a naive domain check even when one exists — e.g.
`https://trusted.com.attacker.net` passing a substring check for
`trusted.com`.

---

## Part C — `kid` Parameter Injection

### 1. The Mechanism

`kid` (Key ID) is meant to help a server pick the right key when multiple are
in use (e.g., during key rotation). The JWS spec deliberately leaves `kid`'s
format undefined — it's just a string the developer chooses to interpret
however they want. This flexibility is exactly the problem: developers often
use it as a **direct lookup value** into a filesystem, database, or key-value
store, without treating it as untrusted input.

### 2. Path Traversal via `kid`

If the server's key-lookup logic does something like:
```
key_path = "/app/keys/" + header.kid
key = read_file(key_path)
```
then an attacker-controlled `kid` can traverse outside the intended keys
directory:
```json
{ "alg": "HS256", "kid": "../../../../dev/null" }
```

**Why `/dev/null` specifically:** on Unix-like systems, reading this file
always returns an **empty byte string**. If the server's logic falls back to
using whatever bytes were "read as the key" for HMAC verification, the
effective key becomes an empty string — a value the attacker also knows and
can sign with directly:
```bash
# Sign the tampered token using an empty string as the HMAC secret
python3 jwt_tool.py <token> -S hs256 -p "" -pc sub -pv administrator
```
- `-S hs256` — sign using HMAC-SHA256.
- `-p ""` — the empty string, matching the empty content of `/dev/null`.
- `-pc sub -pv administrator` — **payload claim** / **payload value**: tells
  jwt_tool to set the `sub` claim to `administrator` before signing (full
  reference in File 06).

In practice via Burp's JWT Editor: create a new symmetric key, set its `k`
value to an empty string, set `kid` in the header to the traversal path, sign
with that empty-string key, "Don't modify header" selected so your `kid`
survives into the final token.

Other traversal targets worth testing beyond `/dev/null`: any file whose
content is fixed and guessable (e.g., a static file the attacker uploaded
elsewhere on the same server if a file-upload vector exists, effectively
letting the attacker choose their own "key" content entirely).

### 3. SQL Injection via `kid`

If the lookup instead queries a database:
```
key = db.query("SELECT key_value FROM keys WHERE kid = '" + header.kid + "'")
```
this is standard SQL injection, just delivered through a JWT header field
instead of a URL parameter or form field. A classic UNION-based payload:
```json
{ "alg": "HS256", "kid": "x' UNION SELECT 'attacker_known_secret' -- -" }
```
Breaking this down:
- `x'` closes the intended string literal early.
- `UNION SELECT 'attacker_known_secret'` forces the query to instead return a
  key value the attacker chose and already knows, in the same column position
  the application expects the real key value in.
- `-- -` comments out the rest of the original query (the closing quote and
  any trailing SQL) so the statement remains syntactically valid.

If successful, the application will use `attacker_known_secret` as the HMAC
key to verify the token — which the attacker can then sign with directly,
identical mechanically to the empty-string case above. This should be treated
and tested using the same systematic SQLi methodology as any other injection
point (error-based, boolean-based, time-based confirmation) — the fact that
the injection point is a JWT header rather than a query string changes nothing
about the underlying technique, only where you deliver the payload.

---

## WAF / API Gateway Considerations for This Topic

This class is **highly relevant** to gateway/WAF-level defense, more so than
algorithm confusion, because the malicious data lives in a structurally
identifiable header field rather than being indistinguishable normal traffic.

**How WAFs/API gateways typically try to detect this pattern:**
- Signature-based rules flagging the presence of a `jwk` or `jku` parameter in
  a decoded JWT header at all, since legitimate use of client-embedded keys or
  externally-fetched key sets is comparatively rare in most APIs — some
  gateways block these parameters outright by default policy.
- Rules detecting path traversal sequences (`../`, URL-encoded `%2e%2e%2f`,
  double-encoded variants) inside the decoded `kid` value specifically.
- Rules detecting classic SQLi markers (`'`, `UNION`, `--`, `/*`) inside the
  decoded `kid` value, same signature families used for traditional SQLi
  detection elsewhere in the WAF.
- Domain allowlisting enforced at the gateway layer for any outbound fetch
  triggered by a `jku`/`x5u` value, before the request ever reaches
  application code that would perform the fetch.

**Realistic bypass considerations:**
- All of these payloads live **inside a base64url-encoded JWT segment** — a
  WAF that only pattern-matches raw request bytes without decoding the JWT
  header first will miss every one of these payloads entirely, since
  `../../../dev/null` and `' UNION SELECT` don't appear anywhere in plaintext
  in the actual HTTP request, only after base64url-decoding the header
  segment. This is the single biggest realistic gap: many WAF rule sets are
  written for plaintext parameters and never account for JWT-specific
  decode-then-inspect logic.
- Double URL-encoding, alternate traversal encodings (`..%c0%af`, overlong
  UTF-8 sequences), and case variation can evade traversal-specific signature
  rules even where JWT-aware decoding is present but the traversal-detection
  regex itself is narrow.
- For `jku`, URL-parsing discrepancies (mismatched host parsing between the
  WAF's URL parser and the application's actual HTTP client library) are the
  same class of bypass used against SSRF domain allowlists — a payload like
  `https://trusted-domain.com@attacker.net/` or
  `https://attacker.net/trusted-domain.com` can pass a naive substring or
  prefix check while actually resolving to attacker infrastructure.
- SQLi payloads inside `kid` can use the full range of standard SQLi WAF
  evasion techniques (inline comments, alternate whitespace, case variation,
  encoding) — nothing about the JWT delivery context weakens or strengthens
  those evasions beyond the base64 decoding gap noted above.

---

## PortSwigger Labs Relevant to This File

- **JWT authentication bypass via jwk header injection** (Practitioner)
- **JWT authentication bypass via jku header injection** (Practitioner)
- **JWT authentication bypass via kid header path traversal** (Practitioner)

(Full progression and exact URLs are in File 07. Note PortSwigger's official
lab set does not include a dedicated `kid`-SQLi lab — that variant is
documented here as a well-established real-world/CTF technique extending the
same `kid` trust flaw; treat it as an extension of the path-traversal lab's
underlying vulnerability class, not an official PortSwigger lab title.)

## Real-World Note

`jwk`/`jku` injection findings are common in identity-provider-style services
that were built to support flexible key rotation for multiple client
applications — the flexibility that makes multi-tenant JWT issuance convenient
is the same flexibility that makes trust-checking easy to get wrong. `kid`
injection (both traversal and SQLi variants) is disproportionately found in
custom-built auth middleware where a developer treated `kid` as an internal,
trusted identifier rather than recognizing it as fully attacker-controlled
input arriving with every single request.
