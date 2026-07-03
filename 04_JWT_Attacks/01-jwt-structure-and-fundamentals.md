# 01 — JWT Structure and Fundamentals

## Why This File Comes First

Every JWT attack in this series is a consequence of how JWTs are built and
verified. Before touching any exploit, you need to know exactly what the three
parts of a token are, how they're encoded, and what "verification" actually
checks — because every attack technique in files 2 through 5 is really just an
abuse of a gap between what a token *claims* and what the server *checks*.

## 1. What a JWT Actually Is

A JWT (JSON Web Token) is a compact, URL-safe string used to represent claims
(statements about a user or entity) between two parties. It is **not**
encrypted by default — it is only encoded and (usually) signed. This
distinction matters enormously for security: anyone who intercepts a JWT can
read its contents without any key. The only thing a signature protects is
**integrity** (has the token been tampered with), not **confidentiality**
(can an attacker read it).

A JWT has three parts, separated by dots:

```
header.payload.signature
```

Example (truncated for readability):

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Split on the dots, this is three Base64URL-encoded segments.

## 2. Part 1 — The Header

Decoded, the header is a small JSON object:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

- **`alg`** — the algorithm used to sign the token (e.g. `HS256`, `RS256`,
  `PS256`, or `none`). This field is attacker-controlled in the sense that an
  attacker can freely rewrite it before re-encoding the token — the header is
  never itself protected until the whole token is signed. Every algorithm
  attack in this series (file 2 and file 3) hinges on the fact that the server
  trusts this field to decide *how to verify* the signature.
- **`typ`** — declares the token type, almost always `JWT`. Rarely
  security-relevant on its own.
- Optional fields you'll encounter in real tokens: **`kid`** (Key ID — tells
  the server which key to use for verification, covered in depth in file 4),
  and **`jwk`** / **`jku`** (an embedded or referenced JSON Web Key, also
  covered in file 4).

## 3. Part 2 — The Payload

Also a JSON object, this holds the **claims** — the actual data the token is
asserting. Example:

```json
{
  "sub": "1234567890",
  "role": "user",
  "iat": 1751328000,
  "exp": 1751331600
}
```

Common claim types:

- **Registered claims** (defined by the JWT spec, not mandatory but standard):
  - `sub` — subject, usually a user ID
  - `iat` — issued-at timestamp (Unix epoch seconds)
  - `exp` — expiry timestamp (Unix epoch seconds) — this is what file 5's
    expiry-bypass attacks target
  - `iss` — issuer
  - `aud` — audience
- **Public/private claims** — anything the application chooses to add, such as
  `role`, `admin`, `permissions`, `email`. These application-defined claims
  are the ones most commonly targeted by claim manipulation (file 5), because
  developers often trust them directly for authorization decisions.

**Critical mechanism to understand**: the payload is Base64URL-*encoded*, not
encrypted. Decoding it requires no key or secret — it's the same operation as
decoding any Base64 string. This is why you should never put sensitive data
(passwords, secrets, PII beyond what's needed) directly in a JWT payload.

## 4. Part 3 — The Signature

This is the only part of the token that actually requires a secret or private
key to produce. How it's computed depends on the algorithm declared in the
header:

**HS256 (HMAC-SHA256)** — symmetric:
```
signature = HMAC-SHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```
The same secret key is used to both sign and verify. Anyone who knows the
secret can forge valid tokens. This symmetric property is exactly what makes
weak-secret brute-forcing (file 2) and algorithm confusion (file 3) possible.

**RS256 (RSA-SHA256)** — asymmetric:
```
signature = RSA-SIGN-SHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  private_key
)
```
The server signs with a **private** key and verifies with the corresponding
**public** key. The public key can be published openly (it's often exposed at
a `/jwks.json` or `/.well-known/jwks.json` endpoint) because knowing the public
key does not let you forge a signature — under correct verification logic.
File 3 covers exactly how broken verification logic defeats this guarantee.

**PS256 (RSASSA-PSS-SHA256)** — asymmetric, same key relationship as RS256 but
uses a probabilistic padding scheme (RSA-PSS) instead of RSA-PKCS#1 v1.5. From
an attacker's perspective the exploitable *logic* flaws are the same family as
RS256; file 3 covers the PS256-specific nuances.

## 5. Base64URL Encoding — What It Actually Does

Base64URL is a minor variant of standard Base64:

- Standard Base64 alphabet: `A-Z`, `a-z`, `0-9`, `+`, `/`, with `=` padding.
- Base64URL alphabet: same, but `+` → `-` and `/` → `_`, and padding (`=`) is
  typically stripped. This makes the output safe to place directly in a URL
  or HTTP header without additional escaping.

**This is encoding, not encryption or hashing.** It is fully reversible with
no key required. Decoding the header and payload of any JWT is a one-line
operation:

```bash
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
```

- `echo -n` — print the string without a trailing newline (a trailing newline
  would corrupt the Base64 input).
- `base64 -d` — the `-d` flag tells the `base64` utility to decode rather than
  encode.

If you get a padding error, add `=` characters until the string length is a
multiple of 4 — Base64URL strips padding but the decoder still expects
correctly padded input:

```bash
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9==" | base64 -d
```

## 6. How Verification Actually Works (Server-Side)

This is the piece every subsequent attack exploits. When a server receives a
JWT, correct verification should:

1. Split the token into header, payload, signature.
2. Read the `alg` field from the header — but a secure implementation
   **ignores what the token claims and enforces an expected algorithm from
   server-side configuration**, not from the token itself.
3. Recompute the signature over `header.payload` using the correct key and
   algorithm.
4. Compare the recomputed signature to the one in the token (constant-time
   comparison to avoid timing attacks).
5. Separately check claims like `exp`, `nbf`, `aud`, `iss` for validity.

Every attack in this series is a case of step 2 being done wrong — the server
lets the *token* dictate how it should be verified, instead of the server's
own configuration dictating it. That single design mistake, in different
forms, is the root cause of `alg:none` (file 2), algorithm confusion (file 3),
and JWK/kid header injection (file 4).

## Real-World Notes

- JWTs are the dominant authentication mechanism for modern REST and GraphQL
  APIs, mobile app backends, and microservice-to-microservice auth (often
  wrapped as OAuth2 access tokens or OIDC ID tokens).
- Because JWTs are self-contained, many APIs skip server-side session storage
  entirely and trust the token's claims directly — which is exactly why claim
  manipulation and algorithm attacks against JWTs tend to grant full account
  takeover or privilege escalation rather than a lesser bug.
- Bug bounty programs (HackerOne, Bugcrowd) see recurring JWT reports in the
  "Broken Authentication" and "Broken Access Control" categories; the highest
  bounties usually come from algorithm confusion or `alg:none` bypasses that
  lead to admin impersonation, not from claim manipulation alone (since claim
  manipulation typically requires an already-broken signature check to be
  useful).
- Libraries have matured significantly — most modern JWT libraries (e.g.
  `jsonwebtoken` in Node, `PyJWT` in Python, `jjwt` in Java) require the
  verifier to explicitly whitelist accepted algorithms. Vulnerable
  implementations are usually older code, custom JWT handling, or
  misconfigured library usage (e.g. passing the token's own `alg` value into
  the verification call instead of a hardcoded expected algorithm).

## PortSwigger Lab Mapping

File 1 has no dedicated PortSwigger lab of its own — it's prerequisite
knowledge for every lab mapped in files 2 through 5. Before starting those
labs, use PortSwigger's own **"JWT Editor"** Burp extension (BApp Store) to
decode, edit, and re-sign tokens interactively — this is the primary tool used
throughout the rest of this series alongside jwt_tool.
