# 01 — JWT Structure Deep Dive (Mechanism First)

> Read this file before any of the attack files. Every attack in this series is a
> violation of one of the mechanisms explained here. If you understand this file
> completely, every later exploit will feel like an obvious consequence rather than
> a magic trick.

---

## 1. What a JWT Actually Is

A JSON Web Token (JWT, RFC 7519) is a compact, URL-safe string used to transmit
claims (statements about a user or session) between two parties in a way that can
be **verified** and **trusted**.

A JWT is not encrypted by default. It is **signed**. This distinction is the single
most important fact in this entire series:

- **Encryption** = nobody but the intended recipient can *read* the data.
- **Signing** = anyone can *read* the data, but only the holder of the correct
  secret/private key can produce a signature the server will accept as *valid*.

A standard JWT (a JWS — JSON Web Signature) gives you **integrity and
authentication**, not confidentiality. Anyone who intercepts a JWT can
base64url-decode it and read every claim in plain text. This is by design — it is
not itself a vulnerability. The vulnerability only appears when the server fails
to properly verify the signature, or when the attacker can influence *how* the
server verifies it. That is the theme of every file that follows.

A JWT always has this shape:

```
header.payload.signature
```

Three sections, separated by two literal dot (`.`) characters, each section
base64url-encoded independently.

Real example (RS256):

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJ3aWVuZXIiLCJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc1MDAwMDAwMH0.
LmZ1bGx5X3JhbmRvbV9zaWduYXR1cmVfYnl0ZXNfZ29faGVyZQ
```//line breaks added for readability — the real token is one continuous string

---

## 2. Part 1 — The Header

Decoded, a typical header looks like this:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "d8f2a1e0-4b3c-4a90-9e21-6f9a2c1b7e44"
}
```

| Field  | Meaning | Why it matters for security |
|---|---|---|
| `alg` | The signing algorithm used to produce the signature (e.g. `HS256`, `RS256`, `none`) | The server usually reads `alg` from the *attacker-supplied token itself* to decide which verification routine to run. This is the root cause of nearly every attack in files 02–04. |
| `typ` | Token type, almost always `"JWT"` | Cosmetic, rarely security-relevant. |
| `kid` | Key ID — tells the server *which* key (out of possibly many) to use for verification | If the server uses this value to build a filesystem path, a database query, or a key lookup without strict validation, it becomes an injection point (File 04). |
| `jwk` / `jku` | Optional — an embedded public key or a URL to fetch one from | If the server trusts these without whitelisting, the attacker can supply their own verification key (File 04). |

**Mechanism point:** the header is not protected by anything other than the
signature itself. It is plain, attacker-modifiable JSON before verification
occurs. Every field in the header is a *hint from the client about how to verify
the client's own token*. A secure server should decide independently which
algorithm and key to use for a given session; a vulnerable server *trusts the
header's instructions*. That single design mistake is the common ancestor of
alg:none, algorithm confusion, and header injection attacks.

---

## 3. Part 2 — The Payload (Claims)

The payload is a JSON object of **claims** — key/value statements about the
subject of the token. Claims fall into three categories:

### 3.1 Registered claims (defined by RFC 7519, not mandatory but standardized)

| Claim | Full name | Meaning |
|---|---|---|
| `sub` | Subject | The principal the token is about — typically a username or user ID. Attackers target this directly to impersonate other users (File 05). |
| `iss` | Issuer | Identifies who issued the token (e.g. `"portswigger"`, an auth server URL). Used to prevent tokens from one system being accepted by another. |
| `aud` | Audience | Identifies the intended recipient(s) of the token (e.g. a specific API or service). A token issued for Service A should be rejected by Service B if `aud` is checked properly. |
| `exp` | Expiration Time | A Unix timestamp (seconds since epoch) after which the token MUST be rejected. This is what makes a session "time out." |
| `iat` | Issued At | Unix timestamp of when the token was created. Used for age checks and replay-window logic. |
| `nbf` | Not Before | Token must not be accepted before this timestamp. |
| `jti` | JWT ID | A unique identifier for the token, sometimes used for one-time-use tokens or revocation lists. |

### 3.2 Public claims
Claims registered in the IANA JWT registry or defined collision-resistantly
(namespaced), e.g. `email`, `email_verified`.

### 3.3 Private (custom) claims
Application-specific claims agreed between issuer and consumer, e.g. `role`,
`admin`, `isAdmin`, `permissions`. **These are the highest-value targets for claim
tampering** (File 05) because applications frequently make authorization
decisions directly from them — `if (claims.role == "admin")` — without any
additional server-side check.

**Mechanism point:** the payload is just JSON, base64url-encoded — not
encrypted, not obfuscated. `exp`, `role`, `sub`, and every other claim are fully
attacker-readable and, if signature verification is broken or bypassable,
fully attacker-writable too. The signature is the *only* thing standing between
"readable" and "trustworthy."

---

## 4. Part 3 — The Signature

The signature is computed over the **ASCII bytes of the encoded header and
payload**, joined by a dot — not over the decoded JSON:

```
signing_input = base64url(header) + "." + base64url(payload)
signature     = SIGN(signing_input, key, alg)
```

This is critical: even one byte of whitespace difference in the JSON would
produce a completely different signature, because signing happens on the
already-encoded string, not on a semantic representation of the JSON.

### 4.1 HMAC-based algorithms (HS256 / HS384 / HS512)

Symmetric — the **same secret** both signs and verifies:

```
signature = HMAC-SHA256(signing_input, secret)
```

The server recomputes the HMAC using its stored secret and compares it to the
signature on the incoming token. If they match, the token is trusted. Anyone who
knows `secret` can forge arbitrary tokens — hence weak-secret brute-forcing
(File 02) and algorithm confusion (File 03, where an RSA *public* key gets misused
as this HMAC secret).

### 4.2 RSA-based algorithms (RS256 / RS384 / RS512)

Asymmetric — a **private key signs**, a separate **public key verifies**:

```
signature = RSASSA-PKCS1-v1_5-SIGN(SHA256(signing_input), private_key)
verify    = RSASSA-PKCS1-v1_5-VERIFY(signature, public_key)
```

The public key can be published openly (it often is, via a `/jwks.json` endpoint
or similar) because it can only *verify*, never *forge*. This is the entire point
of asymmetric signing — and the entire reason algorithm confusion attacks are so
severe: they trick the server into treating that same public value as if it were
a shared HMAC secret, which is a symmetric-key operation with completely
different trust assumptions.

### 4.3 ECDSA (ES256 / ES384 / ES512)

Also asymmetric, based on elliptic curve cryptography. Same public/private trust
model as RSA, different underlying math. Not covered in depth here since attacks
against it mirror the RSA algorithm-confusion class conceptually, but ECDSA
signature malleability is a distinct, narrower research area outside this
series' scope.

### 4.4 `none`

A JWS "algorithm" defined by the spec for cases where integrity protection is
deliberately not required — e.g., a token nested inside an already-secure
channel. The signature segment is empty. A server that honors `alg: none` from
an attacker-controlled header for a token that is supposed to be trusted is
misusing a legitimate spec feature outside its intended context (File 02).

---

## 5. Base64url Encoding — The Mechanism, Precisely

JWTs use **base64url**, not standard base64. This distinction matters because it
is why you cannot always paste a JWT segment into a generic base64 decoder
without adjustment.

Standard base64 alphabet includes `+`, `/`, and pads with `=`.
Base64url replaces those characters so the result is safe inside URLs and HTTP
headers without additional escaping:

| Standard base64 | base64url |
|---|---|
| `+` | `-` |
| `/` | `_` |
| `=` padding | omitted entirely |

**How to decode manually, step by step:**

1. Take the segment (e.g. the header `eyJhbGciOiJIUzI1NiJ9`).
2. Replace `-` → `+` and `_` → `/` if present.
3. Re-add `=` padding until the string length is a multiple of 4.
   - length % 4 == 2 → add `==`
   - length % 4 == 3 → add `=`
   - length % 4 == 0 → add nothing
4. Base64-decode the result → raw JSON bytes.

Example:
```
eyJhbGciOiJIUzI1NiJ9
```
Length is 20, already a multiple of 4, no padding needed. Standard base64 decode
gives:
```json
{"alg":"HS256"}
```

**Why `alg: none` still "fits" the format:** removing the signature doesn't break
the encoding rules — the token simply ends with a trailing dot and nothing after
it (`header.payload.`). The structure is still syntactically a valid three-part
JWT; only the semantic guarantee (that it was actually signed) is gone. This is
exactly what File 02 exploits.

---

## 6. Verification Flow a Correctly-Implemented Server Follows

1. Split the token into header, payload, signature on `.` boundaries.
2. Decode the header. **Do not read `alg` from the header to decide trust** —
   instead, look up the expected algorithm/key for this token type from
   **server-side configuration**, independent of anything the client sent.
3. Recompute the signature using the server-selected key and algorithm.
4. Compare signatures using a constant-time comparison.
5. Only if the signature is valid: check `exp`, `nbf`, `iss`, `aud` claims.
6. Only if all of the above pass: trust `sub` and any custom claims for
   authorization decisions.

**Every attack file in this series is a story about a server skipping, trusting
the wrong input for, or getting confused during one of these six steps.** Keep
this list in mind as you read Files 02–05; each attack maps to exactly one
broken step.

---

## Real-World Note

In real bug bounty and pentest engagements, JWT vulnerabilities are almost never
found by "trying alg:none blindly." They are found by:

- Actually decoding the token and reading every claim and header field first.
- Noticing unusual header parameters (`kid`, `jwk`, `jku`, `x5u`, `x5c`) that
  signal the server does dynamic key resolution — which is where injection bugs
  live.
- Checking whether the same signing key/secret is reused across multiple
  services (common in microservice architectures using a shared internal
  auth library) — a leak or weak-secret finding in one service can compromise
  all of them.
- Testing whether `exp` is actually enforced server-side at all (some
  implementations only let the client-side app react to expiry and never
  re-check it on the API).

This file gave you the mechanism. Files 02 onward assume you can decode a token
by hand, identify every header field, and explain in your own words why the
signature step exists at all — because every exploit is really just "how do I
make step 3 or step 4 above pass without knowing the real secret."
