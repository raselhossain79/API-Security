# 03 — Algorithm Confusion Attacks (RS256 → HS256, PS256)

## Prerequisite

Read file 1 (especially section 4, the signature mechanics for HS256 vs
RS256) before this file. This attack only makes sense once you understand
that HS256 is symmetric (one shared secret) and RS256/PS256 are asymmetric
(private key signs, public key verifies).

## Mechanism — Why This Attack Is Possible At All

The vulnerability lives entirely in **verification logic**, not in RSA or
HMAC cryptography being individually broken. A typical vulnerable
verification function looks conceptually like this:

```
function verify(token, key):
    alg = token.header.alg          // attacker-controlled
    if alg == "RS256":
        return rsa_verify(token, key)      // key = public key
    if alg == "HS256":
        return hmac_verify(token, key)     // key = SAME key object, wrong type
```

The bug: the same `key` variable — the server's RSA **public** key — gets
passed into both code paths. When `alg` is `RS256`, that's correct (public
key verifies an RSA signature). But when an attacker sets `alg` to `HS256`,
the function treats that same public key string as an **HMAC secret** instead
of an RSA public key. Since HMAC just needs *some* byte string as the key, it
happily computes `HMAC-SHA256(header.payload, public_key_string)` — and
because the public key is, by design, publicly available, the attacker can
compute that exact HMAC themselves and produce a signature the server will
accept as valid.

The core insight: **the server's asymmetric key was never meant to be secret
(it's the public half) — but the confused verification path treats it as if
it were a shared secret**, collapsing the security guarantee of asymmetric
crypto down to nothing.

## Step-by-Step Exploitation — RS256 to HS256 Confusion

**Step 1 — Obtain the server's RSA public key.** Common sources:
- A `/jwks.json` or `/.well-known/jwks.json` endpoint (standard JWKS
  discovery location).
- The application's TLS certificate, if the same key pair is reused (less
  common but happens).
- Any endpoint that returns the public key directly for client-side
  verification purposes.

**Step 2 — Normalize the public key to exact PEM format**, byte-for-byte,
including header/footer lines and line breaks:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

This exactness matters: HMAC treats the key as a raw byte string, so even a
single extra newline or trailing whitespace character changes the computed
signature. Getting this formatting wrong is the single most common reason
this attack "doesn't work" in practice — always test with the exact string
as returned by the server, not a reformatted copy.

**Step 3 — Rewrite the token header** to declare HS256 instead of RS256:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Step 4 — Tamper the payload** with the claims you want to forge (e.g.
`"role": "admin"`).

**Step 5 — Sign the token using HMAC-SHA256, with the public key string as
the HMAC secret**:

```bash
python3 jwt_tool.py <original_rs256_token> -X k -pk public_key.pem
```

- `-X k` — jwt_tool's dedicated exploit flag for the **k**ey-confusion attack
  (RS256→HS256). It automates steps 3–5: rewrites the header, computes the
  HMAC using the supplied public key as the secret, and outputs the fully
  forged token ready to send.
- `-pk public_key.pem` — path to the file containing the server's public key
  in PEM format, used as the HMAC signing key.

**Step 6 — Replace your session token** with the forged value and send the
request. If the server's verification logic has the confused branch
described above, this token passes as fully valid.

## PS256 Variant — What Changes

PS256 uses RSASSA-PSS instead of PKCS#1 v1.5 padding for the RSA signature,
but from the confusion-attack perspective, **the exploitable logic flaw is
identical**: if the server's verifier passes the same public-key object into
both an asymmetric-PS256 path and a symmetric-HMAC path based on the
attacker-controlled `alg` header, the same public-key-as-HMAC-secret trick
applies. The only practical difference is the target `alg` string you rewrite
the header to (`PS256` → `HS256`) and, if the library distinguishes hash
sizes, potentially matching HS384/HS512 with RS384/RS512 or PS384/PS512
variants — always check which SHA variant the target's RS/PS algorithm uses
and match the HS equivalent (e.g. `RS384` confusion attempts should target
`HS384`, not `HS256`).

```bash
python3 jwt_tool.py <original_ps256_token> -X k -pk public_key.pem -S hs256
```

- `-S hs256` — explicitly forces the output algorithm to `hs256` in cases
  where jwt_tool's auto-detection of the matching HMAC variant needs an
  override.

## Why This Is Not a Failure of RSA or HMAC Cryptography

It's worth being precise here for accurate reporting: this is **not** an RSA
break, not an HMAC break, and not a hash collision. Both algorithms remain
cryptographically sound in isolation. The vulnerability is a **verification
logic design flaw** — specifically, failing to bind the verification code
path strictly to a server-side-configured expected algorithm, and instead
letting attacker-controlled input (the token's own `alg` header) select which
key-type semantics get applied to a given key value. Framing this correctly
in a report matters for credibility with client engineering teams.

## Real-World Notes

- This attack class produced some of the highest-severity JWT bug bounty
  reports on record, because it grants a full authentication bypass with
  zero secrets ever having to leak — the "secret" (public key) was public
  by design the whole time.
- Modern, well-maintained JWT libraries mitigate this by requiring the
  caller to explicitly specify which algorithm(s) are acceptable at
  verification time (an algorithm allow-list), independent of the token's own
  header. Vulnerable code is almost always either an old library version or
  custom-rolled verification logic that trusted the token's `alg` field.
- JWKS endpoints being publicly reachable is normal and expected — the
  vulnerability is never "the public key was exposed," it's always "the
  server treated a public key as if it were secret." Don't misreport JWKS
  exposure alone as the finding; the finding is the confused verification
  logic.

## PortSwigger Lab Mapping

In official difficulty-progression order:

1. **"JWT authentication bypass via algorithm confusion"** — the primary lab
   for the RS256→HS256 confusion attack described in this file.
2. **"JWT authentication bypass via algorithm confusion with no exposed key"**
   — a harder variant of the same lab where the public key is not directly
   exposed via a JWKS endpoint or similar, requiring the attacker to first
   derive/reconstruct the public key (e.g. from a certificate, or by deriving
   it from two signed tokens if the implementation allows key recovery) before
   performing the same confusion attack.

**Honest gap disclosure**: PortSwigger's lab set targets RS256 specifically.
There is no dedicated PortSwigger lab for the PS256 variant — the PS256
material in this file is supplementary, reasoned from the same underlying
logic flaw rather than drilled against a PortSwigger lab environment. Treat
the PS256 section as conceptual extension work, not lab-verified against
PortSwigger's infrastructure.
