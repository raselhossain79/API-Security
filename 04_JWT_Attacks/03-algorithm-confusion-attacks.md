# 03 — Algorithm Confusion Attacks (RS256 → HS256, PS256 Variants)

> Prerequisite: File 01, especially §4.1 (HMAC) and §4.2 (RSA). This is the
> most conceptually dense attack in the series — go slowly.

---

## 1. The Core Cryptographic Misunderstanding This Attack Exploits

From File 01:

- **RS256** is asymmetric: a **private key signs**, a **public key verifies**.
  The public key is *meant* to be public — publishing it is not a leak, it's
  the design.
- **HS256** is symmetric: the **same secret** both signs and verifies. Knowing
  the "verification value" is equivalent to knowing the "signing value" —
  there is no asymmetry at all.

**Algorithm confusion happens when a server is written to support both RS256
and HS256 verification, and decides *which one to use* based on the
attacker-controlled `alg` header field** (the same root mistake as File 02's
`alg:none` attack, but applied differently):

```
if header.alg == "RS256":
    verify_rsa(signature, server_public_key)
elif header.alg == "HS256":
    verify_hmac(signature, secret_key)   # secret_key variable reused below
```

The vulnerable implementation pattern looks something like this in many
real libraries' misuse:

```
key = load_key_for_this_token_type()   # returns the RSA public key object
verify(token, key, alg=header.alg)      # alg is attacker-controlled!
```

If the underlying crypto library's HMAC-verify function accepts **any byte
string** as its key argument — and an RSA public key, when serialized (e.g. as
PEM), *is just a byte string* — then the library will happily compute
`HMAC-SHA256(signing_input, public_key_bytes)` and compare it to the attacker's
signature.

### 1.1 Why This "Works" at the Cryptographic Level — Precisely

This is the exact mechanism, step by step:

1. The server's RSA public key is not secret. It's routinely exposed via a
   `/jwks.json` endpoint, embedded in client-side JS, or fetchable from a
   `/certs` or `.well-known` path — that's the *entire point* of asymmetric
   crypto: the public half is safe to publish.
2. The attacker fetches this public key and serializes it into its canonical
   byte representation — almost always **PEM format**
   (`-----BEGIN PUBLIC KEY-----...`).
3. The attacker crafts a new JWT with `alg` changed from `RS256` to `HS256` in
   the header.
4. The attacker signs this new token using **HMAC-SHA256**, with the **exact
   PEM bytes of the public key** used as the HMAC secret key:
   ```
   forged_signature = HMAC-SHA256(new_signing_input, rsa_public_key_pem_bytes)
   ```
5. The server receives the token, reads `alg: HS256` from the header (the
   root design flaw — see File 01 §2), and — because it still resolves "the
   key for this session type" to the *same* public key object it always uses
   — calls `HMAC-SHA256(signing_input, that_same_key_bytes)` to verify.
6. Since the attacker used the exact same byte string as the HMAC secret that
   the server is now (incorrectly) using as an HMAC secret too, the
   recomputed HMAC on the server side is **byte-for-byte identical** to the
   attacker's forged signature. Verification passes.

**The cryptographic primitive (HMAC) is not broken.** HMAC-SHA256 is doing
exactly what it's designed to do: prove that both sides used the same secret
key. The vulnerability is that a value the server intentionally made public
(the RSA public key) got fed into a primitive whose entire security model
depends on the key being *secret*. This is a **type confusion between "a value
safe to disclose" and "a value that must be private"** — not a math weakness.

### 1.2 Why "Just Use the Public Key as the Secret" Is Non-Obvious to a Server

This attack is only possible when the developer's code shares a single "get
the verification key for this token" function across both algorithm branches
without checking that the *type* of key matches the *type* the algorithm
expects (asymmetric public key object vs. raw symmetric secret bytes). A
correctly written server would either:
- Hard-code the expected algorithm server-side (never read `alg` from the
  token) — same fix as File 02, or
- Maintain fully separate key stores/types for symmetric vs. asymmetric
  algorithms, so an RSA public key object could never even be *passed into* an
  HMAC function without an explicit, deliberate type conversion.

---

## 2. Building the Attack, Piece by Piece

### Step 1 — Obtain the server's RSA public key

Common sources:
- A dedicated JWKS endpoint, e.g. `GET /.well-known/jwks.json` or `/jwks`.
- A `jku` header value in a legitimately issued token, pointing to the key set
  (see File 04 for what happens when that URL isn't validated).
- Sometimes embedded directly in application source/config exposed by another
  bug (source map leak, `.git` exposure, etc.).
- If genuinely unavailable, the **`sig2n` derivation technique** (§4 below)
  can recover a mathematically valid public key using only two tokens signed
  by the server — no direct key exposure needed at all.

### Step 2 — Convert the key to its exact canonical byte form

Almost always PEM (X.509 SubjectPublicKeyInfo format):
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```
**This exact byte string — including header/footer lines and line breaks
exactly as formatted — becomes the HMAC secret.** Any deviation (different
line-wrap width, missing trailing newline, DER vs. PEM) produces a different
HMAC key and therefore a signature the server won't recognize. This is the
single most common practical failure point when reproducing this attack
manually — always use the tool that extracted the key, don't hand-retype it.

### Step 3 — Modify the header

```json
{"alg": "HS256", "typ": "JWT"}
```
(originally `"RS256"`)

### Step 4 — Modify the payload

Change `sub` to `administrator`, adjust `exp` if needed (mechanically
identical to File 02/05 — edit JSON, re-base64url-encode).

### Step 5 — Sign using HMAC-SHA256 with the PEM bytes as the key

Using Burp's JWT Editor extension (recommended, avoids manual encoding errors):
1. Go to the **JWT Editor Keys** tab → **New Symmetric Key** → **Generate**.
2. Replace the generated `k` value with the **base64url-encoded raw bytes of
   the PEM public key** (this is what makes the "symmetric key" actually be
   the RSA public key underneath).
3. In the token editor, set `alg` to `HS256`, edit the payload claims, then
   click **Sign**, selecting the symmetric key created above, with
   **"Don't modify header"** selected so the `kid` (if present) is preserved
   exactly as the server expects for its key-lookup logic.

Command-line equivalent using jwt_tool (see File 06 for full flag breakdown):
```bash
python3 jwt_tool.py <original_token> -X k -pk public_key.pem
```
`-X k` selects the **known algorithm/key-confusion exploit mode**, and `-pk`
supplies the public key file jwt_tool will use as the HMAC secret internally.

---

## 3. PS256 and Other Variant Considerations

`PS256` (RSASSA-PSS) is also asymmetric, using the same public/private trust
model as RS256 but with a probabilistic padding scheme (PSS) instead of
PKCS#1 v1.5. The **confusion attack itself is identical in mechanism** — the
target public key is still just bytes, and if a server's verification
dispatch trusts the attacker's `alg` field and shares key-resolution logic
across `PS256`/`HS256` the same way it does for `RS256`/`HS256`, the exact same
substitution works. The only difference worth testing for in practice is
whether the target's JWT library even implements a code path for `PS256` →
`HS256` confusion at all (some libraries strictly reject any confusion between
PSS and HMAC families by design), so treat this as "same technique, verify the
library supports the crossover" rather than a separate technique.

---

## 4. When the Public Key Isn't Exposed — `sig2n` Derivation

Some targets never expose their RSA public key directly, but algorithm
confusion may still be exploitable if you can derive a mathematically valid
public key from **two JWTs signed with the same private key**.

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

- `<token1>` and `<token2>` — two **different, legitimately-issued, validly
  signed** RS256 tokens from the same server (e.g., log in twice, or from two
  different sessions). The tool uses number-theoretic properties of RSA
  signatures (specifically, computing the GCD of `signature^e - message` across
  both tokens) to calculate one or more candidate values of the modulus `n`
  that the server's key pair could be using.
- The tool outputs several **candidate X.509 public keys**, since the math can
  yield more than one mathematically possible value — only one will actually
  match the server's real key.
- Each candidate must be **tested empirically**: sign a tampered token with
  each candidate key (used as an HMAC secret, exactly as in §2 above) and
  submit it to a low-privilege endpoint (e.g. `/my-account`). The correct
  candidate is the one that doesn't get rejected.

This does not "break" RSA or recover the private key — it recovers enough of
the *public* key's mathematical structure to reconstruct it from just two
signature samples, which is then used the same way a directly-published public
key would be.

---

## WAF / API Gateway Considerations for This Topic

**Explicitly noted rather than silently omitted:** WAF/API-gateway-level
defenses are **not meaningfully relevant to this specific vulnerability class**,
and here is why:

- The exploit condition is a **server-side application/library logic flaw** —
  specifically, sharing key-resolution logic across algorithm families and
  trusting the client-supplied `alg` field to pick between them. A WAF sits in
  front of the application and inspects requests as opaque strings/patterns; it
  has no visibility into how the backend's JWT library internally resolves keys
  per algorithm, so it structurally cannot detect or prevent the actual root
  cause.
- A forged HS256 token produced by this attack is, syntactically, an entirely
  normal, well-formed JWT — same three segments, same base64url encoding,
  `alg: HS256` is a completely legitimate value seen in countless benign
  requests. There is no distinguishing request-level signature a gateway could
  reliably pattern-match on without an unacceptable false-positive rate (you'd
  have to block all `HS256` tokens outright, which breaks any legitimate use
  of that algorithm on the same system).
- The only durable fix lives in the application code: hard-code the expected
  algorithm per key type server-side, and use libraries/APIs that structurally
  prevent an RSA public key object from ever being accepted where a raw HMAC
  secret is expected (i.e., strict typing between key classes, not just a
  runtime string comparison).

If you are documenting this for a client report, it's worth stating this
explicitly: recommend **library/code-level remediation**, not a WAF rule, and
flag any reliance on gateway-level JWT filtering for this specific class as a
false sense of security.

---

## PortSwigger Labs Relevant to This File

- **JWT authentication bypass via algorithm confusion** (Expert) — public key
  obtainable directly via an exposed endpoint.
- **JWT authentication bypass via algorithm confusion with no exposed key**
  (Expert) — requires the `sig2n` derivation technique from §4.

(Full progression and exact URLs are in File 07.)

## Real-World Note

Algorithm confusion is one of the higher-skill, higher-payout findings in real
JWT-based auth systems precisely because it requires understanding the
underlying crypto model rather than just editing JSON fields — it shows up
disproportionately in custom auth microservices and API gateways that
implement their own "flexible" JWT verification supporting multiple algorithms
for legacy compatibility reasons. Modern, well-maintained JWT libraries
(recent PyJWT, node-jsonwebtoken, jose, Nimbus JOSE+JWT) have largely closed
this class by requiring the caller to explicitly pass an algorithm allowlist
into the verify function and by using distinct, non-interchangeable key
object types for symmetric vs. asymmetric algorithms — but plenty of
production systems still run older versions or hand-rolled wrappers around
them.
