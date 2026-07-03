# 04 — Header Injection Attacks: JWK and kid

## Prerequisite

Read file 1 (section 2, the header structure) first. Both attacks in this
file abuse optional header fields (`jwk` and `kid`) that a server uses to
decide *which key material* to verify against — and both fail the same way
when that decision is influenced by attacker-controlled input instead of
fixed server-side configuration.

---

## Part A — JWK Header Injection (Embedded Malicious Key)

### Mechanism

The `jwk` header parameter allows a token to carry its **own** public key
directly, inline, as a JSON Web Key object. This is a legitimate spec
feature intended for scenarios where multiple signers exist and the verifier
needs to know which key was used. The vulnerability occurs when a server
blindly trusts whatever key is embedded in the `jwk` header to verify the
token's signature — without checking that this key belongs to a trusted,
pre-registered signer. If the server does that, an attacker can:

1. Generate their own RSA (or EC) key pair.
2. Sign a forged token with their **own private key**.
3. Embed their **own public key** directly into the token's `jwk` header.
4. The server reads the embedded public key from the header and uses *that*
   to verify the signature — which of course succeeds, because the attacker
   signed with the matching private key.

The server ends up verifying the attacker's forged token against a key the
attacker themselves supplied. The signature check technically "passes" — it
just verifies nothing meaningful, because the trust anchor (which key is
legitimate) was never actually established.

### Step-by-Step Exploitation

**Step 1 — Generate an RSA key pair** to sign the forged token:

```bash
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem
```

- `openssl genrsa -out attacker_private.pem 2048` — generates a new 2048-bit
  RSA private key and writes it to `attacker_private.pem`.
- `openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem` —
  derives the corresponding public key from that private key (`-pubout`
  tells openssl to output the public key rather than re-output the private
  key) and saves it separately.

**Step 2 — Tamper the target token's claims** as desired (e.g. `role:admin`).

**Step 3 — Embed your public key into the header as a JWK, and sign with your
private key**, using jwt_tool:

```bash
python3 jwt_tool.py <target_token> -X i -pk attacker_private.pem
```

- `-X i` — jwt_tool's dedicated exploit flag for the **i**njected-JWK attack.
  It automatically: converts `attacker_private.pem`'s public component into
  proper JWK JSON format, embeds it in the token header under the `jwk`
  field, sets a matching `kid` if needed, and signs the payload with the
  attacker's private key.
- `-pk attacker_private.pem` — the attacker-generated private key used both
  to derive the embedded public JWK and to produce the actual signature.

**Step 4 — Send the forged token.** If the server extracts and trusts the
embedded `jwk` for verification rather than checking it against a
pre-registered, trusted key store, the forged token is accepted.

### Why This Is Different From Algorithm Confusion (File 3)

Algorithm confusion (file 3) tricks the server into misusing its **own**
legitimate key under the wrong algorithm. JWK injection instead tricks the
server into trusting a **completely attacker-supplied** key from the start —
no knowledge of the server's real key material is required at all, which
makes it, in some ways, an even more direct bypass when it's present.

---

## Part B — kid (Key ID) Injection

### Mechanism

The `kid` header field tells the verifier which key to use out of a set of
possible keys (common in systems that rotate signing keys or support
multiple signers). The verifier typically does something like:

```
key = lookup_key(token.header.kid)
verify(token, key)
```

The vulnerability occurs when `lookup_key()` uses the attacker-controlled
`kid` value **unsafely** — as a raw filesystem path, or directly inside a
database query — instead of validating it against a fixed allow-list of
known key identifiers.

### B1 — Path Traversal via kid

If `lookup_key()` reads a key file from disk using the `kid` value as (part
of) the file path, an attacker can supply a path traversal sequence to make
the server read an arbitrary, predictable file on disk and use its contents
as the "key" — and then sign the token using that exact same file content as
the HMAC secret, since HMAC will accept any byte string as a key.

**Step 1 — Identify a predictable file on the server** whose content you can
also read or predict yourself. Classic targets:
- `/dev/null` — a zero-byte file. If the server treats a zero-byte read as an
  empty-string key, you can sign with an empty string as the HMAC secret.
- A known static file bundled with the application (e.g. a default config
  file, a static asset with predictable content) that you can also fetch
  directly (e.g. via a public URL) to know its exact byte content.

**Step 2 — Set the `kid` header to a traversal path** pointing at that file:

```json
{
  "alg": "HS256",
  "kid": "../../../../dev/null",
  "typ": "JWT"
}
```

- `../../../../dev/null` — repeated `../` sequences walk up the directory
  tree from wherever the application's key-lookup function starts, to reach
  the filesystem root, then descend into `/dev/null`. The number of `../`
  repetitions needed depends on how deep the application's key directory is;
  over-supplying `../` sequences beyond the root is harmless on Linux (it
  simply stays at `/`), so err on the side of adding extra `../` segments.

**Step 3 — Sign the token using the known content of that file as the HMAC
secret.** For `/dev/null`, the content is empty, so the HMAC key is an empty
string:

```bash
python3 jwt_tool.py <target_token> -X i -ju "kid=../../../../dev/null" -S hs256 -p ""
```

- `-X i` — reuses jwt_tool's injection exploit mode (also used for JWK
  injection above; jwt_tool groups header-injection style attacks under the
  same flag).
- `-ju "kid=../../../../dev/null"` — sets the `kid` header field to the
  traversal path.
- `-S hs256` — sign using HMAC-SHA256 (switching the algorithm to symmetric
  is required here, since we're now supplying a raw secret value, not an
  asymmetric private key).
- `-p ""` — the HMAC secret to sign with; empty string, matching `/dev/null`'s
  content.

### B2 — SQL Injection via kid

If `lookup_key()` instead pulls the key from a database using the `kid` value
directly concatenated into a query (e.g.
`SELECT key_value FROM keys WHERE kid = '<kid>'`), the `kid` field becomes a
classic SQL injection sink — but with an unusual, attacker-favorable
consequence: a successful injection can be used to make the query return a
**known, attacker-chosen value** as the "key," rather than needing to
exfiltrate data through blind/error-based techniques.

**Step 1 — Confirm injectability** with a standard SQLi probe in the `kid`
field (single quote, observe for a 500 error or verification behavior
change):

```json
{ "kid": "test'" }
```

**Step 2 — Use a UNION-based payload to force the lookup to return a value
you control** as the key column:

```
' UNION SELECT 'attacker_known_secret' -- -
```

Full `kid` field value:

```json
{ "kid": "nonexistent' UNION SELECT 'attacker_known_secret'-- -" }
```

- `nonexistent'` — closes out the intended string literal early with an
  unmatched key ID that won't match any real row, so the original half of the
  query returns nothing on its own.
- `UNION SELECT 'attacker_known_secret'` — appends a second query via `UNION`
  that returns the literal string `attacker_known_secret` in the same column
  position the application expects the key value to appear in. Column count
  and types must match the original query — if the original `SELECT`
  returns more than one column, pad with additional `UNION SELECT` values
  (e.g. `UNION SELECT 'attacker_known_secret', NULL-- -`) to match.
- `-- -` — SQL line comment, terminates the rest of the original query
  (anything after the injection point, like a trailing quote from the
  original query string) so it doesn't cause a syntax error. The trailing
  space after `--` is required in some SQL dialects (notably MySQL) for the
  comment to be parsed correctly.

**Step 3 — Sign the token using that known value as the HMAC secret**, since
you dictated exactly what value the database lookup will return:

```bash
python3 jwt_tool.py <target_token> -X i -ju "kid=nonexistent' UNION SELECT 'attacker_known_secret'-- -" -S hs256 -p "attacker_known_secret"
```

## Real-World Notes

- JWK injection is less common than algorithm confusion in the wild because
  it requires the server to accept and trust an *inline* key rather than a
  pre-registered one — many production JWKS implementations correctly ignore
  embedded `jwk` headers and only trust keys from their own configured JWKS
  endpoint. When it does appear, it's usually in custom or early-stage JWT
  implementations that added `jwk` support without adding a trust check.
- `kid` path traversal has shown up in real disclosed reports against
  applications that store per-tenant or per-environment signing keys as
  individual files on disk, keyed by a filename derived from the `kid` claim
  without validation.
- `kid`-based SQL injection is a good example of why every attacker-supplied
  value that flows into a lookup — even ones that look like innocuous
  metadata such as a key identifier — needs to be treated as untrusted input
  and parameterized, not just user-facing form fields.

## PortSwigger Lab Mapping

In official difficulty-progression order:

1. **"JWT authentication bypass via jwk header injection"** — maps directly
   to Part A of this file.
2. **"JWT authentication bypass via jku header injection"** — a closely
   related variant using the `jku` (JWK Set URL) header instead of an inline
   `jwk`; the attacker hosts a malicious JWKS document at a URL they control
   and points the `jku` header at it. Not fully detailed as its own attack in
   this file since the exploitation logic is nearly identical to Part A (host
   your JWK set publicly instead of embedding it inline), but worth
   practicing directly on this lab as a variant.
3. **"JWT authentication bypass via kid header path traversal"** — maps
   directly to Part B1 of this file.

**Honest gap disclosure**: PortSwigger's official JWT lab set does **not**
include a dedicated `kid`-based SQL injection lab. Part B2 of this file is
constructed from real-world disclosed report patterns and general SQL
injection technique (see the separate SQL Injection series in this note
library for full SQLi methodology), not drilled against a PortSwigger lab
environment. If practicing this specific sub-technique hands-on, a
custom-built vulnerable lab or a CTF challenge targeting `kid`-based SQLi is
needed — PortSwigger does not currently provide one.
