# 02 — alg:none Attack and Weak Secret Brute-Forcing

> Prerequisite: File 01 (JWT structure). This file assumes you already understand
> the header, the signing input, and why the signature exists.

---

## Part A — The `alg:none` Attack

### 1. The Broken Mechanism

Recall from File 01, step 2 of correct verification: *"Do not read `alg` from
the header to decide trust."* This attack exists entirely because many JWT
libraries and custom implementations violate that rule — they read `alg` from
the untrusted, attacker-supplied header and then branch their verification
logic based on it:

```
if header.alg == "HS256": verify_hmac(...)
elif header.alg == "RS256": verify_rsa(...)
elif header.alg == "none": skip verification entirely   # <-- the bug
```

The JWS spec does define `"none"` as a legitimate algorithm value for
*unsecured* JWTs. The vulnerability is not that `none` exists — it's that a
server which is supposed to require a trustworthy signature will honor it
anyway, because the client told it to.

### 2. Building the Payload, Piece by Piece

Starting from a legitimate captured token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3aWVuZXIiLCJleHAiOjE3NTAwMDB9.abc123signature
```

**Step 1 — Decode and modify the header.**
Original: `{"alg":"HS256","typ":"JWT"}`
Modified: `{"alg":"none","typ":"JWT"}`

Only the `alg` field changes. Some implementations are case-sensitive-safe by
default, so variants worth testing separately: `none`, `None`, `NONE`, `nOnE`.
This isn't randomness — some parsing libraries lowercase/uppercase-compare the
algorithm string inconsistently, so a case mismatch can either bypass a
denylist check or fail an allowlist check depending on how the library was
written.

**Step 2 — Re-encode the header.**
Base64url-encode the modified JSON (no padding, `+`→`-`, `/`→`_`):
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
```

**Step 3 — Modify the payload as needed** (e.g. change `sub` to
`administrator` — covered mechanically in File 05, but the encoding step is
identical: edit the JSON, re-base64url-encode it).

**Step 4 — Remove the signature, but keep the trailing dot.**
Final token:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiZXhwIjoxNzUwMDAwfQ.
```

Notice the token still has three dot-separated segments in form — the third
segment is simply empty. This matters because a naive split-on-dot parser
still sees `header.payload.` and doesn't error out; it just receives an empty
string for the signature, which the vulnerable code path never inspects.

**Why this works cryptographically:** it doesn't "break" any cryptography at
all — no computation is performed or defeated. The server is executing a code
path where `verify_signature()` is simply never called. This is a **logic
flaw**, not a cryptographic weakness, which is why it's the fastest JWT bug to
test and the most severe when found (full authentication bypass with zero
brute-forcing or key material needed).

### 3. Related library-level variants worth testing
- Some libraries only skip verification if `alg` is exactly `"none"` **and**
  the signature segment is empty — test both together and separately.
- Some accept `none` only if the header also lacks a `kid` — test with and
  without `kid` present.

---

## Part B — Weak Secret Brute-Forcing (HS256)

### 1. The Mechanism Being Attacked

HS256 is symmetric (File 01, §4.1): the same string signs and verifies. If a
developer sets that secret to something short, guessable, or copy-pasted from a
tutorial (`"secret"`, `"changeme"`, `"12345678"`), an attacker who intercepts
**one valid token** can offline-brute-force the secret without touching the
live server at all — this is the same math the server itself performs on every
request, just run locally, millions of times per second, against a wordlist.

This is fundamentally different from the `alg:none` attack: here the
cryptography is sound; the **key management** is what failed.

### 2. Cracking with hashcat — Every Flag Explained

hashcat has a dedicated mode for JWT (HS256/384/512): **mode 16500**.

```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

Breaking down every flag:

| Flag | Meaning |
|---|---|
| `-a 0` | Attack mode `0` = **straight/dictionary attack** — try each word in the wordlist as-is against the hash. (Other modes: `1` = combinator, `3` = brute-force/mask, `6`/`7` = hybrid dictionary+mask — useful if you suspect the secret is a dictionary word plus a suffix like a year.) |
| `-m 16500` | Hash **mode 16500** = JSON Web Token (JWT) mode inside hashcat. This tells hashcat the input format is `header.payload.signature` and how to reconstruct the signing input and compare against HMAC output internally. |
| `jwt.txt` | The file containing the target token, in the exact `header.payload.signature` format hashcat expects. Must contain the *original, unmodified* token — you are cracking the secret used to sign it, not a token you've already tampered with. |
| `wordlist.txt` | The candidate secret list — e.g. `rockyou.txt`, or a small curated list of common JWT secrets (`secret`, `password`, `123456`, `your-256-bit-secret`, company name variants, etc.) |

**Optional but commonly paired flags:**

| Flag | Meaning |
|---|---|
| `-o cracked.txt` | Write the cracked secret to this output file once found. |
| `--force` | Bypass hashcat's hardware/driver sanity warnings (common in VMs or containers without full GPU passthrough). Use only when you understand why the warning appeared — it can also mask a real setup problem. |
| `-r rules/best64.rule` | Apply a **rule file** — a set of text mutation rules (append digits, capitalize, leetspeak, etc.) to each wordlist entry before testing it, dramatically increasing coverage without a bigger wordlist. |
| `--status` | Print periodic progress updates during a long-running crack — useful for large wordlists run unattended. |

**Verifying a candidate secret manually (sanity check, not just trusting
hashcat's output):**
```bash
echo -n "<header>.<payload>" | openssl dgst -sha256 -hmac "candidate_secret" -binary | base64
```
This recomputes the raw HMAC over the signing input using the candidate secret
and openssl directly — if the base64 (adjusted to base64url) output matches the
token's original signature segment, the secret is confirmed correct
independent of any tool.

### 3. Cracking and Exploiting with jwt_tool

`jwt_tool` (by ticarpi) automates both cracking and forging in one workflow.

**Step 1 — Cracking mode:**
```bash
python3 jwt_tool.py <token> -C -d wordlist.txt
```

| Flag | Meaning |
|---|---|
| `<token>` | The captured JWT to attack, passed positionally as the target. |
| `-C` | **Crack mode** — tells jwt_tool to attempt to brute-force the signing secret rather than perform any of its other operations (tampering, scanning, etc.). |
| `-d wordlist.txt` | The **dictionary** file to use for the crack attempt — jwt_tool iterates through it the same conceptual way hashcat does, testing each line as a candidate HMAC secret. |

**Step 2 — Forging a new, validly-signed token once the secret is known:**
```bash
python3 jwt_tool.py <token> -S hs256 -p "cracked_secret" -T
```

| Flag | Meaning |
|---|---|
| `-S hs256` | **Sign mode**, explicitly using the `HS256` algorithm — tells jwt_tool how to compute the new signature (must match what the server expects for that key). |
| `-p "cracked_secret"` | The **payload/passphrase** — in this context, the actual secret string recovered from cracking, used as the HMAC key for signing. |
| `-T` | **Tamper mode** — opens an interactive prompt letting you edit individual claims (e.g. `sub`, `role`, `admin`) before the token is signed, rather than forcing you to hand-edit JSON and re-encode manually. |

The output is a complete, validly-signed JWT — because you now legitimately
possess the same secret the server uses, `HMAC(signing_input, secret)` computed
by jwt_tool will be bit-for-bit identical to what the server computes, so the
signature check in File 01 §6 step 3/4 passes honestly. This is not a bypass of
verification like `alg:none` — it is a full, valid forgery using a stolen key.

### 4. Why This Attack Is More Severe Than It Sounds

Once you have the secret, you don't just get one impersonated token — you can
sign **any** payload with **any** expiry, indefinitely, until the server rotates
the secret. This is a full key compromise, not a single-request bypass.

---

## WAF / API Gateway Considerations for This Topic

This is one of the areas where gateway-level defenses are **genuinely
relevant**, so this section is included in full rather than skipped.

**How WAFs/API Gateways typically try to detect this pattern:**
- Static signature rules looking for the base64url-encoded string
  `eyJhbGciOiJub25lIiwi...` (i.e., `{"alg":"none"` after decoding) appearing in
  the `Authorization` header or cookie value — a very common, low-effort WAF
  rule.
- Rate-limiting or anomaly detection on repeated malformed/rejected JWTs from
  the same source IP, which can catch live online brute-forcing (note: it does
  **not** catch offline hashcat cracking, since that never touches the server
  at all).
- Some API gateways that terminate and re-issue their own JWTs at the edge will
  reject any inbound token whose `alg` doesn't match an explicit allowlist
  before it ever reaches the application layer.

**Realistic bypass considerations:**
- Case variation (`None`, `NONE`) and encoding tricks (extra whitespace inside
  the JSON before encoding, e.g. `{"alg": "none"}` with different spacing —
  which changes the base64url string enough to dodge a naive substring
  signature rule while remaining valid JSON) can evade static pattern rules
  that only match one exact encoded string.
- Because hashcat/jwt_tool cracking happens **entirely offline**, no gateway or
  WAF can observe or rate-limit it — the defense at that stage has to be
  **secret strength**, not request-layer detection. This is a key point to
  raise in a report: recommend a high-entropy secret (256-bit random, not a
  passphrase) as the actual fix, not a WAF rule.
- A gateway that only checks `alg` against an allowlist but still forwards the
  full token to the backend for signature verification provides no protection
  at all if the backend itself has the flawed `alg`-trusting logic described in
  Part A — the fix has to happen at the verification code, not just at the
  edge.

---

## PortSwigger Labs Relevant to This File

- **JWT authentication bypass via unverified signature** (Apprentice) — server
  doesn't check the signature at all, regardless of `alg`.
- **JWT authentication bypass via flawed signature verification** (Apprentice)
  — server is misconfigured to specifically accept unsigned (`alg:none`-style)
  tokens.
- **JWT authentication bypass via weak signing key** (Practitioner) — the
  hashcat/jwt_tool brute-force workflow above, exactly as described.

(Full progression and exact URLs are in File 07.)

## Real-World Note

In real assessments, `alg:none` findings have dropped significantly over the
last several years as major libraries (jjwt, PyJWT, node-jsonwebtoken,
jose) now require the expected algorithm to be explicitly passed into the
verify call and reject `none` by default. It still turns up in **custom,
hand-rolled JWT handling** — especially in internal microservice-to-microservice
auth, older codebases, or IoT/embedded backends where a developer wrote their
own minimal JWT parser without using a maintained library. Weak-secret findings
are still common in real bug bounty programs, especially where a team has
copy-pasted a tutorial's example secret into production and never rotated it.
