# 06 — Complete jwt_tool Usage Guide (Every Flag, Every Mode)

> This file is a standalone reference. Individual flags were introduced
> piece-by-piece in Files 02–05 alongside the attacks they support; this file
> consolidates and expands on every flag so you have one place to look things
> up during an actual engagement.

`jwt_tool` (by ticarpi, https://github.com/ticarpi/jwt_tool) is a Python
utility for parsing, tampering with, forging, and testing JSON Web Tokens.

---

## 1. Installation and Basic Invocation

```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip3 install -r requirements.txt --break-system-packages
python3 jwt_tool.py -h
```
- `git clone` — retrieves the tool's source from its repository.
- `pip3 install -r requirements.txt` — installs Python dependencies
  (cryptography libraries, termcolor, etc.) the tool needs.
- `--break-system-packages` — required on newer Debian/Ubuntu-based systems
  that block system-wide pip installs by default (PEP 668); tells pip to
  proceed anyway inside this environment.
- `-h` — display the built-in help/usage text.

Basic invocation always takes the target token as the first positional
argument:
```bash
python3 jwt_tool.py <token> [mode flags...]
```

---

## 2. Core Modes (`-M`)

jwt_tool organizes its primary operations into named modes via `-M`:

| Mode value | Meaning |
|---|---|
| `-M pb` | **Playbook scan** — runs a full automated series of common JWT attacks/misconfigurations against a live target (requires request details via `-t`/`-rh`/`-cc`, see §5). This is the closest thing to an "automatic exploit everything" mode and is the best starting point on an unfamiliar target. |
| `-M at` | **All Tests** scan — similar automated sweep focused specifically on algorithm/signature-related misconfigurations (alg:none variants, common weak secrets, etc.) without needing full live-request context. |
| `-M er` | **Error/Exception** mode — deliberately sends malformed tokens (corrupted structure, invalid base64, wrong segment counts) to observe how the target's error handling behaves; useful for information disclosure and fingerprinting the underlying JWT library from its error messages/stack traces. |

---

## 3. Decoding and Inspection (No Target Interaction)

```bash
python3 jwt_tool.py <token>
```
Run with **no additional flags**, jwt_tool simply parses and pretty-prints the
header and payload of the supplied token — equivalent to manually reversing
File 01 §5's base64url decoding, but automated and formatted. Always start
here on a new token before doing anything else, to see every header parameter
(`alg`, `kid`, `jwk`, `jku`, etc.) and every claim at a glance.

---

## 4. Tampering and Forging Flags

| Flag | Meaning |
|---|---|
| `-T` | **Tamper mode** — opens an interactive prompt letting you select and edit individual header fields and payload claims one at a time, without hand-editing raw JSON and re-encoding yourself. Ends with an option to sign the result. |
| `-I` | **Injection mode shortcut** — a faster non-interactive way to inject a single claim value directly from the command line, typically combined with `-pc`/`-pv` below. |
| `-pc <claim>` | **Payload claim** — specifies which claim name to target for injection (e.g. `-pc sub`). Used together with `-pv`. |
| `-pv <value>` | **Payload value** — the new value to set for the claim named in `-pc` (e.g. `-pv administrator`). |
| `-hc <header_claim>` | **Header claim** — same concept as `-pc` but targets a header field instead of a payload claim (e.g. `-hc kid`). |
| `-hv <value>` | **Header value** — the new value for the header field named in `-hc`. |

Example — set `sub` to `administrator` non-interactively:
```bash
python3 jwt_tool.py <token> -I -pc sub -pv administrator -S hs256 -p "known_secret"
```

---

## 5. Signing Flags

| Flag | Meaning |
|---|---|
| `-S <alg>` | **Sign mode** — specifies the algorithm to use when producing the new signature. Accepted values include `hs256`, `hs384`, `hs512`, `rs256`, `rs384`, `rs512`, `es256`, `none`. |
| `-S none` | Explicitly signs using the `none` algorithm — i.e., produces a token with `alg: none` and an empty signature segment, automating the File 02 Part A attack. |
| `-p "<secret>"` | **Passphrase** — the HMAC secret string to sign with, used with `-S hs256`/`hs384`/`hs512`. This is the value recovered from cracking (File 02) or the value derived during algorithm confusion (File 03, where this is the RSA public key's byte content rather than a human secret). |
| `-pk <keyfile>` | **Private/public key file** — path to a PEM-format key file, used with `-S rs256`/etc. for genuine asymmetric signing, or supplied as the confusion-attack key material with the exploit modes in §7. |
| `-b` | **Blank/empty signature** — forces an empty signature segment regardless of algorithm, useful for manually testing signature-stripping behavior distinct from a full `-S none` re-sign. |

---

## 6. Cracking Flags

| Flag | Meaning |
|---|---|
| `-C` | **Crack mode** — attempts to brute-force the HMAC secret used to sign the supplied token. |
| `-d <wordlist>` | **Dictionary file** — path to the wordlist used during crack mode; each line is tried as a candidate secret. |
| `-cv <value>` | **Crack value** — supply a single specific candidate secret to test directly, rather than an entire wordlist (useful for quickly confirming a suspected secret without a full dictionary run). |

Example (identical to the one introduced in File 02):
```bash
python3 jwt_tool.py <token> -C -d wordlist.txt
```

---

## 7. Exploit Modes (`-X`)

These are jwt_tool's purpose-built, named attack automations — each one
encapsulates a full attack chain from Files 02–04 into a single flag.

| Flag | Meaning | Corresponds to |
|---|---|---|
| `-X a` | **alg:none variants** — automatically tries the full set of case/format variants of the `none` algorithm (`none`, `None`, `NONE`, `nOnE`, etc.) against the target. | File 02, Part A |
| `-X n` | **Null signature** — sends the token with the signature segment entirely blanked out without altering `alg`, to test if the server has a separate flaw accepting empty signatures regardless of declared algorithm. | File 02, Part A (variant) |
| `-X k` | **Known algorithm/key confusion** — automates the RS256→HS256 substitution attack, using a supplied public key (`-pk`) as the HMAC secret. | File 03 |
| `-X i` | **JWK header injection** — automates embedding an attacker-generated JWK into the header and signing with the matching private key (`-pk`). | File 04, Part A |
| `-X s` | **Spoof JWKS (jku injection helper)** — assists in generating a JWK Set payload suitable for hosting at an attacker-controlled URL, to pair with a manually-set `jku` header value. | File 04, Part B |
| `-X t` | **Timestamp tampering** — automates common `exp`/`iat`/`nbf` manipulation attempts (extending expiry, backdating issue time) in one pass. | File 05, §3 |

Example combining an exploit mode with claim tampering:
```bash
python3 jwt_tool.py <token> -X k -pk server_public_key.pem -I -pc sub -pv administrator
```
This reads as: use algorithm confusion (`-X k`) with the given public key as
the substitute HMAC secret, while also injecting (`-I`) a change to the `sub`
claim (`-pc sub -pv administrator`) into the same forged token.

---

## 8. Live-Target Testing Flags (for `-M pb` / direct request replay)

| Flag | Meaning |
|---|---|
| `-t <url>` | **Target URL** — the live endpoint jwt_tool should send crafted tokens to directly, rather than just printing them for you to paste elsewhere. |
| `-rh "<header>: <value>"` | **Request header** — add a custom header to the outgoing test request (e.g. to place the tampered token into a custom `Authorization` or app-specific header rather than a cookie). |
| `-cc "<name>=<value>"` | **Cookie** — set a cookie on the outgoing test request, for apps that transmit the JWT via cookie rather than a header. |
| `-rc "<string>"` | **Response check (content)** — a string to search for in the response body that indicates success (e.g. a string only present on an authenticated admin page), letting jwt_tool auto-flag which tampered variants actually worked. |
| `-rs <code>` | **Response check (status code)** — an HTTP status code (e.g. `200`) to treat as a success indicator instead of/alongside `-rc`. |

Example — full live playbook scan against a target endpoint, checking cookie
delivery and a success string:
```bash
python3 jwt_tool.py <token> -t https://target.example/api/profile \
  -M pb -cc "session=<token>" -rc "\"role\":\"admin\""
```

---

## 9. Output/Verbosity Flags

| Flag | Meaning |
|---|---|
| `-v` | **Verbose** — print additional diagnostic detail about each step jwt_tool takes internally, useful when a crafted token isn't behaving as expected and you need to see exactly what was generated. |
| `-nt` | **No tests** — used with certain scan modes to skip the built-in test payloads and only perform the decode/parse step. |

---

## Quick Reference — Flag-to-File Map

| Attack | Primary jwt_tool invocation | Detailed in |
|---|---|---|
| alg:none | `-X a` or `-S none` | File 02, Part A |
| Weak secret crack + forge | `-C -d wordlist.txt` then `-S hs256 -p "<secret>" -T` | File 02, Part B |
| Algorithm confusion | `-X k -pk public_key.pem` | File 03 |
| JWK header injection | `-X i -pk attacker_private.pem` | File 04, Part A |
| JKU header injection | `-X s` (JWKS generation helper) + manual `-hc jku -hv <url>` | File 04, Part B |
| kid path traversal / SQLi | `-hc kid -hv "<payload>"` + `-S hs256 -p "<resolved key value>"` | File 04, Part C |
| Claim manipulation | `-I -pc <claim> -pv <value>` or `-T` | File 05 |
| Expiry tampering | `-X t` | File 05, §3 |

---

## Real-World Note

In a real engagement, the actual workflow is rarely "run one flag and get a
shell." It's closer to: decode the token first with no flags to see every
header parameter, form a hypothesis from File 01–05's mechanisms about which
attack class is plausible given what you see (a `kid` parameter suggests File
04; a `jku`/`jwk` parameter suggests File 04's URL/embedded-key variants; a
plain HS256 token with no unusual header fields suggests File 02's weak-secret
path is the most likely starting point), then reach for the specific flag
combination that tests that hypothesis — rather than blindly running every
`-X` mode against a production target, which is noisy, easily logged, and
unprofessional on a live engagement outside an explicitly authorized,
low-noise-tolerant scope.
