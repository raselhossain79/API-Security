# 05 — JWT Claim Manipulation, Token Expiry Bypass, and Refresh Token Abuse

> Prerequisite: File 01 §3 (claims), and at least one of Files 02–04 — claim
> manipulation is the **payload** side of an attack; it only becomes exploitable
> once you've achieved one of the signature-bypass or forgery techniques
> covered in those files. This file is "what do I change" — Files 02–04 are
> "how do I make the server accept the change."

---

## 1. The Mechanism: Why Claims Are Just Trusted JSON

As established in File 01 §3, the payload is base64url-**encoded**, not
encrypted. Every claim is fully readable and, once you can produce a signature
the server accepts (via any technique from Files 02–04), fully writable too.
The vulnerability being exploited here is almost always an **authorization
logic flaw downstream of authentication**: the application reads a claim
directly out of the token and uses it as the sole basis for an access-control
decision, e.g.:

```
if (decoded_token.role == "admin") { grant_admin_access(); }
```

This is dangerous for two independent reasons that are worth separating:
1. If signature verification is broken (Files 02–04), the attacker can set
   `role` to anything.
2. Even with a technically valid signature, if the **application**, not just
   the *token issuer*, ever lets a user influence which claims get embedded at
   issuance time (e.g. a registration endpoint that naively copies
   client-submitted JSON fields into the token payload), privilege escalation
   is possible without breaking any cryptography at all — this is a **mass
   assignment**-flavored bug wearing a JWT costume, not a JWT bug per se, but
   it's worth explicitly distinguishing from true signature-bypass claim
   tampering.

---

## 2. Claim Manipulation, Piece by Piece

Given any technique from Files 02–04 that lets you produce an
accepted signature, the actual edit is always the same three steps:

**Step 1 — Decode the payload segment** (File 01 §5 — reverse base64url,
re-pad, decode).

**Step 2 — Edit the target claim(s).** Common high-value targets:

| Claim | Typical exploitation goal |
|---|---|
| `sub` | Change to another username (e.g. `administrator`) to impersonate that user's session. |
| `role` / `isAdmin` / `admin` / `permissions` | Elevate privilege directly if the app trusts this claim for authorization. |
| `exp` | Extend far into the future to prevent the token from ever expiring (see §3 below). |
| `iss` | If the app trusts tokens from multiple issuers without properly scoping trust, forging a token that claims to be from a more-trusted issuer. |
| `aud` | If a token issued for one API/service can be replayed against another that shares the same signing key but fails to check `aud`, this widens the blast radius of a single compromised token across services. |

**Step 3 — Re-encode and re-sign.** Re-base64url-encode the modified JSON
(File 01 §5), reassemble `header.payload.` and produce a new signature using
whichever technique from Files 02–04 is applicable to this target (weak
secret, algorithm confusion, or header injection).

**A note on combining techniques:** in a real engagement you typically chain
one signature-bypass technique with one or more of these claim edits in the
*same* forged token — e.g., confirm the secret is crackable (File 02), crack
it, then use that secret to sign a token where you've simultaneously changed
`sub` to `administrator` **and** extended `exp`. jwt_tool's tamper mode
(`-T`, File 06) is built specifically to let you edit several claims in one
pass before signing, rather than repeating the encode/sign cycle per claim.

---

## 3. Token Expiry Bypass

### 3.1 Simple `exp` Extension (requires a signature-bypass technique)
If you can forge a valid signature by any means, extending `exp` to a Unix
timestamp far in the future removes the session-timeout mechanism entirely.
This is usually paired with another claim change (e.g. privilege escalation)
rather than tested in isolation, since a longer-lived low-privilege token
isn't itself very interesting.

### 3.2 Missing Server-Side Enforcement (no forgery needed)
A distinct and often more directly exploitable bug: some implementations
only check `exp` in the **client-side application logic** (e.g. a
single-page app hiding the "logout" state once it locally detects an expired
token) while the **API backend never re-validates `exp` on incoming
requests at all.** In this case, an already-issued, validly-signed, genuinely
expired token continues to work indefinitely when replayed directly against
the API — no signature tampering is needed, only a captured old token. Test
this explicitly and separately from forgery-based bypass: capture a token,
wait for it to pass its `exp` timestamp (or simply note the value and craft a
direct API request after that time), and replay it unmodified against
protected endpoints.

### 3.3 Missing `nbf`/Clock-Skew Handling
Less commonly exploitable directly, but worth checking: some
implementations allow a generous clock-skew tolerance (e.g. accepting tokens
up to several minutes before their `iat`/after their `exp`) that can be
abused to extend an effective session window slightly beyond what the
application intends, particularly useful when chained with a race-condition
style attack elsewhere in the app.

---

## 4. Refresh Token Abuse

Refresh tokens exist to let a client obtain a new short-lived access token
without re-authenticating with a password every time. They introduce a
distinct attack surface from access tokens because they're typically
**longer-lived and higher-value** — compromising one gets you a fresh valid
access token indefinitely, not just until the current one expires.

Common abuse patterns worth testing:

- **Refresh token is itself a JWT with weak/no signature verification** — if
  so, every technique in Files 02–04 applies directly to it, and forging a
  refresh token effectively grants indefinite re-authentication as any user.
- **Refresh token not invalidated on logout or password change** — capture a
  refresh token, have the legitimate user "log out" or change their password,
  then attempt to use the old refresh token to mint a new access token. If it
  still works, the server isn't maintaining a revocation list/denylist tied to
  password or session state changes.
- **Refresh token reuse not detected** — a refresh token should typically be
  single-use, rotating into a new refresh token on each use (refresh token
  rotation). If the same refresh token can be replayed multiple times to mint
  multiple valid access tokens concurrently, this indicates no rotation or
  reuse-detection is implemented, which matters significantly if a refresh
  token is ever leaked (e.g. via logs, browser history, or a referrer leak) —
  the leaked token remains usable indefinitely rather than being invalidated
  the moment the legitimate client uses it again.
- **Refresh token scope/audience not enforced** — if a refresh token issued
  for a low-privilege mobile client can be exchanged for an access token
  scoped to an internal admin API, that's a broken `aud`/scope check on the
  token-exchange endpoint itself, distinct from anything in the JWT's
  signature.
- **No claim binding between refresh and access token** — if the refresh
  endpoint accepts an arbitrary `sub` or `role` claim change during the
  exchange (rather than deriving the new access token's claims strictly from
  server-side session/user records), this becomes a direct privilege
  escalation path with no signature forgery required at all.

---

## WAF / API Gateway Considerations for This Topic

Claim manipulation and expiry/refresh abuse sit mostly **downstream of
transport-layer inspection**, so this section explains the limited but real
role gateways play:

- A WAF/API gateway can meaningfully enforce **`exp` validation itself** as a
  defense-in-depth layer — some API gateways decode and check standard claims
  (`exp`, `nbf`, `aud`, `iss`) before forwarding the request to the backend at
  all, which would catch §3.2's missing-backend-enforcement scenario even if
  the application code never checks it. This is a legitimate, commonly
  deployed mitigation, not a bypassable heuristic — worth noting as an
  effective compensating control when recommending fixes.
- However, gateways generally **cannot detect** privilege-escalation-via-claim
  edits (e.g. `role` changed to `admin`) on their own, because a gateway has
  no way to know which claim values are "supposed to" be valid for a given
  authenticated principal — that requires application-level authorization
  logic, which is exactly the layer this vulnerability class lives in. A
  gateway seeing a syntactically well-formed, validly-signed JWT with
  `role: admin` has no basis to flag it as anomalous unless it maintains its
  own out-of-band session/authorization state to cross-check against, which
  most gateways don't do for arbitrary custom claims.
- Refresh token reuse detection is a **backend session-management
  responsibility** (tracking token family/rotation state), not something a
  WAF pattern-matching requests can implement — this is explicitly an
  application/auth-server design decision, so if you're documenting a finding
  here, the remediation belongs in the auth flow, not a gateway rule.

---

## PortSwigger Labs Relevant to This File

Claim manipulation is the payload-editing step embedded inside nearly every
lab in this topic rather than its own standalone lab — every lab listed in
File 07 involves changing `sub` (and in several cases other claims) as part of
the solution, after achieving whatever signature bypass that specific lab
targets. There is no dedicated standalone PortSwigger lab purely for
`exp`-bypass or refresh-token abuse in the JWT topic; those are documented
here as broader real-world/API-security concepts that extend past what the
lab set covers.

## Real-World Note

In production APIs, the single most common finding in this category isn't a
clever cryptographic bypass at all — it's an application trusting a `role` or
`isAdmin` claim for authorization decisions without any additional
server-side check against the actual user record in the database. Whenever
you find a JWT-based API, always test whether authorization decisions are
re-verified against server-side state or derived solely from the token's
claims — the latter pattern means **any** successful signature bypass from
Files 02–04, however minor it initially seems, immediately becomes a full
privilege escalation.
