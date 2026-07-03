# 05 — Claim Manipulation, Expiry Bypass, and Refresh Flow Abuse

## Prerequisite

Read files 1–4 first. This file assumes you already have a way to produce a
token the server will accept as validly signed — either because you
successfully carried out one of the signature-bypass attacks in files 2–4,
or because you legitimately hold a valid low-privilege token and want to
understand what happens once claims inside it are trusted blindly.

## Mechanism — Why Claim Manipulation Is a Distinct Attack Class

Files 2–4 are entirely about defeating the **signature check**. This file is
about what happens **after** that check — specifically, what a server does
with the claims inside a payload it has decided to trust. Even a perfectly,
correctly signed token can lead to authorization bypass if the application
logic trusts application-defined claims (like `role` or `admin`) without
re-validating them against a source of truth (like a database lookup) on
every privileged action. This is a classic case of confusing
**authentication** (who are you — handled by signature verification) with
**authorization** (what are you allowed to do — which should not be decided
solely by a client-editable claim).

## Part A — Direct Claim Manipulation

Once you have a technique from files 2–4 that lets you produce an
acceptably-signed token (or you're demonstrating impact assuming a
successful bypass), the actual claim edits are straightforward JSON changes
to the payload before re-signing:

**Privilege escalation via `role` / `admin` claims:**

```json
{
  "sub": "1001",
  "role": "user",
  "admin": false
}
```
becomes:
```json
{
  "sub": "1001",
  "role": "admin",
  "admin": true
}
```

**Impersonation via `sub` claim:**

```json
{ "sub": "1001" }
```
becomes:
```json
{ "sub": "1" }
```
— testing whether user ID `1` corresponds to an administrative or
first-created account, a common convention worth probing.

**Using jwt_tool's interactive tamper mode to edit and re-sign in one step:**

```bash
python3 jwt_tool.py <valid_token> -T -S hs256 -p "recovered_or_known_secret"
```

- `-T` — tamper mode. jwt_tool decodes the token and presents each claim
  interactively, letting you type a new value for any field before
  re-encoding.
- `-S hs256` — re-sign the tampered token using HS256.
- `-p "recovered_or_known_secret"` — the secret to sign with (from file 2's
  brute-force, or whatever key material the specific bypass technique from
  files 3–4 requires — swap for `-pk` and the relevant flags if using an
  asymmetric-key-based bypass instead).

## Part B — Token Expiry Bypass

### Mechanism

The `exp` claim is a Unix timestamp the server is expected to check against
the current time on every request; if `exp` is in the past, the token should
be rejected regardless of signature validity. Two distinct failure modes
show up in practice:

**B1 — The server doesn't check `exp` at all.** Some implementations
correctly verify the signature but never separately validate the timestamp
claims. In this case, an expired (but still validly signed) token you
already legitimately hold simply continues to work indefinitely — no
tampering needed, just replay the old token.

**B2 — The server checks `exp`, but you can forge a token via files 2–4's
techniques and set `exp` to whatever you want.** Once you have a working
signature bypass, set `exp` to a value far in the future:

```json
{ "exp": 9999999999 }
```

- `9999999999` — Unix epoch timestamp corresponding to November 2286, chosen
  as a conveniently far-future round number well beyond any realistic
  application lifetime, guaranteeing the token never appears expired.

### Testing for B1 Without Any Signature Bypass

This is worth checking independently even when no signature attack is
available, since it requires no forgery at all:

1. Capture a valid token close to its expiry.
2. Wait until after the `exp` timestamp has passed (decode the token per
   file 1 section 5 to know exactly when).
3. Replay the exact same, unmodified token against a protected endpoint.
4. If the request succeeds, the server is not enforcing `exp` server-side —
   a genuine finding on its own, independent of any cryptographic attack.

## Part C — Refresh Token Flow Abuse

### Mechanism

Most production JWT-based auth systems use a **short-lived access token**
(the JWT itself, often expiring in minutes) plus a **long-lived refresh
token** (often an opaque random string, not a JWT, stored server-side) used
to obtain new access tokens without re-authenticating with a password. This
adds attack surface beyond the JWT itself:

**C1 — Refresh token reuse / no rotation.** If a refresh token remains valid
and reusable indefinitely (rather than being invalidated and rotated on each
use), a single stolen refresh token grants effectively unlimited new access
tokens for as long as the attacker wants, even after the legitimate user has
logged out or rotated their password — if the refresh token itself wasn't
also invalidated on those events.

**C2 — Refresh endpoint trusts client-supplied claims.** Test whether the
`/refresh` or `/token` endpoint blindly re-issues a new access token with the
**same claims** as whatever was in the old (possibly tampered) token, rather
than re-deriving claims fresh from the user record in the database. If an
attacker can get even one forged token with elevated claims accepted once
(via files 2–4), and the refresh flow perpetuates those claims into every
subsequent reissued token, the initial bypass becomes persistent — new
tokens keep coming with the escalated privileges baked in, long after the
original forged token itself would have expired.

**Testing steps:**

1. Obtain a legitimate refresh token through normal login.
2. Call the refresh endpoint multiple times in a row with the **same**
   refresh token:
   ```bash
   curl -s -X POST https://target.example/api/token/refresh \
     -H "Content-Type: application/json" \
     -d '{"refresh_token":"<refresh_token_value>"}'
   ```
   - `-X POST` — refresh endpoints are conventionally POST.
   - `-H "Content-Type: application/json"` — declares the body format.
   - `-d '{"refresh_token":"<refresh_token_value>"}'` — the request body
     carrying the refresh token; adjust the field name/shape to match the
     specific API's documented or observed contract.
3. If every call succeeds and returns a new valid access token, the refresh
   token is not being rotated/invalidated on use — log this as a finding
   even before combining it with any claim-manipulation impact.
4. Separately, log out the session (or trigger a password reset) via the
   normal application flow, then retry the same refresh call. If it still
   succeeds, session invalidation isn't properly cascading to refresh tokens.

## Real-World Notes

- Claim manipulation findings are almost always reported as **Broken Access
  Control** (OWASP A01) rather than as a standalone "JWT vulnerability" —
  frame reports this way for clients, since it maps to a category their
  engineering and compliance teams already have a remediation playbook for.
- The single most common real-world variant of Part A is trusting a `role`
  or `permissions` claim set once at login time and never re-checked against
  the database on subsequent privileged actions — meaning a user whose role
  was legitimately downgraded (e.g. after an admin revokes access) can keep
  using their old, still-unexpired token to retain the old privilege level
  until it naturally expires. This is worth testing for even without any
  forgery: log in as an admin, downgrade the account's role via a normal
  admin action, and see if the still-active token retains admin access.
- Refresh token rotation failures are a frequent, high-value finding on
  their own in bug bounty programs, independent of any JWT signature attack
  — because the impact (indefinite persistence of a stolen credential) is
  easy to demonstrate cleanly and clients understand it immediately.

## PortSwigger Lab Mapping

**Honest gap disclosure — this is the file with the largest gap in this
series.** PortSwigger's dedicated JWT lab set (the labs mapped in files 2–4)
is scoped specifically to signature-verification bypasses; it does not
include dedicated labs for claim manipulation as a standalone topic, `exp`
enforcement testing, or refresh token rotation. The closest related
PortSwigger material is:

- The general **"Broken Access Control"** lab topic area (outside the JWT lab
  set specifically) covers the underlying privilege-escalation-via-trusted-
  claim pattern conceptually, using non-JWT session mechanisms in several
  labs — the reasoning transfers directly to JWT `role`/`admin` claims even
  though those labs aren't JWT-specific.
- There is no PortSwigger lab at all for refresh token rotation testing
  (Part C). This content is built from real-world methodology and OAuth2/OIDC
  refresh token best-practice documentation, not from a PortSwigger lab
  environment.

Practice Part A of this file by chaining it on top of whichever file 2–4 lab
you've already solved (use the same lab's forged-token capability to also
edit `role`/`admin` claims, since PortSwigger's own labs already require this
as part of reaching the solved state in several cases). Parts B and C should
be practiced against a intentionally-vulnerable local lab setup (e.g.
OWASP's `juice-shop`, or a custom Node/Express + `jsonwebtoken` test harness)
rather than PortSwigger, since no PortSwigger lab targets them directly.
