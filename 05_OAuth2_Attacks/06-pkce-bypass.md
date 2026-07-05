# PKCE Implementation Bypass

## Why PKCE Exists

Recall from file 1 that the authorization code flow's security against interception relies on the `client_secret` being required at the token-exchange step (Step 4) — an attacker who steals a `code` off the browser can't redeem it without that secret. But **public clients** — SPAs and native mobile apps — cannot hold a `client_secret` securely at all, since their entire codebase (JavaScript bundle or compiled app binary) is, by definition, sitting on a device fully accessible to whoever runs it. Anyone can extract a "secret" embedded in a mobile app.

PKCE (Proof Key for Code Exchange, RFC 7636, pronounced "pixy") solves this without requiring a static secret, by having the client generate a **fresh, one-time secret for every single authorization request**, proving at exchange time that whoever is redeeming the code is the same party who initiated the flow — even though no long-term secret was ever needed.

## PKCE Mechanics, Step by Step

### Step 1 — Client Generates a Code Verifier and Code Challenge

Before redirecting the user, the client generates:

```
code_verifier = a high-entropy random string, 43–128 characters
                e.g., "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

code_challenge = BASE64URL(SHA256(code_verifier))
                e.g., "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

This happens entirely client-side, before any network request is sent. The `code_verifier` never leaves the client at this point — only its hashed derivative does.

### Step 2 — Authorization Request Includes the Challenge, Not the Verifier

```
GET /auth?response_type=code&client_id=spa-app&redirect_uri=https://client-app.com/callback&scope=openid%20profile&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256 HTTP/1.1
Host: auth.oauth-provider.com
```

Line-by-line:
- `code_challenge=...` — the hashed value from Step 1. The authorization server stores this, associated with the `code` it's about to issue.
- `code_challenge_method=S256` — tells the server the challenge was derived using SHA-256. The alternative, `plain` (covered below), means the "challenge" is just the raw verifier with no hashing at all.

### Step 3 — Authorization Response (Unchanged from File 1)

```
HTTP/1.1 302 Found
Location: https://client-app.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
```

Nothing new here — this is exactly as vulnerable to interception as any other authorization code, per file 2. **PKCE does not prevent code interception. It prevents the interceptor from redeeming what they intercept.** This distinction matters and is worth stating explicitly in any assessment write-up.

### Step 4 — Token Request Includes the Original Verifier

```
POST /token HTTP/1.1
Host: auth.oauth-provider.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https://client-app.com/callback&client_id=spa-app&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Line-by-line:
- `code_verifier=...` — the original, un-hashed value from Step 1, sent now for the first time.
- **No `client_secret` at all** — this is the entire point. Public clients never need one.
- The authorization server takes this `code_verifier`, applies the same hash function it was told to expect (`code_challenge_method` from Step 2), and checks whether the result matches the `code_challenge` it stored when the `code` was issued.
- If an attacker intercepted the `code` from Step 3 but never saw the original `code_verifier` (which never traveled over any network channel until this exact request, from the legitimate client), they cannot construct a valid exchange — they'd need to guess a 43+ character high-entropy string that hashes to a specific known value, which is computationally infeasible for a properly generated verifier.

## Bypass Technique 1: Downgrade to `plain` Method

**The flaw:** RFC 7636 permits `code_challenge_method=plain` as a fallback for clients that can't compute SHA-256 (largely a legacy accommodation). Under `plain`, `code_challenge` **is** the `code_verifier` — no hashing at all, sent in cleartext in Step 2's authorization request.

**Why this defeats the entire protection:** if `code_challenge` equals `code_verifier` exactly, then anyone who intercepts the Step 2 authorization *request* (not even the response — the initial request itself, which is also visible to anyone with browser/proxy access on the victim's device, browser history, or referrer leakage as discussed in file 4) already has everything needed to complete Step 4's exchange. The "proof" component of PKCE only exists when a one-way function (the hash) separates what's exposed early (the challenge) from what's needed later (the verifier). `plain` collapses that separation entirely.

**Attack construction:**
1. Observe or force the authorization request to use `code_challenge_method=plain`. If the authorization server accepts *any* client-supplied value for this parameter without restricting it based on client registration, an attacker (or a compromised/malicious client on a shared device) can simply submit `code_challenge_method=plain&code_challenge=anything` themselves.
2. Because the "challenge" is now identical to the "verifier," anyone who captures the authorization request or response (browser history, a compromised proxy, an app that observes inter-app redirects on the same device, a malicious app registered to intercept the same custom URL scheme on mobile) already holds the value needed to complete the token exchange — no hash to invert, no computation required.

**Testing approach:** attempt an authorization request explicitly specifying `code_challenge_method=plain`. If the server accepts it rather than rejecting non-`S256` methods outright (the OAuth Security BCP explicitly recommends servers **only** accept `S256` and reject `plain` entirely), flag this as a finding — it's a real, exploitable weakening even before any interception attempt.

## Bypass Technique 2: Missing PKCE Enforcement (Optional Rather Than Mandatory)

**The flaw:** Some authorization servers support PKCE but don't **require** it — if a client simply omits `code_challenge` from the authorization request entirely, the server falls back to classic code-flow behavior with no PKCE binding at all.

**Attack construction:** if PKCE is optional and the redirect_uri validation has any weakness at all (file 2), an attacker doesn't need to defeat PKCE — they simply initiate their *own* malicious authorization request that never includes `code_challenge` in the first place, sidestepping the whole mechanism rather than attacking it.

**Why this matters even for legitimate clients:** if the *legitimate* client application always includes `code_challenge`, but the server doesn't enforce it as mandatory for that `client_id`, an attacker attempting to intercept a **victim's** code via redirect_uri manipulation still faces the legitimate client's own `code_verifier` requirement at exchange time (since the exchange is initiated by the real client, which will supply its own real verifier) — so the practical exploitability depends on exactly whose request is being intercepted and who performs the final exchange. This is worth reasoning through carefully per-target rather than assuming PKCE is present-but-optional automatically means bypassable.

## Bypass Technique 3: Authorization Code Substitution (No Verifier-to-Client Binding)

**The flaw:** PKCE binds a `code` to a specific `code_verifier`. It does **not**, by itself, bind a `code` to a specific `client_id` unless the server separately enforces that check. If a server validates "does this verifier hash to the challenge stored for this code" but fails to also validate "was this code originally issued to this client_id," an attacker can potentially use a code obtained via one (attacker-controlled) client together with a manipulated request to a different client's token endpoint — though this specific gap is uncommon in mature implementations and largely closed by requiring `client_id` to match at redemption, which is why real-world PKCE bypasses concentrate overwhelmingly on Technique 1 (`plain` downgrade) and Technique 2 (optional enforcement) rather than this cross-client substitution path.

## Bypass Technique 4: Mobile-Specific — Custom URL Scheme Interception

**Context:** Native mobile apps often use a custom URL scheme (e.g., `myapp://callback`) rather than an HTTPS `redirect_uri`, since there's no web server to receive the redirect. PKCE was specifically designed with this scenario in mind, since custom URL schemes are not exclusively owned by one app — multiple apps installed on the same device can register to handle the same scheme.

**Why this matters:** if a **malicious app** on the victim's device registers the same custom URL scheme as the legitimate client (`myapp://callback`), the OS may deliver the incoming redirect — carrying the authorization `code` — to the malicious app instead of, or in addition to, the legitimate one, depending on OS version and app-installation order.

**Why PKCE specifically neutralizes this, when correctly implemented:** the malicious app receives the `code`, but the `code_verifier` was generated and held **in the legitimate app's own memory**, never transmitted anywhere before the token exchange. The malicious app has no way to obtain it, so it cannot complete Step 4 even though it successfully intercepted Step 3. This is the scenario PKCE's design description most directly targets, and it's a good example to cite when explaining *why* PKCE matters for mobile clients specifically, distinct from the CSRF/interception concerns already covered for web clients in files 2–3.

**Where this still fails in practice:** if the legitimate app's own implementation is careless — for example, persisting the `code_verifier` to shared device storage, a location accessible to other apps or accessible via a rooted/jailbroken device, rather than keeping it purely in-memory for the lifetime of the single request — the isolation PKCE depends on is broken by the client's own poor storage practice rather than any flaw in the protocol itself. This is worth testing directly during a mobile app assessment: locate where `code_verifier` is stored between generation and use, and confirm it isn't written to a world-readable location, an unencrypted local database, or a logging system.

## Consolidated PKCE Testing Checklist

1. Confirm whether PKCE is present at all in the authorization request (`code_challenge` parameter).
2. If present, check whether `code_challenge_method=plain` is accepted by the server — attempt submitting it explicitly even if the legitimate client normally uses `S256`.
3. Attempt an authorization request with `code_challenge` omitted entirely, and see whether the server still issues a code without demanding one — this reveals whether PKCE is enforced or merely supported.
4. For mobile targets specifically, inspect (via static/dynamic analysis of the app) where and how long the `code_verifier` is retained, and whether it's exposed to other apps, backups, or logs.
5. Regardless of PKCE's presence, continue testing `redirect_uri` (file 2) and `state` (file 3) independently — PKCE addresses code-redemption by an interceptor; it does not address where the code gets delivered in the first place, nor does it substitute for CSRF protection on the client's own callback endpoint.

## Real-World Notes

- PKCE is now recommended by the OAuth 2.0 Security Best Current Practice for **all** clients, not just public ones — confidential (server-side) clients benefit from it too, since it adds a second, independent layer of interception protection on top of `client_secret`.
- The `plain` method downgrade is the most commonly found real-world PKCE weakness precisely because it's easy to overlook during code review — the parameter is present, the flow "looks" PKCE-protected in a request trace, and only checking the actual `code_challenge_method` value and confirming the server rejects `plain` reveals the gap.
- PKCE is not a replacement for `state` (file 3) — the two protect different things (code redemption vs. callback CSRF) and a mature implementation uses both together, which is also PortSwigger's own stated recommendation.

## What Comes Next

File 7 consolidates everything into a single quick-reference cheatsheet and maps every relevant PortSwigger Web Security Academy OAuth lab to the specific technique in this series it corresponds to, in official difficulty-progression order.
