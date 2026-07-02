# 02 — Token Security Testing

This file covers testing methodology for the four token-related failure modes most commonly exploited under API2:2023: weak token entropy, token reuse across sessions, insecure token transmission, and missing expiration/revocation.

---

## 1. Weak Token Entropy

### 1.1 What You're Testing For

If a token (session token, API key, password reset token, or JWT signing secret) can be predicted, brute-forced, or guessed because it doesn't contain enough true randomness, an attacker doesn't need to steal a token — they can simply generate a valid one.

### 1.2 Identifying Low-Entropy Tokens by Inspection

Before running any tool, inspect a sample of tokens manually. Request the same endpoint (e.g., login, or "generate API key") multiple times using a fresh account or session each time, and collect 10–20 token samples.

```
curl -s -X POST https://api.target.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser1","password":"Password123!"}'
```

Command breakdown:
- `curl` — the HTTP client used to send the request.
- `-s` — silent mode; suppresses curl's progress meter so only the response body is shown.
- `-X POST` — explicitly sets the HTTP method to POST, required for a login submission.
- `https://api.target.com/v1/auth/login` — the target authentication endpoint.
- `-H "Content-Type: application/json"` — tells the server the request body is JSON-encoded, which most modern APIs require to parse the body correctly.
- `-d '{"username":"testuser1","password":"Password123!"}'` — the request body itself, containing the credentials being submitted.

Repeat this with sequential test accounts and record the returned token value each time. Look for:
- **Sequential or incrementing patterns** (e.g., token ends in `...0001`, `...0002`).
- **Timestamp-based tokens** — if the token appears to encode the current Unix timestamp or a predictable date format, decode it and compare against your request time.
- **Short overall length** — tokens under roughly 128 bits (22 characters in base64, 32 hex characters) of true random entropy are considered weak by modern standards; note that length alone doesn't guarantee entropy if the generation algorithm is flawed underneath.
- **Reused prefixes/suffixes** — if every token shares a large fixed substring, the actual random portion is smaller than the token's total length suggests.

### 1.3 Statistical Entropy Analysis with Burp Sequencer

Burp Suite Community Edition includes **Sequencer**, purpose-built for this exact test.

1. Send a request that returns a token (login, password reset, session generation) to Burp's proxy history.
2. Right-click the request → **Send to Sequencer**.
3. In the Sequencer tab, set the **Token Location** — usually "Cookie" or a custom location if the token is in the JSON response body (use "Configure" to define a regex extraction pattern for JSON tokens, e.g., `"token":"([^"]+)"`).
4. Click **Start live capture**. Sequencer will repeatedly send the request and collect token samples automatically.
5. Let it collect at least 1,000 samples (this can take several minutes depending on server response time), then click **Analyze now**.

Sequencer produces an entropy report with an overall verdict (e.g., "effective entropy: 62 bits") and character-level bit-distribution charts. An effective entropy estimate below ~128 bits is generally flagged as insufficient for session-critical tokens.

### 1.4 JWT-Specific Entropy: Weak Signing Secrets

If the token is a JWT (identifiable by its three base64url-encoded, dot-separated segments — header, payload, signature), entropy testing shifts from the token itself to the **signing secret**, since a JWT's unforgeability depends entirely on the secret (for HMAC algorithms like HS256) or private key (for RSA/EC algorithms like RS256) being unguessable.

Decode the header and payload first to confirm the algorithm:

```
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
```

Command breakdown:
- `echo "..."` — outputs the base64url-encoded JWT header segment (the first of the three dot-separated parts) as text.
- `| base64 -d` — pipes that text into the `base64` utility with the `-d` (decode) flag, converting it back to readable JSON.
- Result reveals `{"alg":"HS256","typ":"JWT"}` — confirming this JWT uses HMAC-SHA256, meaning it's signed with a shared secret rather than a public/private key pair.

If `alg` is `HS256`, `HS384`, or `HS512`, the secret can be brute-forced offline using **hashcat** with mode 16500 (JWT):

```
hashcat -m 16500 -a 0 jwt.txt rockyou.txt
```

Command breakdown:
- `hashcat` — the GPU-accelerated password/hash cracking tool.
- `-m 16500` — selects hash mode 16500, hashcat's dedicated mode for cracking JWT HMAC signing secrets.
- `-a 0` — attack mode 0, a straight dictionary attack (each wordlist entry tried as-is, no mutation rules).
- `jwt.txt` — a file containing the full JWT string to attack.
- `rockyou.txt` — the wordlist being tried against the JWT; common weak secrets (`secret`, `password`, `changeme`, tutorial-default values like `your-256-bit-secret`) are frequently found this way because developers copy example code without changing the placeholder secret.

If cracked, the secret allows forging arbitrary JWTs — including changing the `sub` (subject) or `user_id` claim to impersonate any user, or elevating a `role` claim to `admin`.

---

## 2. Token Reuse Across Sessions

### 2.1 What You're Testing For

A correctly implemented session/token system issues a **unique** token per login session. Token reuse vulnerabilities occur when:
- The same token is issued to multiple concurrent logins by the same user without any binding to device/session context (this is sometimes intentional and acceptable — the concern is when it should *not* be intentional per the app's stated security model).
- A token issued to User A can be replayed by User B to gain User A's access (a critical, non-negotiable failure).
- Logging out, changing password, or explicitly revoking a session does not actually invalidate the old token — it remains usable indefinitely.

### 2.2 Testing Methodology

**Step 1 — Concurrent session test.** Log in as the same user from two separate Burp Suite sessions (use two separate browser profiles or two Burp project instances to avoid proxy history cross-contamination). Capture both tokens. Confirm whether the application's intended behavior is single-session (older token should be invalidated) or multi-session (both remain valid by design — check the app's documentation or ask the client during a scoped engagement). If single-session is expected but both tokens remain valid, that's a finding.

**Step 2 — Cross-account token replay.** This is the highest-severity variant. Capture a valid token from Account A. Log in separately as Account B, then replace Account B's token with Account A's captured token in an authenticated request:

```
curl -s https://api.target.com/v1/user/profile \
  -H "Authorization: Bearer <ACCOUNT_A_TOKEN>"
```

Command breakdown:
- `curl -s` — silent HTTP client invocation.
- `https://api.target.com/v1/user/profile` — an endpoint that should return the profile of whoever the token belongs to.
- `-H "Authorization: Bearer <ACCOUNT_A_TOKEN>"` — sends Account A's token in the standard Bearer authentication header.
- If this returns Account A's data while you are testing from an unrelated context (e.g., a different testing machine, after Account A "logged out"), it confirms the token was never actually bound to session validity checks server-side — it's a static credential rather than a live session reference.

**Step 3 — Logout invalidation test.** Capture a valid token. Trigger the application's logout function. Immediately replay the pre-logout token against a protected endpoint using the same request structure as Step 2. If the request still succeeds, the API is not invalidating tokens server-side on logout — a common flaw in stateless JWT implementations that rely purely on client-side token deletion with no server-side blocklist or short expiration.

### 2.3 Why This Is an API-Specific Concern

Web applications typically bind sessions to server-side session stores (Redis, database-backed sessions) that can be invalidated on demand. Many APIs, especially JWT-based ones, are built "stateless" for scalability — meaning the server does no lookup at all and trusts the token's signature alone. This design choice is reasonable *only* if paired with short expiration windows and a revocation mechanism (Section 4). Teams that adopt stateless JWTs for performance reasons without building revocation create exactly this vulnerability class.

---

## 3. Insecure Token Transmission

### 3.1 What You're Testing For

Tokens transmitted somewhere other than a header (specifically the `Authorization` header) or a properly-flagged cookie are exposed to a wider set of interception points: browser history, server access logs, proxy logs, referrer headers leaked to third-party resources, and shoulder-surfing via screen-shared URLs.

### 3.2 Identifying the Pattern

While proxying traffic through Burp, review every authenticated request in the HTTP history and check **where** the token is placed:

- **In the URL path or query string** — e.g., `GET /api/v1/orders?token=eyJhbGc...` or `GET /api/v1/orders/eyJhbGc.../details`. This is the primary anti-pattern this section targets.
- **In a custom header without appropriate protections** — less severe than URL placement, but confirm the header isn't also being logged by an intermediate proxy or CDN by policy.
- **In the response body of an unrelated, unauthenticated endpoint** — e.g., a token accidentally echoed back in an error message or debug response.

### 3.3 Why Query-String Tokens Are a Real Finding, Not a Nitpick

Query strings, unlike request bodies or headers, are commonly:
- Logged in plaintext by web servers (Apache/Nginx access logs), CDNs, and API gateways by default configuration.
- Stored in browser history if the endpoint is ever hit via a browser or WebView (common in mobile apps that open in-app browsers for OAuth flows).
- Leaked via the `Referer` header if the page containing the URL loads any third-party resource (image, script, analytics pixel) — the full URL, token included, gets sent to that third party.
- Cached by intermediate proxies or CDNs that key cache entries on the full URL including query string, potentially serving one user's authenticated response to another.

### 3.4 Practical Test

Search Burp's proxy history for token-shaped strings appearing outside headers:

1. In Burp, go to **Proxy → HTTP history**.
2. Use the search/filter bar (or Logger++ extension for more powerful regex search) with a pattern matching your target's token format, e.g., a JWT pattern: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
3. Review matches — flag every occurrence where the match appears inside the **URL** column rather than the **Headers** or **Body** detail view exclusively.

Also check server-side artifacts if you have any visibility into them during a whitebox/greybox engagement (access logs, CDN logs) — a query-string token is a finding even if the current UI never sends it that way, if a legacy or alternate endpoint accepts it that way as a fallback (test by manually appending `?token=` or `?access_token=` to endpoints that normally expect a header).

---

## 4. Missing Token Expiration and Revocation

### 4.1 What You're Testing For

Two related but distinct failures:
- **Missing expiration** — a token, once issued, remains valid indefinitely (or for an unreasonably long period, e.g., a JWT with no `exp` claim, or `exp` set years in the future).
- **Missing revocation** — even where expiration exists, there is no mechanism to invalidate a token *before* its natural expiration in response to logout, password change, or a detected compromise.

### 4.2 Testing Expiration

If the token is a JWT, decode the payload segment directly:

```
echo "eyJzdWIiOiIxMjM0IiwiZXhwIjoxNzk5MDAwMDAwfQ" | base64 -d
```

Command breakdown:
- `echo "..."` — outputs the JWT's payload (second segment, between the two dots).
- `| base64 -d` — decodes it from base64url to readable JSON.
- Resulting JSON might show `{"sub":"1234","exp":1799000000}` — the `exp` claim is a Unix timestamp marking expiration. Convert it (e.g., `date -d @1799000000`) to check whether it's set to a reasonable near-term value or an implausibly distant one.
- If the `exp` claim is **absent entirely**, most JWT libraries will treat the token as valid forever unless the server explicitly checks for its presence — a very common oversight.

If the token is opaque (not a JWT — just a random string), expiration can't be inspected client-side. Instead, test empirically: capture a token, wait past any documented or assumed session timeout window, then replay it against a protected endpoint. If it still works well beyond a reasonable session lifetime (industry-standard access tokens are typically short-lived — commonly in the 15-minute-to-a-few-hours range, with refresh tokens handling longer-lived re-authentication), that's a finding.

### 4.3 Testing Revocation

Revocation testing directly reuses the Section 2.2 Step 3 methodology (logout invalidation test) but should also be repeated for these triggers, each tested independently since an application may implement revocation for one but not others:

- **Password change** — capture a token, change the account password through the legitimate flow, then replay the pre-change token. It should fail.
- **Explicit "log out of all devices" / "revoke all sessions" feature** — if present, capture two tokens from two sessions, trigger the revoke-all action from one session, then replay both tokens.
- **Account deletion or deactivation** — capture a token, deactivate the account (where testing scope permits), replay the token.

A token that survives any of these should-invalidate events indicates the API is validating tokens purely by signature/format rather than checking a live, server-side revocation state — a design gap rather than a one-off bug, meaning it likely affects every token the system issues.

### 4.4 Real-World Framing

Missing revocation is a frequent finding in APIs that migrated from session-cookie architectures to JWTs for mobile-app support, because the migration often preserves the "stateless" performance benefit of JWTs without adding the denylist/short-expiration-plus-refresh-token pattern needed to make revocation possible. This tradeoff is a known, documented risk in JWT-based architecture (the JWT specification itself does not mandate a revocation mechanism), which is precisely why testers should never assume revocation exists just because expiration does — they are separate controls and must be tested separately.

---

## 5. PortSwigger and crAPI Lab Mapping

**PortSwigger (JWT category, in official difficulty order):**
1. *JWT authentication bypass via unverified signature* — directly exercises the "does the server actually validate the signature" question underlying Section 1.4.
2. *JWT authentication bypass via flawed signature verification* — covers algorithm confusion (`alg: none` and RS256-to-HS256 downgrade attacks), a deeper extension of weak-secret testing.
3. *JWT authentication bypass via weak signing key* — the closest direct match to the hashcat workflow in Section 1.4; PortSwigger provides a small wordlist scenario to practice against.
4. *JWT authentication bypass via jwk header injection* and *jku header injection* — more advanced key-confusion attacks, useful once the fundamentals above are solid.

**Honest gap disclosure:** PortSwigger has no lab covering token reuse across sessions, query-string token transmission, or revocation testing (Sections 2–4 of this file) — these are architectural/behavioral tests rather than single injectable bugs, which doesn't fit PortSwigger's lab format well.

**crAPI modules for this file's gaps:**
- The crAPI **community** and **forum** authentication flows are useful for practicing token reuse and replay testing against a realistic multi-user API.
- crAPI's JWT implementation is a practical target for entropy/secret analysis (Section 1) in a full-application context rather than an isolated lab.

## 6. What's Next

File 03 covers credential stuffing and brute-force methodology specific to APIs — how detection and tooling choices differ from testing a web login form.
