# API Broken Authentication — Token Security Testing

Covers: token entropy analysis, token reuse across sessions, insecure transmission channels, missing expiration, missing revocation.

---

## 1. Token Entropy Analysis

### 1.1 What we're actually checking

A session token, API key, or refresh token needs enough unpredictability that an attacker cannot guess, brute-force, or statistically infer a valid one belonging to another user. "Entropy" here means: given one or more tokens issued by the target, how much genuine randomness is in them versus predictable structure (timestamps, incrementing counters, weak PRNG output, encoded user data).

### 1.2 Step-by-step methodology

**Step 1 — Collect a sample set.**
Log in/log out repeatedly (or trigger token issuance repeatedly, e.g., password reset requests) to collect 20–50 tokens issued in sequence.

```
for i in 1 2 3 4 5; do
  curl -s -X POST https://api.target.com/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"Test1234!"}' \
    | jq -r '.token' >> tokens.txt
  sleep 1
done
```

Piece-by-piece:
- `for i in 1 2 3 4 5; do ... done` — bash loop to repeat the request 5 times; increase this count in practice (20+ samples give much better entropy signal).
- `curl -s` — `-s` (silent) suppresses curl's progress meter so only the response body prints/pipes cleanly.
- `-X POST` — explicitly sets the HTTP method to POST, required because login endpoints virtually never accept GET (credentials must not appear in a URL or server log).
- `-H "Content-Type: application/json"` — tells the server to parse the body as JSON; omitting this often causes the API to reject the request or parse it incorrectly.
- `-d '{"username":"testuser","password":"Test1234!"}'` — the JSON request body, using a throwaway test account you're authorized to use.
- `| jq -r '.token'` — pipes the JSON response into `jq`, extracting the `token` field; `-r` outputs the raw string without surrounding quotes.
- `>> tokens.txt` — appends each result to a file (append, not overwrite, so all 5 tokens are captured).
- `sleep 1` — 1-second delay between requests; avoids tripping a rate limiter while sampling, and produces timestamp separation useful for the timing analysis in Step 3.

**Step 2 — Decode structural encoding.**
Before assuming the token is "random," check if it's actually a structured format with a decodable payload:

- **JWT** (`xxxxx.yyyyy.zzzzz` — three base64url segments separated by dots): decode the header and payload segments with `echo <segment> | base64 -d`. If the payload contains the user ID or issue timestamp in plaintext, the "randomness" you're evaluating is only the signature segment, not the whole token.
- **Base64-looking single blob**: try `echo '<token>' | base64 -d | xxd` — `xxd` renders the decoded bytes in hex+ASCII side by side so you can spot recognizable substrings (usernames, IDs, timestamps) hiding inside what looked like noise.

**Step 3 — Statistical / structural comparison across the sample.**
Align the collected tokens and diff them character-by-character (for fixed-length tokens):

```
awk '{ for(i=1;i<=length($0);i++) print i, substr($0,i,1) }' tokens.txt | sort | uniq -c | sort -rn | head -40
```

Piece-by-piece:
- `awk '{ for(i=1;i<=length($0);i++) print i, substr($0,i,1) }'` — for every line (token) in the file, loop character-by-character and print the position index alongside the character at that position. This lets you see, per-position, how much the character varies across your samples.
- `sort` — groups identical (position, character) pairs together so `uniq` can count them.
- `uniq -c` — counts occurrences of each unique (position, character) pair.
- `sort -rn` — sorts numerically, descending, so the most-repeated position/character combinations bubble to the top.
- `head -40` — limits output to the top 40 rows for readability.

**What you're looking for:** if certain character positions show the *same* character in nearly every sample (e.g., position 9 is always `2` and position 10 is always `0`), that's a strong signal of an embedded timestamp or fixed structure rather than random bytes — dramatically reducing effective entropy even if the token *looks* long.

**Step 4 — Timing correlation.**
If tokens appear to contain a numeric component that increments predictably relative to the `sleep 1` intervals used during collection, the token generation is very likely seeded from (or directly is) a Unix timestamp or sequential counter — trivially predictable, not brute-force resistant.

### 1.3 Weak PRNG identification

If the token is a fixed-length hex/alphanumeric string with no visible structure, but was generated using a non-cryptographic PRNG (e.g., `Math.random()` in Node.js, or `rand()` in PHP without a CSPRNG wrapper), the output is still statistically predictable from a small number of samples using known PRNG-state-recovery techniques. Practical field test:

1. Confirm token length and character set (e.g., 16 hex chars = 64 bits).
2. If the backend framework/language is identifiable (via response headers, error messages, or a `X-Powered-By` header), check whether its **default** session-token generator uses a CSPRNG. Frameworks vary — this is a documentation/config check, not something you brute-force blindly.
3. Flag as a finding even without full PRNG state recovery: "token entropy insufficient / non-cryptographic RNG suspected" is a legitimate, reportable finding on its own once structural predictability is demonstrated in Steps 2–4.

---

## 2. Insecure Token Transmission

### 2.1 The core check

Search **every** request the API client makes — not just login — for tokens appearing anywhere other than a proper header (`Authorization: Bearer <token>` or a dedicated header like `X-Api-Key`).

**Where tokens should never appear:**
- URL query string: `GET /api/v1/orders?token=eyJhbGciOi...`
- URL path segment: `GET /api/v1/session/eyJhbGciOi.../orders`
- Referer header leakage — if a token is in the URL and the page makes an outbound request (e.g., loading an image from a third party), the token leaks via the `Referer` header to that third party.

### 2.2 Methodology

**Step 1 — Full traffic capture.**
Route the target mobile app or SPA through Burp Suite (proxy configured on the device/emulator) and browse the full functionality surface: login, password reset, account settings, any "magic link" style email flows.

**Step 2 — Search proxy history for token patterns.**
In Burp, use **Search** (or **Logger**, Burp Suite Professional) across the entire proxy history:

- Search term: the exact token value obtained from a successful login response.
- Also search for JWT structural patterns: strings matching `^eyJ` (base64url-encoded `{"` always starts a JWT header segment with `eyJ`).

If the same token string reappears in a **request URL** (not just the `Authorization` header) anywhere in the captured traffic, that's a confirmed insecure-transmission finding.

**Step 3 — Check server-side log exposure risk (documentation-based, not exploitation).**
URL query strings are logged by default by most web servers (Nginx/Apache access logs), CDNs, and any intermediate proxy — meaning a token transmitted this way is written to disk in plaintext on every hop, and often shipped to log-aggregation platforms (e.g., third-party log management tools) outside the organization's direct control. This doesn't require you to access those logs to report the finding — the design itself is the vulnerability regardless of whether you can prove log retention.

**Step 4 — Referer-leak proof of concept (safe, non-destructive).**
If a token is confirmed in the URL, and a page reached with that URL loads any external resource (image, script, font from a CDN), demonstrate the leak safely:

```
curl -s -D - https://api.target.com/v1/reports?token=<captured-token> -o /dev/null | grep -i "^location\|^set-cookie"
```

- `-D -` — dumps response headers to stdout (`-` means "to standard output" rather than a file), so you can inspect what the server sends back including any redirects.
- `-o /dev/null` — discards the response body since we only care about headers here.
- `grep -i "^location\|^set-cookie"` — filters for redirect targets or additional cookies set, case-insensitively; useful to confirm whether the token-bearing URL triggers a further request chain that would propagate the leak.

---

## 3. Missing Token Expiration

### 3.1 Methodology

**Step 1 — Capture a token and note issue time.**
```
TOKEN=$(curl -s -X POST https://api.target.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"Test1234!"}' | jq -r '.token')
echo "Issued at: $(date -u)"
```
- `TOKEN=$(...)` — captures the token into a shell variable for reuse in later requests.
- `echo "Issued at: $(date -u)"` — records the exact UTC timestamp of issuance so you can measure elapsed time precisely in later steps.

**Step 2 — Decode the expiry claim if JWT.**
```
echo "$TOKEN" | cut -d '.' -f2 | base64 -d 2>/dev/null | jq .
```
- `cut -d '.' -f2` — JWTs are three dot-separated segments (header.payload.signature); `-d '.'` sets the delimiter, `-f2` extracts the second field (the payload).
- `base64 -d` — decodes the base64url payload into raw JSON text. (Note: JWT uses base64**url** encoding, which may need padding fixed or `base64 -d` swapped for a tool that handles URL-safe base64 if you get decode errors — `jwt.io`-style CLI decoders handle this automatically.)
- `2>/dev/null` — suppresses decode error noise if padding is off; still generally produces readable output for inspection.
- `jq .` — pretty-prints the resulting JSON so you can read the `exp` (expiry) claim directly.

If there is no `exp` claim, or `exp` is set implausibly far in the future (e.g., years), that is a direct, reportable finding.

**Step 3 — Empirical expiry test (for opaque, non-JWT tokens).**
Since opaque tokens have no decodable expiry claim, test empirically:
1. Use the token successfully against a protected endpoint to confirm it works.
2. Wait past the organization's stated session-timeout policy (check documentation, or default to testing at 1 hour, 8 hours, 24 hours, and 7 days if no policy is published).
3. Re-test the same token at each interval:
```
curl -s -o /dev/null -w "%{http_code}\n" https://api.target.com/v1/account/profile \
  -H "Authorization: Bearer $TOKEN"
```
- `-o /dev/null` — discards the body since we only need the status code.
- `-w "%{http_code}\n"` — `-w` (write-out) prints a custom format string after the request completes; `%{http_code}` is curl's variable for the HTTP status code returned.

A `200` at every interval tested, including well beyond any documented session policy, confirms a missing-expiration finding.

---

## 4. Missing Token Revocation

### 4.1 The scenario being tested

Even if a token *does* eventually expire, a well-designed system also needs a way to invalidate a token **immediately** on demand — logout, password change, "log out of all devices," or a detected compromise. Many APIs implement expiry but not revocation, meaning a stolen token stays valid until its natural expiry regardless of any user action.

### 4.2 Methodology

**Step 1 — Capture two valid tokens for the same account** (e.g., log in from two different "sessions" — this could just be two separate login calls).

**Step 2 — Trigger each revocation-relevant action and re-test the *other* token:**

| Action triggered | Token being re-tested | Expected secure behavior |
|---|---|---|
| Explicit logout (Token A) | Token A itself | Should be rejected immediately |
| Password change | Token A and Token B (both pre-existing) | Both should be rejected — a password change should invalidate all prior sessions |
| "Log out all devices" (if offered) | Every previously issued token | All should be rejected |

Example test after triggering logout on Token A:
```
curl -s -X POST https://api.target.com/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN_A"

curl -s -o /dev/null -w "%{http_code}\n" https://api.target.com/v1/account/profile \
  -H "Authorization: Bearer $TOKEN_A"
```
- First call logs out using Token A.
- Second call immediately reuses the *same* Token A against a protected endpoint. A `200` response here — instead of `401`/`403` — is the finding: the server accepted the logout request but never actually invalidated the token server-side (common when tokens are stateless JWTs with no server-side denylist/blocklist check).

**Step 3 — Distinguish "client-side logout theater" from real revocation.**
A frequent anti-pattern: the client (mobile app/SPA) deletes the token from local storage on logout, giving the *appearance* of security, while the token remains valid server-side indefinitely. The test in Step 2 — replaying the captured token directly via `curl`, bypassing the client entirely — is exactly what exposes this, because it removes the client's cooperation from the test.

---

## 5. Real-World Notes

- **Token-in-URL leakage** was a widely reported class of finding across password-reset "magic link" implementations circa 2021–2023, where reset tokens embedded in emailed URLs ended up in browser history, corporate proxy logs, and — when the link was pasted into chat tools for "sharing" — third-party chat-platform logs.
- **Stateless JWT revocation gaps** are extremely common because JWTs are, by design, self-contained and don't require a database lookup to validate — which is exactly why revoking one before its natural expiry requires an explicit denylist mechanism that many teams skip for performance reasons, trading revocability for speed.
- Bug bounty programs frequently score "no server-side session invalidation on logout" as a Medium-severity finding even without further exploitation chain, because it directly extends the window of usability for any token later obtained via phishing, device theft, or interception.

---

Continue to `03_Credential_Based_Attacks.md`.
