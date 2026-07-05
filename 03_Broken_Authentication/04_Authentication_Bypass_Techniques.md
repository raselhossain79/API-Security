# API Broken Authentication — Authentication Bypass Techniques

Covers: removing the Authorization header, HTTP method switching, token format manipulation, and gateway/backend enforcement mismatches. Also covers sensitive-action re-authentication gaps as a bypass-adjacent finding.

---

## 1. Removing the Authorization Header Entirely

### 1.1 Why this works more often than it should

Authentication middleware is frequently implemented per-route or per-router-group rather than globally. A very common real-world pattern: a developer adds a new endpoint, forgets to attach it to the auth-required router group, and the endpoint is now reachable with zero authentication — while every endpoint around it correctly requires a token. This is the single highest-value, lowest-effort test in the entire series, and should be run against **every** endpoint discovered during recon, not just ones that "look" sensitive.

### 1.2 Methodology

**Step 1 — Establish the baseline (authenticated) response.**
```
curl -s -o /dev/null -w "%{http_code}\n" https://api.target.com/v1/admin/users \
  -H "Authorization: Bearer $TOKEN"
```
Confirms the endpoint exists and what a normal authenticated response looks like (status code, roughly).

**Step 2 — Repeat with the header stripped entirely.**
```
curl -s -o /dev/null -w "%{http_code}\n" https://api.target.com/v1/admin/users
```
- No `-H "Authorization: ..."` at all — this is not sending an *empty* or *malformed* header, it is omitting the header completely, which exercises a different code path than a malformed-token check might.

**Step 3 — Interpret carefully.** A `401`/`403` here is the expected, correct behavior — not a finding. The finding occurs when this returns `200` (or any other success-indicating status) with the same or similar body content as the authenticated baseline from Step 1.

**Step 4 — Automate across an endpoint list.**
Since this check is identical for every endpoint, script it across your full recon-derived endpoint list rather than testing one-by-one:

```
while read -r path; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com${path}")
  echo "$code  $path"
done < endpoints.txt | sort | grep -E "^200|^301|^302"
```
- `while read -r path; do ... done < endpoints.txt` — reads each line of `endpoints.txt` (one endpoint path per line, gathered during recon/spidering) into the variable `path`; `-r` prevents backslash characters in the file from being interpreted/escaped incorrectly.
- `code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com${path}")` — sends an unauthenticated request to each path and captures only the status code.
- The final `sort | grep -E "^200|^301|^302"` — filters the output down to only the interesting status codes (success or redirect) worth manually reviewing, since a large endpoint list will produce mostly `401`/`403`/`404` noise you don't need to read line-by-line.

---

## 2. HTTP Method Switching

### 2.1 Why this works

Authentication middleware is sometimes bound to a specific HTTP method rather than to the route path itself — for example, a framework's routing configuration might apply an auth guard to `POST /api/v1/users/:id` (the "update" action) but the same path handler also silently accepts `GET`, `PUT`, `PATCH`, or `DELETE` on the identical path without the guard being re-checked, because the guard was configured per-verb rather than per-path.

### 2.2 Methodology

**Step 1 — Identify the endpoint's documented/observed method.**
Suppose recon shows `POST /api/v1/users/42/role` requires an admin token and correctly returns `403` without one.

**Step 2 — Systematically try alternate methods on the identical path**, both with and without the auth header, since the goal is checking two things simultaneously: (a) does an unintended method work at all, and (b) does it work *without* authentication:

```
for method in GET PUT PATCH DELETE OPTIONS HEAD; do
  echo "=== $method ==="
  curl -s -o /dev/null -w "%{http_code}\n" -X "$method" \
    https://api.target.com/v1/users/42/role
done
```
- `-X "$method"` — overrides curl's default method (GET) with each value from the loop in turn.
- Deliberately **omitting** the `Authorization` header here — the first pass checks whether *any* alternate method is even reachable at all without auth; a second pass (adding the header back in) can then check whether an alternate method bypasses an *authorization* check even while authenticated as a lower-privileged user, which is a related but distinct access-control question outside this file's scope.

**Step 3 — Pay special attention to `OPTIONS` and `HEAD`.**
These verbs are frequently excluded from auth middleware by design (since `OPTIONS` is used for CORS preflight and is expected to be publicly reachable, and `HEAD` is often treated as "just like GET but no body" without separate guard logic). Confirm whether `HEAD` responses leak information via headers alone (e.g., `Content-Length` revealing whether a resource exists) even when the equivalent `GET` is properly protected.

**Step 4 — Check for method-override header tricks.**
Some frameworks support overriding the effective method via a header or query parameter for compatibility with clients that can't send arbitrary verbs (e.g., older HTML forms). Test:
```
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  -H "X-HTTP-Method-Override: DELETE" \
  https://api.target.com/v1/users/42
```
- `-H "X-HTTP-Method-Override: DELETE"` — sends a POST on the wire (which may pass a POST-scoped auth check) while instructing the backend framework to *treat* it as a DELETE internally. If the auth middleware inspects the literal wire method (POST) but the route handler acts on the overridden method (DELETE), the two checks disagree — an authorization/authentication mismatch results. Also test `X-HTTP-Method`, `X-Method-Override`, and a `_method` query/body parameter, since the specific header name supported varies by framework.

---

## 3. Token Format Manipulation

### 3.1 What this covers

Rather than removing the token, this category modifies its **structure** to see if the validation logic makes an unsafe assumption about format, algorithm, or type.

### 3.2 JWT-specific manipulation

**`alg: none` attack.**
```
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
PAYLOAD=$(echo -n '{"sub":"1","role":"admin"}' | base64 | tr -d '=' | tr '+/' '-_')
FORGED_TOKEN="${HEADER}.${PAYLOAD}."
```
- `echo -n '...'` — `-n` suppresses the trailing newline `echo` normally adds, which would otherwise corrupt the base64 encoding.
- `base64 | tr -d '=' | tr '+/' '-_'` — standard base64 uses `+`, `/`, and `=` padding, but JWTs use **base64url** encoding, which replaces `+` → `-`, `/` → `_`, and omits `=` padding entirely; this chain converts standard base64 output into proper base64url format.
- `FORGED_TOKEN="${HEADER}.${PAYLOAD}."` — note the **trailing dot with nothing after it** — this is deliberate: an `alg: none` JWT has an empty signature segment, so the token ends in a bare `.` with no third segment content. Some libraries, when they see `alg: none` in the header, skip signature verification entirely and trust the payload — meaning this crafted token, with a self-declared `role: admin`, may be accepted if the backend doesn't explicitly reject the `none` algorithm.

**Algorithm confusion (RS256 → HS256).**
If the API's real tokens are signed with an asymmetric algorithm (`RS256`, verified using a public key the server exposes, e.g., via a `/jwks.json` endpoint), some vulnerable implementations use a single generic "verify" function that trusts the `alg` field from the token header itself to decide how to verify — meaning if you change the header to declare `HS256` and then sign the forged token using the **public key** (which you legitimately have) as if it were an HMAC secret, the naive verifier may compute the same signature and accept the forgery, because it never enforces that the verification algorithm must match the one the server actually issues.

```
python3 -c "
import jwt
public_key = open('rs256_public.pem').read()
forged = jwt.encode({'sub':'1','role':'admin'}, public_key, algorithm='HS256')
print(forged)
"
```
- `import jwt` — uses the PyJWT library.
- `public_key = open('rs256_public.pem').read()` — reads the server's published RSA public key (obtained from its JWKS endpoint or embedded in client-side code) as a plain string.
- `jwt.encode({'sub':'1','role':'admin'}, public_key, algorithm='HS256')` — this is the attack itself: instead of using the public key for RSA *verification* as intended, it's passed as the *secret* for HMAC *signing*. If the server's verification code blindly reads `alg` from the incoming token and dispatches to an HMAC-verify routine using that same public key value as the HMAC secret, the signatures will match.

### 3.3 API-key format manipulation

- **Type confusion in array-accepting parameters:** if an API accepts a token/key via a JSON field, test submitting it as an array instead of a string: `{"api_key": ["validkey123"]}` or `{"api_key": ["validkey123","anything"]}` — some backend languages' loose type-coercion (particularly older PHP patterns comparing an array against a string with `==`) can cause a comparison to unexpectedly evaluate true.
- **Null/empty variants:** test `{"api_key": null}`, `{"api_key": ""}`, and omitting the field entirely — each exercises a different code path in validation logic and occasionally one is unguarded while the others are correctly rejected.
- **Case sensitivity of Bearer scheme:** test `bearer <token>`, `BEARER <token>`, and `Bearer<token>` (no space) — inconsistent parsing occasionally causes a malformed-but-technically-present header to fall through to a default-allow code path rather than a proper reject.

---

## 4. Gateway / Backend Enforcement Mismatch

### 4.1 The scenario

In a Gateway-fronted architecture, the Gateway (Kong, Apigee, AWS API Gateway, NGINX-based custom gateways) typically terminates authentication before forwarding the request internally to the backend microservice. The backend service often trusts that "if I received this request, the Gateway already authenticated it" — and therefore performs **no independent authentication check of its own.**

### 4.2 Methodology (only within authorized scope, and only where internal network access is part of the engagement)

**Step 1 — Identify the backend's real hostname/IP**, which sometimes leaks via:
- Verbose error messages revealing internal hostnames (e.g., a stack trace mentioning `internal-users-svc.default.svc.cluster.local`)
- DNS records (subdomain enumeration turning up an internal-sounding hostname that happens to resolve publicly, e.g., `users-api-internal.target.com`)
- Response headers occasionally left over from the backend (e.g., a `Server` or `X-Powered-By` header inconsistent with what the Gateway itself would present)

**Step 2 — Attempt to reach the backend directly, bypassing the Gateway.**
```
curl -s -o /dev/null -w "%{http_code}\n" https://users-api-internal.target.com/v1/admin/users
```
If this succeeds without any `Authorization` header at all, it confirms the backend performs zero independent authentication and relies entirely on network-path trust — meaning **any** path that reaches it directly (a misconfigured internal load balancer, an exposed debug/staging environment, a compromised adjacent service in the same network) bypasses authentication completely, since the Gateway was the *only* enforcement point.

**Step 3 — Report this distinctly from a simple "missing auth header" finding** (Section 1), because the remediation is architecturally different: Section 1 findings are fixed by adding a check to that specific route; this finding requires the backend service itself to independently validate authentication regardless of network origin ("zero trust" / defense-in-depth), since relying on the Gateway as the sole checkpoint is itself the root cause.

---

## 5. Sensitive-Action Re-Authentication Gaps

### 5.1 What to test

For every endpoint that changes account-recovery-relevant data — email address, password, MFA enrollment/removal, linked recovery phone number — check whether the API requires the user's **current** password (or a fresh MFA challenge) in addition to a valid session token.

### 5.2 Methodology

**Step 1 — Perform the sensitive action using only the session token, deliberately omitting any current-password field:**
```
curl -s -X PATCH https://api.target.com/v1/account/email \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"new_email":"attacker-controlled@example.com"}'
```
If this succeeds (`200`, email actually changed) without ever prompting for the current password, this is the finding: a stolen or hijacked session token (from XSS, a leaked token per file 2, or a shoulder-surfed device) is now sufficient on its own to fully take over the account by redirecting password-reset emails to an attacker-controlled address — no password knowledge needed at all.

**Step 2 — If a `current_password` field exists in the request schema, confirm it's actually *checked*, not just accepted and ignored:**
```
curl -s -X PATCH https://api.target.com/v1/account/email \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"new_email":"attacker-controlled@example.com","current_password":"definitely_wrong_value"}'
```
If this still succeeds despite an obviously incorrect password value, the field is present in the API contract for appearances but not enforced server-side — a subtler and easily-missed variant of the same gap.

**Step 3 — Check whether MFA-protected accounts can have MFA itself removed without a fresh MFA challenge**, applying the identical pattern: attempt the MFA-disable endpoint using only the long-lived session token, with no fresh one-time code required.

---

## 6. Real-World Notes

- The `alg: none` and RS256→HS256 confusion attacks were widespread enough in 2015–2018 that most major JWT libraries now reject `none` by default and require the verifier to explicitly whitelist accepted algorithms — but custom or older internal implementations, especially in APIs built before these library defaults changed, remain a realistic finding in bug bounty programs today.
- HTTP method-switching bypasses have been documented in numerous CVEs and disclosed bug bounty reports where an admin action was correctly guarded on `POST` but the same route handler responded to `GET` with full data exposure, often because the framework's routing layer matched the path across all methods by default unless explicitly restricted.
- The "change email without current password" gap is one of the most consistently rewarded account-takeover-adjacent findings on HackerOne/Bugcrowd because of how directly it chains into full takeover (change email → trigger password reset → intercept reset link at the new attacker-controlled address).

---

Continue to `05_Final_Cheatsheet.md`.
