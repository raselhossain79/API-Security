# 04 — Authentication Bypass Techniques

This file covers methodology for finding endpoints or request variations where the intended authentication check simply doesn't apply — either because it was never wired up, because it only checks one of several accepted formats, or because it wasn't wired up to every HTTP method a resource responds to. It closes with the OWASP API2:2023-specific gap of missing re-authentication on sensitive account actions.

---

## 1. Removing Authentication Headers Entirely

### 1.1 What You're Testing For

The most basic — and surprisingly still common — authentication bypass test: does the endpoint actually enforce the presence of an auth token at all, or does it only validate the token *if one happens to be present*? This flaw typically arises from middleware ordering mistakes, where a route is registered without the authentication middleware attached, or where the middleware is written to pass through requests with no `Authorization` header instead of rejecting them.

### 1.2 Testing Methodology

Take any confirmed-working authenticated request and systematically strip authentication in multiple ways, testing each independently:

**Remove the header completely:**

```
curl -s -i https://api.target.com/v1/user/orders
```

Command breakdown:
- `curl -s -i` — silent mode with response headers included in the output.
- `https://api.target.com/v1/user/orders` — the target endpoint, called with **no** `Authorization` header at all, as opposed to an invalid one.
- A correctly protected endpoint should return `401 Unauthorized`. If it instead returns `200 OK` with actual data, the endpoint has no authentication enforcement whatsoever.

**Send an empty Authorization header:**

```
curl -s -i https://api.target.com/v1/user/orders \
  -H "Authorization:"
```

Command breakdown:
- `-H "Authorization:"` — sends the header name with no value, which some frameworks handle differently from the header's total absence (some middleware checks `if header exists` without validating it's non-empty, treating an empty-but-present header as "authenticated" in badly written checks).

**Send a malformed Bearer prefix:**

```
curl -s -i https://api.target.com/v1/user/orders \
  -H "Authorization: Bearer"
```

Command breakdown:
- `-H "Authorization: Bearer"` — sends the `Bearer` scheme keyword with no token value following it, testing whether the server's token-extraction logic (commonly a string split on whitespace) fails safely (rejects) or fails open (treats a missing token portion as valid/skippable).

### 1.3 Testing Across the Full Endpoint Set, Not Just One Endpoint

This check is cheap enough that it should be run against **every** discovered endpoint (using the endpoint list from your recon/mapping phase — see your API reconnaissance notes) rather than spot-checked on a handful. A common real-world pattern is that authentication is correctly enforced on 95% of endpoints and missing on a small handful that were added later, refactored separately, or belong to a different internal team's code — exactly the kind of gap that a full sweep catches and a sample-based check misses.

For efficient bulk testing, use Burp's **match and replace** rule or a simple loop feeding a list of known authenticated endpoints:

```
while read -r endpoint; do
  echo "=== $endpoint ==="
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$endpoint"
done < endpoints.txt
```

Command breakdown:
- `while read -r endpoint; do ... done < endpoints.txt` — a bash loop reading each line of `endpoints.txt` (one endpoint path per line) into the variable `endpoint`; `-r` prevents backslash characters in the file from being interpreted as escape sequences.
- `echo "=== $endpoint ==="` — prints a separator label so output stays readable across many iterations.
- `curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$endpoint"` — sends a request with **no** auth header (intentionally, to test the bypass) to each endpoint; `-o /dev/null` discards the response body since only the status code matters here; `-w "%{http_code}\n"` prints just the numeric HTTP status code followed by a newline.
- Scan the output for any `200` (or other success code) appearing where a `401`/`403` was expected.

---

## 2. Swapping Token Formats

### 2.1 What You're Testing For

APIs that support more than one authentication mechanism (a very common situation — e.g., an API key for server-to-server partner integrations alongside JWT bearer tokens for the mobile app) sometimes validate *either* format on endpoints that should only accept one, or fail to fully validate the claims/scope embedded within one format while correctly validating the other.

### 2.2 Testing Methodology

**Step 1 — Enumerate accepted auth mechanisms.** Check API documentation (if available), and probe manually by sending a known-invalid value in each plausible auth mechanism to see which ones the server even attempts to parse (a parse attempt often produces a different error message than "mechanism not recognized"):

```
curl -s -i https://api.target.com/v1/user/orders \
  -H "X-API-Key: invalid-test-value"
```

```
curl -s -i https://api.target.com/v1/user/orders \
  -H "Authorization: Bearer invalid-test-value"
```

Command breakdown (applies to both):
- The two requests test whether the endpoint's auth middleware inspects the `X-API-Key` header, the `Authorization: Bearer` header, or both, by comparing error responses — an endpoint that only checks one will typically return a generic `401` regardless of what's in the header it doesn't check, while genuinely attempting to validate the header it does check (potentially producing a more specific error, e.g., "malformed API key" vs. "missing authorization").

**Step 2 — Test privilege differences between mechanisms.** If both mechanisms are accepted on the same endpoint, obtain a valid credential of each type (e.g., a low-privilege JWT and a partner-scoped API key) and compare what each returns. It's a common flaw for an API key intended only for limited server-to-server scope to be accepted on user-data endpoints that should only trust user-scoped JWTs, because the auth middleware was written as "accept anything that passes *a* validity check" rather than "accept only the credential type appropriate to this endpoint's trust level."

**Step 3 — Test format confusion within a single mechanism.** For JWT-based auth specifically, test whether the server accepts an opaque/non-JWT string in the `Authorization: Bearer` slot if the application also issues opaque tokens elsewhere (e.g., password reset tokens, email verification tokens) — a token meant for one purpose being accepted as a general session credential is a distinct and serious bypass, since it means the server is checking "is this a string in our token table" without checking *what kind* of token it is or what scope it was actually issued for.

---

## 3. HTTP Method Switching to Find Unprotected Paths to the Same Resource

### 3.1 What You're Testing For

Authentication middleware in many frameworks is registered per-route, and per-route registration is sometimes done per-HTTP-method rather than for the resource as a whole. This means the exact same URL path can have authentication correctly enforced on `GET` but missing on `PUT`, `POST`, `DELETE`, or a less common method like `PATCH` or `OPTIONS` — because a developer added the auth check when writing the `GET` handler and forgot (or a different developer wrote) the `POST` handler for the same path without replicating it.

### 3.2 Testing Methodology

For every endpoint where authentication is confirmed working on its primary method, systematically retest with every other HTTP method the resource might plausibly respond to:

```
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "=== $method ==="
  curl -s -o /dev/null -w "%{http_code}\n" -X "$method" \
    https://api.target.com/v1/user/orders/12345
done
```

Command breakdown:
- `for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do ... done` — a bash loop iterating over the standard set of HTTP methods worth testing against a REST resource.
- `-X "$method"` — sets curl's request method to the current loop value.
- `https://api.target.com/v1/user/orders/12345` — the target resource path, kept identical across every iteration; deliberately sent **without** an `Authorization` header, since the goal is checking whether *any* method on this path skips the auth check.
- `-o /dev/null -w "%{http_code}\n"` — discards the body, prints only the status code, as in Section 1.3.
- Flag any method returning something other than `401`/`403`/`404`/`405` — particularly a `200` or `204`, which would indicate that method path bypassed authentication while other methods on the same resource correctly enforced it.

### 3.3 Method Override Headers

Some frameworks support method-override headers that let a client signal an intended method different from the actual HTTP verb used (originally designed to work around clients/proxies that only support `GET`/`POST`). If the auth middleware checks the literal HTTP method but the route-handling logic checks the override header, this creates a mismatch worth testing directly:

```
curl -s -i -X POST https://api.target.com/v1/user/orders/12345 \
  -H "X-HTTP-Method-Override: DELETE"
```

Command breakdown:
- `-X POST` — sends the actual request as a POST, which may pass a less strict auth check applied to POST.
- `-H "X-HTTP-Method-Override: DELETE"` — signals to the application layer (if it honors this header, common in frameworks built to accommodate older clients) that the request should be processed as if it were a DELETE — potentially triggering delete logic while bypassing whatever auth check was specifically bound to literal DELETE requests.
- Other override header names worth testing depending on framework: `X-HTTP-Method`, `X-Method-Override`.

### 3.4 Real-World Framing

HTTP method-based auth gaps are a recurring finding class in bug bounty reports on REST APIs, particularly around resource-modification endpoints (`DELETE`/`PUT`/`PATCH`) that were added after the initial `GET`/`POST` API surface was already secured and load-tested — the newer methods sometimes ship without inheriting the same middleware configuration review the original endpoints received.

---

## 4. Sensitive Action Re-Authentication Gaps (OWASP API2:2023-Specific)

### 4.1 What This Is and Why OWASP Calls It Out Specifically

This is distinct from the bypass techniques above because the user *is* correctly authenticated — the flaw is that the API treats "has a valid session token" as sufficient proof of identity for **every** action, including sensitive account changes that industry practice treats as requiring a fresh, explicit re-proof of identity (current password, MFA re-verification, or a short-lived step-up token). OWASP's 2023 API Security Top 10 update explicitly calls this out under API2 because it's a distinct and common enough pattern to warrant naming directly, separate from general "missing authentication."

The underlying risk scenario: if a session token is compromised through any means (session hijacking, an XSS bug elsewhere in the application, a shared/public device, a stolen mobile device with a still-valid app session), an attacker holding that token should not be able to take over the account entirely by changing the email and password without ever needing to know the current password — but that's exactly what happens when re-authentication isn't enforced on these actions.

### 4.2 Endpoints to Specifically Target

- Change password
- Change account email address
- Add or remove a linked authentication method (e.g., add a new OAuth provider, add a new API key with account-wide scope)
- Disable or reconfigure MFA/2FA
- Change account recovery information (backup email, phone number, security questions)
- Generate or view API keys with elevated scope
- Delete the account entirely

### 4.3 Testing Methodology

**Step 1 — Attempt the sensitive action with only the session token, no current-password field.** Capture the legitimate request the frontend sends when a user changes their password through the normal UI flow, and inspect its body:

```
curl -s -i -X PUT https://api.target.com/v1/user/password \
  -H "Authorization: Bearer <VALID_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"new_password":"NewPass123!"}'
```

Command breakdown:
- `-X PUT` — the method the password-change endpoint uses (verify against the actual captured request; some use `POST` or `PATCH`).
- `-H "Authorization: Bearer <VALID_TOKEN>"` — the currently valid session token for the account under test.
- `-d '{"new_password":"NewPass123!"}'` — **deliberately omits** any `current_password` field, testing whether the server requires it or silently accepts the change based on the session token alone.
- If the server responds `200`/`204` and the password is actually changed (confirm by attempting login with the new password), this confirms the endpoint accepts the sensitive action without re-authentication.

**Step 2 — If a `current_password` field exists in the legitimate request, test whether it's actually validated server-side or merely expected client-side.** Send the request with an obviously wrong value in that field:

```
curl -s -i -X PUT https://api.target.com/v1/user/password \
  -H "Authorization: Bearer <VALID_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"definitely_wrong_value","new_password":"NewPass123!"}'
```

Command breakdown:
- Identical structure to Step 1, but with a `current_password` field present, deliberately set to an incorrect value.
- If the server still processes the change successfully, this reveals that the field is present in the API contract (likely because the frontend sends it) but is never actually compared against the account's real current password server-side — a validation-in-name-only flaw that's functionally identical to having no re-authentication check at all.

**Step 3 — Test whether email change silently changes the account of record for login without any confirmation step.** Some implementations correctly require current-password re-entry for the *password* endpoint but treat the *email* endpoint as lower-risk and skip the same check, or skip sending a confirmation link to the *old* email address to notify the legitimate owner of the change (a secondary but related control — the old email should be notified even where a confirmation-to-new-email flow exists, so the legitimate owner has a chance to detect and react to an unauthorized change).

**Step 4 — Test MFA-disable endpoints specifically for step-up requirements.** If the account has MFA enabled, attempt to disable it using only the session token, with no requirement to enter a current MFA code or password:

```
curl -s -i -X DELETE https://api.target.com/v1/user/mfa \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Command breakdown:
- `-X DELETE` — the method disabling MFA on this hypothetical endpoint (verify against the target's actual API).
- `-H "Authorization: Bearer <VALID_TOKEN>"` — the only credential supplied; no MFA code or password is included, directly testing whether disabling a security control requires proving you're not just holding a stolen session token but can also produce the second factor (or password) that a token thief likely wouldn't have.

### 4.4 Real-World Framing

This exact gap — session-token-only authorization for account-takeover-adjacent actions — is a recurring high-severity finding in bug bounty programs, frequently rated critical because the impact chain is short and severe: any session hijacking or token leak vulnerability elsewhere in the application (even a low-severity one on its own) becomes a full account takeover the moment it can be chained into an unguarded password/email change endpoint. This is also why re-authentication requirements on these specific actions are explicitly recommended by both OWASP's API Security guidance and general industry account-security best practice (e.g., major platforms requiring password re-entry before allowing email changes, and sending old-email notifications on any change) — it's treated as a baseline control, not a hardening extra.

---

## 5. PortSwigger and crAPI Lab Mapping

**PortSwigger:** PortSwigger does not have labs directly modeling REST API method-based auth gaps, token-format-swapping, or sensitive-action re-authentication — these are architectural/access-control patterns that don't map to PortSwigger's single-vulnerability lab format. The closest conceptually adjacent labs live under **Access Control** (e.g., *Unprotected admin functionality*, *Method-based access control can be circumvented*) which reinforce the underlying "check every method/path, not just the obvious one" mindset from Sections 1 and 3, even though they're framed around web app admin panels rather than APIs directly.

**Honest gap disclosure:** This entire file's core content — Sections 2 and 4 specifically — has no PortSwigger lab equivalent. This is one of the clearest cases in this series where hands-on practice needs to happen against a real API training target rather than PortSwigger.

**crAPI modules for this file's gaps:**
- crAPI's user profile and password-change endpoints in the **community** module are a direct, practical target for Section 4's re-authentication testing methodology.
- crAPI's mixed use of JWT and other credential types across its microservices (vehicle API vs. community API) provides realistic ground for Section 2's token-format-swapping tests across service boundaries.

## 6. What's Next

File 05 consolidates every command, payload, and checklist from files 02–04 into a single field-reference cheatsheet.
