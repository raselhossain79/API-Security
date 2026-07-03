# BFLA — Common Exploitation Patterns

Three patterns account for the overwhelming majority of real-world BFLA findings. Each is broken down request-by-request: what's sent, what's expected, what actually happens, and precisely why the authorization check fails.

---

## 1. HTTP Method Switching

**Mechanism:** authorization checks are frequently applied to a *route handler for one specific verb*, not to the URL path as a whole. When a framework maps `GET /api/users/{id}`, `PUT /api/users/{id}`, and `DELETE /api/users/{id}` to three separate handler functions, a developer can correctly gate one verb and simply forget the others — because in their mental model they "already secured that endpoint."

### Worked Example

**Step 1 — baseline, allowed action:**
```
GET /api/users/1042 HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-priv-user-token>
```
```
HTTP/1.1 200 OK

{"id":1042,"username":"jdoe","role":"user"}
```
- **What's being tested:** does a regular user's token work for reading their own (or any) user record via GET.
- **Result:** works as intended — read access to `/api/users/{id}` is meant to be broadly available (e.g., for a public profile view).

**Step 2 — escalate the verb, same path, same token:**
```
DELETE /api/users/1042 HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-priv-user-token>
```
```
HTTP/1.1 204 No Content
```
- **What's being tested:** whether the `DELETE` handler on the identical path independently enforces a role check, or whether it inherited only the authentication check that lets any logged-in user reach the route at all.
- **Why the check fails:** the developer added `@login_required` at the router level (applied to all verbs on this path) but only added `@role_required('admin')` inside the `GET` handler's surrounding controller class — not realizing that `PUT`/`DELETE`/`PATCH` are handled by sibling methods in the same class that don't inherit the decorator, or are routed through an entirely separate controller that was never audited at all.
- **Impact:** a completely unprivileged user just deleted an arbitrary account by number. This is vertical BFLA with immediate, high-severity, destructive impact — no BOLA ownership check was even relevant here, because the *function itself* (delete-any-user) should never have been reachable.

**Testing checklist for this pattern — for every discovered endpoint, try all of:**
```
GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
```
against the identical path with the identical low-privilege token, and compare each response body and status code against the expected "should be forbidden" baseline.

**Tooling note:** Burp's "Turbo Intruder" or a simple Repeater tab-per-verb workflow is sufficient — this doesn't need automation for a handful of endpoints, but for large APIs discovered via Swagger (file 02, section 3), scripting a full verb sweep against every documented path is far faster than manual testing.

---

## 2. Endpoint Path Manipulation

**Mechanism:** some codebases physically separate "admin" and "regular user" functionality into parallel route trees (`/user/...` vs `/admin/user/...`) that call the **same underlying service/business logic function**, differing only in which route prefix has an authorization middleware attached. If the mapping between the two trees is predictable, or if the "admin" tree's middleware is misconfigured (applies to the wrong path prefix, has a typo, or only checks a subset of routes under it), a low-privileged token can call the admin-prefixed path directly.

### Worked Example

**Step 1 — baseline, the intended low-privilege path:**
```
GET /api/user/profile/1042 HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-priv-user-token>
```
```
HTTP/1.1 200 OK

{"id":1042,"username":"jdoe","email":"j***@example.com"}
```
- **What's being tested:** the normal, sanctioned self-service profile read. Email is masked — a sign the API already applies *some* field-level restriction based on role.

**Step 2 — try the discovered admin-prefixed equivalent (found via JS mining or Swagger, per file 02):**
```
GET /api/admin/user/profile/1042 HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-priv-user-token>
```
```
HTTP/1.1 200 OK

{"id":1042,"username":"jdoe","email":"jdoe@example.com","internalNotes":"Flagged for chargeback review 2026-04-11","riskScore":82}
```
- **What's being tested:** whether the `/admin/` prefix actually carries an authorization requirement, or whether it's purely a naming/routing convention with no enforcement behind it.
- **Why the check fails:** the two routes were built to share the same underlying `getUserProfile(id)` service function, with the admin route simply requesting additional fields (`internalNotes`, `riskScore`) via a query parameter or a different serializer. The developer secured the *admin dashboard's frontend routing* (an SPA-level route guard) but never added a matching **backend** authorization check on `/api/admin/*` — the assumption was "no one will call this URL unless they're already inside the admin dashboard," which is a client-side assumption with zero enforcement value against a direct API call.
- **Impact:** full unmasked PII plus internal risk/fraud metadata, reachable by any authenticated regular user who can guess or discover the `/admin/` mirror of a path they already have legitimate access to under `/user/`.

**Systematic approach for this pattern:**
1. For every legitimate endpoint you're given (`/api/user/...`, `/api/orders/...`, `/api/tickets/...`), try inserting `admin`, `internal`, `manage`, or `staff` as a path segment in every plausible position:
   ```
   /api/user/X          -> /api/admin/user/X
   /api/user/X          -> /api/user/admin/X
   /api/v1/orders       -> /api/v1/admin/orders
   /api/orders/{id}     -> /api/orders/{id}/admin
   ```
2. Also try the **inverse** — if you found an admin-prefixed endpoint via JS/Swagger mining, check whether a non-prefixed sibling exists that might have weaker checks, or vice versa.
3. Diff the response bodies, not just status codes — as shown above, a `200 OK` on both paths can still represent two very different privilege boundaries if one returns extra fields.

---

## 3. Parameter-Based Role Manipulation

**Mechanism:** instead of (or in addition to) checking a server-side session/token claim for role, some APIs trust a role or permission value sent **by the client** — in the JSON body, a query string parameter, or occasionally a header — and use that client-supplied value to decide what the request is allowed to do. This is a textbook case of trusting client input for a security decision.

### Worked Example A — JSON body role field

**Step 1 — normal profile update, as sent by the legitimate frontend:**
```
PUT /api/users/1042 HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-priv-user-token>
Content-Type: application/json

{"username":"jdoe","bio":"Security enthusiast","role":"user"}
```
```
HTTP/1.1 200 OK

{"id":1042,"username":"jdoe","bio":"Security enthusiast","role":"user"}
```
- **What's being tested:** the baseline — the frontend always echoes the current `role` value back in the update payload, even though the user has no UI control to change it.

**Step 2 — modify the role field in the same request:**
```
PUT /api/users/1042 HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-priv-user-token>
Content-Type: application/json

{"username":"jdoe","bio":"Security enthusiast","role":"admin"}
```
```
HTTP/1.1 200 OK

{"id":1042,"username":"jdoe","bio":"Security enthusiast","role":"admin"}
```
- **What's being tested:** whether the backend's update handler blindly maps every field in the incoming JSON onto the database record (a "mass assignment"-style flaw, see also file on Mass Assignment for the broader pattern) rather than explicitly whitelisting which fields a self-service update endpoint is allowed to touch.
- **Why the check fails:** the developer wrote something functionally equivalent to `user.update(request.body)` instead of `user.update({username: body.username, bio: body.bio})`. There is no role check at all here — the vulnerability is that `role` should never have been a writable field on this endpoint for *any* caller except a dedicated, separately-authorized admin role-management function.
- **Impact:** the user has just self-escalated to admin. This is the single most severe BFLA sub-pattern because it doesn't just reach one privileged function — it grants a token that now passes every subsequent role check across the entire API.

### Worked Example B — query parameter permission override

```
GET /api/reports/financial?asAdmin=true HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-priv-user-token>
```
```
HTTP/1.1 200 OK

{"totalRevenue":4210330.55,"refundLiability":98211.02,"reportScope":"organization-wide"}
```
- **What's being tested:** whether a debug/internal convenience parameter (`asAdmin`, `debug`, `override`, `bypass`, `elevated`) — likely left in from development or an internal admin-impersonation tool — is checked against the caller's *actual* role, or just checked for presence/truthiness.
- **Why the check fails:** the parameter was almost certainly built for legitimate internal tooling (e.g., customer support impersonating a user's view for troubleshooting) where the *caller* is expected to already be an admin. The bug is that the handler checks `if request.args.get('asAdmin') == 'true'` and branches logic based on that, without an additional `and current_user.role == 'admin'` guard — the parameter name effectively became a static, unauthenticated backdoor.
- **Discovery tip:** these parameters are found via JS source mining (file 02, section 2) — grep specifically for `admin`, `debug`, `override`, `elevated`, `bypass`, `impersonate`, `sudo` as string literals near fetch/axios calls, since they're rarely documented in Swagger but are almost always present in the client code that calls them (even if only used by an internal support tool bundled in the same JS build).

**Systematic approach for this pattern:**
1. For every request body and query string, note every field that looks like a flag, role, or permission — even booleans that seem unrelated (`verified`, `trusted`, `internal`, `staff`).
2. Try flipping each one independently (don't change multiple fields at once — you need to isolate which single field the backend actually trusts).
3. Try both **adding** a field the legitimate client never sends (`"role":"admin"` injected into a payload that normally omits it) and **modifying** a field the client does send.
4. Test the same idea in headers — `X-User-Role`, `X-Admin`, `X-Internal-Request` are common in APIs behind an internal gateway that's meant to strip/set these headers itself but doesn't validate that a client-supplied version wasn't already present before the gateway processed the request.

---

## 4. Pattern Summary Table

| Pattern | What changes between request 1 and request 2 | Root cause |
|---|---|---|
| HTTP method switching | Verb only (GET → PUT/DELETE), same path | Verb-specific handlers don't share authorization middleware |
| Endpoint path manipulation | Path only (`/user/` → `/admin/user/`), same verb | Parallel route trees share business logic but not enforcement |
| Parameter-based role manipulation | Body/query/header value, same path and verb | Client-supplied value trusted for a security decision (mass assignment or trusted-flag pattern) |

All three are frequently combined in a single finding — for example, a path-manipulated admin endpoint that *also* accepts a role parameter, compounding the severity.

---

## 5. What's Next

**File 04** covers how these individual patterns escalate into full vertical privilege escalation and lateral (cross-role/cross-tenant) escalation chains, including combining BFLA with BOLA for maximum impact.
