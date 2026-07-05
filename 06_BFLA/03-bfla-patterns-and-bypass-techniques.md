# BFLA — Common Patterns & Bypass Techniques

This file assumes you already have a candidate list of privileged endpoints from the discovery phase (`02-discovery-methodology.md`). Here we cover how to actually confirm and exploit BFLA against each candidate, broken down request-by-request.

---

## 0. Baseline testing methodology: non-admin credentials against discovered endpoints

Before any bypass trick, the first and most important test is the simplest one: **just call the endpoint as a lower-privileged user and see what happens.**

### Setup
You need at minimum two accounts at different privilege levels (three is better):
- A confirmed admin/privileged account (to capture a known-working baseline request)
- A regular/low-privilege account (the attacker perspective)
- Optionally, a second regular account (to test lateral escalation between two non-admin users)

### Method

1. Log in as the **admin** account, perform the privileged action through the UI, capture the exact request in Burp (Proxy history or Repeater).
2. Log in as the **regular** account in a separate browser session/incognito window, capturing that session's valid auth token/cookie.
3. In Burp Repeater, take the **admin's captured request** and swap only the authorization material (session cookie, `Authorization: Bearer` token, or API key) for the **regular user's** credential — leave everything else identical (method, path, body).
4. Send it. Observe the response.

### Piece-by-piece breakdown of this exact test

```
Original (admin) request:
POST /api/v1/admin/users/41/promote HTTP/1.1
Host: target-api.com
Authorization: Bearer eyJhbGc...{admin-JWT}...
Content-Type: application/json

{"newRole": "admin"}
```
```
Modified (regular user) request:
POST /api/v1/admin/users/41/promote HTTP/1.1
Host: target-api.com
Authorization: Bearer eyJhbGc...{regular-user-JWT}...
Content-Type: application/json

{"newRole": "admin"}
```

- **What's being tested:** whether the server-side handler for this route checks `role` on the authenticated caller before executing the promotion, or only checks that *a* valid, authenticated session is attached.
- **What a vulnerable response looks like:** `200 OK` / `302` with a success body, and — critically — you must **verify server-side state actually changed** (log back in as the target user, or re-fetch their profile, to confirm `role` actually became `admin`). A `200` alone isn't proof; some apps return `200` with a fake-success body while silently no-opping the write, so state verification is a required step, not optional.
- **Why the check fails when it does:** the handler function pulled `req.user` (proving authentication succeeded) but never branched on `req.user.role`. This is the single most common BFLA root cause — authentication middleware and authorization middleware are two separate pieces of code, and it's extremely common for a route to have the first wired up and the second forgotten, especially on newer or less-reviewed endpoints (admin features tend to get added later, by fewer reviewers, under more time pressure).

This baseline test alone finds a large fraction of real BFLA bugs. Everything below is for when the *naive* version doesn't work and the endpoint has *some* check, but an incomplete one.

---

## 1. HTTP method switching

**Concept:** some backends implement authorization at the level of "this route + this method" rather than "this route," and forget to replicate the check across every method the underlying framework auto-registers.

### Example scenario
The app has a "view own profile" feature (`GET`, unauthenticated-safe) and an "admin edit any profile" feature (`PUT`, meant to be admin-only) — both routed to the same path in the framework's router, because REST convention maps CRUD verbs to one resource path.

```
Step 1 — confirm the protected method is actually blocked:
PUT /api/v1/users/41 HTTP/1.1
Authorization: Bearer <regular-user-JWT>
Content-Type: application/json

{"role": "admin"}

Response: 401 Unauthorized
```

```
Step 2 — the actual bypass, method switch to GET carrying the same intent via query string,
or switch to a method the guard middleware doesn't explicitly enumerate:

GET /api/v1/users/41?role=admin HTTP/1.1
Authorization: Bearer <regular-user-JWT>

or:

PATCH /api/v1/users/41 HTTP/1.1
Authorization: Bearer <regular-user-JWT>
Content-Type: application/json

{"role": "admin"}

Response: 200 OK
```

### Piece-by-piece: why this works

- **What's being tested:** whether the authorization middleware is bound to *specific* HTTP verbs (e.g., a route-guard config that explicitly lists `['PUT', 'DELETE']` as requiring the admin check) rather than to the *route itself* regardless of verb.
- **Why the check fails:** frameworks like Express, Spring, and Django REST Framework let developers attach middleware per-method on a shared route. If a developer writes `router.put('/users/:id', requireAdmin, updateHandler)` but a separate `router.patch('/users/:id', updateHandler)` was added later for a partial-update feature and the `requireAdmin` guard wasn't copy-pasted onto it, `PATCH` silently reaches the exact same `updateHandler` logic with zero authorization.
- **A documented, near-identical real case:** PortSwigger's "Method-based access control can be circumvented" lab demonstrates this exact pattern — an admin panel's user-promotion action is blocked on `POST` for non-admin sessions, but changing the same request to use `GET` (via Burp's "Change request method" feature) reaches the same handler logic and executes the privileged action, because the access-control check was wired specifically to the `POST` code path.
- **Testing checklist for this pattern:** for every discovered privileged endpoint, systematically try `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and also malformed/uncommon methods like `POSTX` (some frameworks fall through to a permissive default handler on an unrecognized method rather than rejecting it outright — this is itself a discovery signal, since a response of "missing parameter" instead of "method not allowed" tells you the request *reached application logic*, just failed a body-shape validation, which the correctly-shaped request will then pass).

---

## 2. Endpoint path manipulation

**Concept:** the same underlying data/action is reachable via two different path structures — a "public" one that's properly gated, and an internal/legacy/versioned one that isn't.

### Example scenario

```
Blocked (properly gated):
GET /api/v2/admin/user/41 HTTP/1.1
Authorization: Bearer <regular-user-JWT>

Response: 403 Forbidden
```

```
Bypass — try path variants: different casing, versioning, trailing structure,
path traversal-style normalization tricks, or nesting under a "safe" parent:

GET /api/v1/admin/user/41 HTTP/1.1        (older API version, checks not ported forward)
GET /API/v2/admin/user/41 HTTP/1.1        (case sensitivity in routing/WAF rule, not backend)
GET /api/v2/admin//user/41 HTTP/1.1       (double slash — some routers normalize differently than gateway/WAF layer)
GET /api/v2/user/../admin/user/41 HTTP/1.1 (path traversal segment reaching same route differently)
GET /api/v2/users/41/../../admin/user/41 HTTP/1.1
GET /api/v2/admin/user/41/ HTTP/1.1       (trailing slash — some frameworks route this identically, some gateway ACL rules match on exact string only)

Response: 200 OK (on whichever variant the backend router normalizes to
the same handler, but the ACL rule/WAF signature was written to match
only the exact canonical string)
```

### Piece-by-piece: why this works

- **What's being tested:** whether the access-control enforcement point (often a reverse proxy rule, an API gateway route ACL, or a regex-based middleware check) uses the **exact same normalization logic** as the actual application router underneath it.
- **Why the check fails:** this is a classic **inconsistent normalization** bug. A gateway or WAF ACL rule might say "block `/admin/*`" using a literal or slightly naive regex, while the backend web framework normalizes `//`, `/./`, `/../`, trailing slashes, and case differently (or not at all) before matching a route. If the enforcement layer and the routing layer disagree on what counts as "the same path," an attacker just needs to find one string that both (a) the gateway's ACL rule doesn't recognize as `/admin/*`, and (b) the backend router still resolves to the actual admin handler.
- **This maps directly to PortSwigger's "URL-based access control can be circumvented" lab**, where a front-end reverse proxy blocks direct requests to `/admin`, but the same panel is reachable via a URL structure the proxy doesn't recognize as matching its block rule (e.g., appending a value after the path that the proxy's exact-match rule doesn't account for, while the backend still routes it correctly), and can also be reached indirectly using the `X-Original-URL` / `X-Rewrite-URL` header trick where a front-end trusts a header to determine the "real" path for logging/rewriting purposes while a back-end component uses it for actual routing decisions.

---

## 3. Parameter-based role manipulation in the request body

**Concept:** the API accepts a role/permission-related field in a write request (profile update, registration, account creation), and the server either doesn't validate that the caller is permitted to set that specific field, or doesn't validate it at all — it just persists whatever's in the body.

### Example scenario

```
Legitimate request the app's own frontend sends (profile update, no role field
because the UI form doesn't expose one):

PATCH /api/v1/users/41 HTTP/1.1
Authorization: Bearer <regular-user-JWT>
Content-Type: application/json

{"email": "wiener@example.com", "displayName": "wiener"}
```

```
Bypass — inject the field the response body revealed during discovery
(recall 02-discovery-methodology.md, step 4 — response field inference):

PATCH /api/v1/users/41 HTTP/1.1
Authorization: Bearer <regular-user-JWT>
Content-Type: application/json

{"email": "wiener@example.com", "displayName": "wiener", "roleId": 2}
```

### Piece-by-piece: why this works

- **What's being tested:** whether the backend's update handler does field-level allow-listing (only persisting fields the frontend is *supposed* to send) or naive mass-binding (taking the entire request body and writing every key straight to the database record, trusting the client to only send "appropriate" fields).
- **Why the check fails:** this is a mass-assignment root cause manifesting as BFLA specifically because the field being over-assigned (`roleId`) controls **function-level privilege**, not just data content. (Note the overlap here with API3:2023 BOPLA/Mass Assignment — the mechanism is identical; whether you classify the finding as BFLA or BOPLA in a report depends on framing: if the impact is "I changed my own privilege level," BFLA is the more precise label since the end result is unauthorized function access; if the impact is "I changed a data field I shouldn't be able to touch, with no privilege implication," it's BOPLA. Document both angles when the finding straddles the line — this is exactly the kind of honest, precise classification a bug bounty triager will respect.)
- **A documented, near-identical real case:** PortSwigger's "User role controlled by request parameter" and "User role can be modified in user profile" labs are exact matches for this pattern — a hidden or client-modifiable `roleid` parameter accepted on a profile-update endpoint, with no server-side check that the caller is permitted to set it to a privileged value.
- **Where to find candidate field names:** anywhere a response body (even one you're not editing) echoes back fields like `role`, `roleId`, `isAdmin`, `permissions`, `accountType`, `tier`, `scope`, `groupId`. If the API shows it to you on read, always try sending it back on write, even into unrelated update endpoints (registration forms are a particularly common soft spot, since account-creation code paths are often less carefully reviewed than the main admin-management ones).

---

## 4. Vertical vs lateral privilege escalation — testing both directions

### Vertical escalation (regular user → admin function)
Covered by every example above. The test axis is: **same user, attempting a higher tier of function.**

### Lateral escalation into another user's privileged scope
The test axis shifts: **User A (regular) attempting to reach or manipulate a function that is legitimately scoped to User B**, where User B might hold elevated privilege (e.g., User B is a team admin, and User A wants to reach User B's team-admin panel or perform an action *as* or *against* User B's elevated context).

```
Example: multi-tenant SaaS app, User A is a regular member of Team X,
User B is the admin of Team Y (different tenant).

Confirm User B's admin action (captured while testing with a cooperating
test account, or inferred from discovery):
POST /api/v1/teams/Y/members/99/remove HTTP/1.1
Authorization: Bearer <UserB-admin-JWT>

Test as User A, same team-scoped admin action, wrong team + wrong role:
POST /api/v1/teams/Y/members/99/remove HTTP/1.1
Authorization: Bearer <UserA-regular-JWT>
```

- **What's being tested:** whether the authorization check validates **two dimensions simultaneously** — (1) does the caller have the admin *role*, and (2) is the caller's admin role scoped to *this specific tenant/team/resource*. A common flaw is checking only dimension 1: "is this user an admin of *anything*?" rather than "is this user an admin *of team Y specifically*." A user who is a legitimate admin of their own small team can sometimes use that same admin-flagged token to manage an entirely different tenant's team, because the check for "is admin" never cross-referenced "admin of which team" against the target resource's actual tenant ID.
- **Why this is classified as BFLA and not BOLA:** the object being acted on (`members/99`) does belong to a real, existing scope — this isn't "wrong ID guessing" in the BOLA sense of swapping a resource identifier at the same permission tier. The break is that a **team-admin-only function** (`remove member`) is reachable by a caller whose admin claim doesn't actually cover this function's scope — the function-level gate (role = team admin) exists but doesn't correctly validate *which* team the role applies to.

---

## 5. WAF / API Gateway detection & bypass considerations for BFLA

As stated in the overview file, this is **not a primary control layer for BFLA**, and this section explains the mechanics of why, plus the narrow cases where gateway configuration itself becomes part of the finding.

### How WAFs/gateways typically approach this vulnerability class (and why it mostly doesn't apply)

- **Signature/pattern matching** (classic WAF): looks for known-malicious *content* in a request — SQLi tokens, script tags, traversal sequences. A BFLA exploit request has no malicious content; the body `{"newRole": "admin"}` is a perfectly well-formed, benign-looking JSON payload that also happens to be exactly what a legitimate admin request looks like. There is no string pattern to signature against.
- **Rate-based/anomaly detection**: can incidentally flag a testing session that rapidly probes many `/admin/*` paths or sends many requests with unusual role/permission fields, but this detects *testing behavior volume*, not the vulnerability itself — a single, one-shot exploit request from a real attacker who already knows the exact path and payload will not trip volume-based rules at all.
- **Gateway-level route ACLs** (the one case that's actually relevant): as covered in the path manipulation section above, some API gateways (Kong, AWS API Gateway, Apigee, Azure APIM) can enforce role/scope checks *at the gateway*, before a request even reaches the backend. When this is the only enforcement point, the gateway's ACL configuration **is** the authorization control, and gaps in it are BFLA findings against the gateway layer rather than the application layer. Test the same method-switching and path-manipulation tricks specifically against the gateway's routing rules — a common real gap is a gateway policy written to match `POST /admin/**` that doesn't account for `PATCH`, `PUT`, or case/encoding variants, exactly mirroring the backend-level bugs but one layer up the stack.
- **JWT/OAuth scope validation at the gateway**: some gateways validate JWT `scope` or `aud` claims before forwarding, which is a legitimate function-level control if configured correctly — but is only as strong as the scope granularity defined. A gateway that checks "does this token have *any* valid scope" rather than "does this token have the *specific* scope required for *this* route" reproduces the exact same under-scoped check problem as an application-layer bug, just implemented in gateway config (e.g. Kong ACL plugin, Apigee policy XML) instead of application code.

### Practical takeaway for testing methodology

Don't treat "there's a WAF/gateway in front of this API" as a reason to look for clever encoding tricks to sneak a BFLA payload past it — that instinct belongs to injection-class vulnerabilities, not authorization-class ones. Instead:
1. Confirm whether the gateway itself is doing any role/scope enforcement (test method-switching and path variants directly against gateway-fronted routes, same as you would against backend routes).
2. If the gateway is a pure reverse proxy / rate limiter with no authz logic, treat it as irrelevant to this specific vulnerability class and focus entirely on the application layer.
3. If your discovery/testing traffic gets rate-limited or blocked, that's an engagement-logistics issue (slow down, spread requests, coordinate with the client's security team per rules of engagement) — not a security control you need to "defeat" to prove the BFLA finding is real.

---
*Every technique above should be validated with actual state verification (re-fetch the target resource, confirm the change persisted) — a 200 response alone is not proof of a working BFLA exploit.*
