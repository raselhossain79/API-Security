# BOLA — Testing Methodology (Manual, Step-by-Step)

This file covers the manual testing process. Every step explains exactly what is being changed in a request and why that specific change is what proves or disproves an authorization bypass — not just "swap the ID and see what happens."

---

## 1. Preparation — Test Account Setup

Before any request is sent, set up accounts deliberately:

- **Account A** and **Account B** — two accounts of the *same* privilege tier, same tenant/organization. Used for horizontal privilege escalation testing.
- **Account C (Tenant X)** and **Account D (Tenant Y)** — two accounts registered under *separate* organizations/workspaces, if the target is multi-tenant SaaS. Used for cross-tenant testing.
- Keep each account's **session token/API key/JWT** captured separately and labeled. You will be swapping tokens against object IDs constantly, and mixing them up produces false results.
- If the API is versioned or has both a web-facing and mobile-facing surface, authenticate through both if possible — mobile-only endpoints are a common place where authorization checks are inconsistently applied.

---

## 2. Baseline Mapping Before Testing Begins

You cannot test what you haven't inventoried. This step is what most separates BOLA testing from classic web IDOR testing (see file 1, section 2).

**Step 2.1 — Pull the API specification if one exists.**
Check for `/swagger.json`, `/openapi.json`, `/api-docs`, `/v1/api-docs`, or a `.well-known` discovery endpoint. If found, this is the fastest way to get a complete list of every endpoint, every HTTP method per endpoint, and every parameter name — including endpoints the UI never calls directly.

*Why this matters:* an endpoint absent from the spec but present in mobile app traffic (or vice versa) is exactly the kind of coverage gap that produces missed findings when testers rely on UI-driven crawling alone.

**Step 2.2 — If no spec exists, build the map manually via traffic capture.**
Route all traffic (web UI, mobile app via a proxy-aware emulator, browser extension calls) through Burp. Use Burp's site map / Logger to build an inventory of every unique endpoint + method combination observed. Pay attention to:
- Any endpoint containing a numeric, UUID-shaped, or hash-shaped path segment.
- Any endpoint whose JSON *request body* contains a field ending in `_id`, `Id`, `_ref`, `_uuid`, or similar.
- Any endpoint whose JSON *response body* contains such fields, even if the current screen doesn't display them.

**Step 2.3 — Catalog object ownership relationships.**
Write down, for each object type, which user/tenant is supposed to own it (e.g., "orders belong to a user," "invoices belong to an org," "vehicle records belong to a user within an org"). This ownership model is what you'll be violating in each subsequent test.

---

## 3. Horizontal Privilege Escalation — Step-by-Step

**Goal:** prove that Account A, using Account A's own valid token, can read or modify an object that belongs to Account B.

**Step 3.1 — Establish the baseline request.**
Log in as Account A. Trigger the action that legitimately retrieves Account A's own object (e.g., viewing an order). Capture this request in Burp:

```
GET /api/v1/orders/1042 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...A_TOKEN
```

Confirm the response returns Account A's order data with a `200 OK`.

**Step 3.2 — Identify Account B's object ID.**
Log in as Account B in a separate session (use Burp's separate tab/session or a second browser profile so cookies/tokens don't collide). Trigger the equivalent action and note Account B's object ID from the response — e.g., `1043`.

**Step 3.3 — Send the modified request.**
Take the *exact* request captured in Step 3.1 (Account A's token, unchanged) and change only the object ID in the path from `1042` to `1043`:

```
GET /api/v1/orders/1043 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...A_TOKEN
```

**What is being changed and why:** only the `orders/{id}` path segment is modified. The `Authorization` header remains Account A's own legitimate, unmodified token. This isolates the test to a single variable: does the server check that the object ID in the path actually belongs to the identity in the token? If the response returns Account B's order data with a `200 OK`, the object-level authorization check is missing — the server is trusting the path parameter alone to select the record, with no cross-reference against the authenticated identity.

**Step 3.4 — Rule out false positives.**
Before declaring success, check:
- Does the response actually contain Account B's *real* data, or a generic/redacted placeholder? Some apps return a sanitized "not found" object with a `200` status rather than a proper `403`/`404` — read the response body, don't just check the status code.
- Is there a subtle difference in response shape (e.g., a `"restricted": true` flag) that a status-code-only check would miss? Always diff the full response body between an authorized and unauthorized fetch.
- If the response *is* a redirect to a login page (`302`) or an "access denied" page, check whether that redirect response still leaks data in its body — the note in file 1 about GUID-based IDOR mentions this exact pattern: redirects can still carry sensitive fragments even when the primary access is denied.

**Step 3.5 — Repeat for state-changing methods, not just read.**
Repeat the same substitution using `PUT`, `PATCH`, and `DELETE` against the same object ID — this connects to the HTTP-method-coverage testing in section 5 below. A read-only check on `GET` does not prove write/delete paths are equally protected, and in practice they very often are not, because developers frequently add the ownership check to the "view" controller and forget to replicate it on the "edit" or "delete" controller.

---

## 4. Cross-Tenant BOLA in Multi-Tenant SaaS — Step-by-Step

**Goal:** prove that a user in Tenant X can access an object belonging to Tenant Y — a strictly more severe finding than horizontal escalation within one tenant, because it breaks the platform's outermost data isolation boundary.

**Step 4.1 — Identify how tenancy is scoped in the URL/data model.**
Look for a `tenant_id`, `org_id`, `workspace_id`, or `account_id` appearing in:
- The URL path itself, e.g. `/api/v1/orgs/{org_id}/invoices/{invoice_id}`
- A request header, e.g. `X-Tenant-ID: 55`
- A claim inside the JWT payload (base64-decode the token's middle segment and inspect it)
- Implicitly, with no tenant identifier ever sent by the client at all — meaning the server is expected to derive tenancy purely from the authenticated session server-side (this is actually the *safest* pattern if implemented correctly, and the *most dangerous* if the server instead trusts any client-supplied tenant value alongside it)

**Step 4.2 — Test the case where tenant ID and object ID are both in the path.**
As Tenant X's user, request:

```
GET /api/v1/orgs/55/invoices/900 HTTP/1.1
Authorization: Bearer <Tenant_X_token>
```

Then substitute Tenant Y's known `org_id` (discovered from Tenant Y's own session) while keeping Tenant X's token:

```
GET /api/v1/orgs/61/invoices/900 HTTP/1.1
Authorization: Bearer <Tenant_X_token>
```

**What is being changed and why:** the `org_id` path segment (`55` → `61`) is changed while the token stays Tenant X's own. This tests whether the server validates that the *token's* tenant matches the *path's* tenant, or whether it simply trusts whichever `org_id` appears in the URL to scope the query. If Tenant Y's invoice data is returned, the server is authorizing based on the path parameter, not the authenticated session's actual tenant membership.

**Step 4.3 — Test tenant ID spoofing via header or body, independent of the path.**
If tenancy is also (or instead) communicated via a header like `X-Tenant-ID`, repeat the test by leaving the URL identical but changing only that header:

```
GET /api/v1/invoices/900 HTTP/1.1
Authorization: Bearer <Tenant_X_token>
X-Tenant-ID: 61
```

**What is being changed and why:** only the `X-Tenant-ID` header value changes, from Tenant X's own ID to Tenant Y's. This isolates whether the backend derives the effective tenant scope from a client-controllable header (unsafe) versus deriving it strictly from server-side session state tied to the token (safe). This is a very common real-world gap because header-based tenant switching is often added later for admin/support tooling and left reachable by ordinary users.

**Step 4.4 — Test JWT tenant claim tampering.**
If the tenant ID is embedded as a claim inside the JWT payload and the signature is not properly re-validated server-side per request (or the app is vulnerable to `alg:none` / weak-secret attacks — a separate JWT-attack topic in your other series), modify the decoded claim, e.g. `"org_id": 55` → `"org_id": 61"`, before re-signing or re-submitting. This overlaps with JWT attack methodology but is worth a direct cross-tenant test pass here since a forged tenant claim *is* a cross-tenant BOLA vector in practice.

---

## 5. BOLA in Non-Obvious Locations

These are the categories most manual testers skip because they only check the URL path.

### 5.1 — Object references hidden in the request body

The URL/path parameter can be entirely correct and properly scoped to the authenticated user, while a *body* field still contains an unchecked object reference. Example — a "transfer funds" endpoint:

```
POST /api/v1/accounts/me/transfer HTTP/1.1
Authorization: Bearer <Account_A_token>
Content-Type: application/json

{
  "amount": 100,
  "recipient_account_id": 4471
}
```

The path (`accounts/me`) is correctly scoped to the authenticated user — that part is fine. But `recipient_account_id` is a second, independent object reference inside the body. The test here is not to change the path but to test **which values are legitimate to place in `recipient_account_id`** — e.g., can Account A supply the ID of an account it should have no relationship to at all in order to, say, view its balance in the transfer confirmation response, or trigger an action against it it shouldn't be able to (like initiating a request that debits an account not owned by the caller and not an authorized recipient)? The key testing discipline: **read every field in every JSON body for anything ID-shaped, not just the URL.** A URL-only test methodology systematically misses this entire class.

### 5.2 — References disclosed in one response and reused in a later request

This is a two-step chain and needs to be tested as a chain, not a single request:

**Step 1:** Call an endpoint that returns more data than the current screen displays. E.g.:

```
GET /api/v1/profile HTTP/1.1
Authorization: Bearer <Account_A_token>
```

Response:
```json
{
  "username": "accountA",
  "linked_invoice_id": 5591,
  "support_ticket_id": 8820
}
```

Neither `linked_invoice_id` nor `support_ticket_id` might be shown anywhere in Account A's own UI — they may be internal fields the frontend simply doesn't render but that are present in the JSON regardless.

**Step 2:** These same field names, once you know they exist, become a *search target* across every other user's response. If Account B's `/profile` response reveals `"linked_invoice_id": 5602"`, test whether `GET /api/v1/invoices/5602` is reachable using Account A's token. **What's being tested:** whether the invoice-fetch endpoint re-validates ownership independently, or implicitly trusts that if you know an invoice ID, you must have gotten it legitimately — a dangerous and common assumption once you understand that the ID was disclosed via an unrelated, seemingly harmless endpoint.

*Practical technique:* use Burp's "Search" across the entire proxy history for numeric/UUID patterns once you've identified an object ID format, to find every place that ID type has ever leaked in a response — not just the one place you first noticed it.

### 5.3 — BOLA via HTTP method coverage gaps

The single most common oversight: developers add an ownership check to the endpoint their frontend actually calls (often `GET`, for the display view) and never replicate it on `POST`/`PUT`/`PATCH`/`DELETE` for the same resource, because the frontend "never calls it that way" — but the backend route still accepts the method.

**Step 5.3.1 — Enumerate methods, don't assume.**
For every object-referencing endpoint found in mapping (section 2), explicitly test `OPTIONS` first to see what the server itself declares as allowed:

```
OPTIONS /api/v1/orders/1043 HTTP/1.1
Authorization: Bearer <Account_A_token>
```

Response header `Allow: GET, PUT, DELETE` tells you which methods to test even if the frontend only ever issues `GET`.

**Step 5.3.2 — Test each declared method against another user's object ID, using your own token.**
```
DELETE /api/v1/orders/1043 HTTP/1.1
Authorization: Bearer <Account_A_token>
```
Where `1043` belongs to Account B. **What's being changed and why:** the method itself (`GET` → `DELETE`) against an object ID that isn't yours. If `GET` was properly protected (403) but `DELETE` succeeds (200/204), the authorization check exists on the read path but was never applied to the destructive path — a far higher-severity finding than a read-only BOLA, since it demonstrates unauthorized data destruction/modification, not just disclosure.

**Step 5.3.3 — Test method-override headers.**
Some frameworks honor `X-HTTP-Method-Override` or `X-Method-Override` headers to let a `POST` simulate another verb — sometimes bypassing gateway-level method restrictions that only inspect the literal HTTP method line rather than the override header:
```
POST /api/v1/orders/1043 HTTP/1.1
Authorization: Bearer <Account_A_token>
X-HTTP-Method-Override: DELETE
```
**What's being tested:** whether a platform-layer restriction (e.g., "only GET is allowed on this route at the gateway") is enforced only against the literal method and can be routed around via an override header the backend application framework still honors.

### 5.4 — Nested resource / parent-child ID combinations

For paths like `/api/orgs/{org_id}/users/{user_id}/documents/{doc_id}`, test mismatched combinations deliberately: a valid `org_id` you belong to, paired with a `user_id` or `doc_id` that belongs to a *different* org entirely. Some implementations validate that the outermost path segment matches the token's tenant, but never verify that the innermost object ID is actually a *child* of the specific parent stated in the URL — allowing an attacker to reference a real object that exists under a completely different parent chain than the one stated in the path.

---

## 6. Summary Checklist for This File

- [ ] Baseline API map built from spec or full traffic capture — not UI-crawl-only
- [ ] Horizontal escalation tested on GET, then repeated on PUT/PATCH/DELETE
- [ ] Cross-tenant tested via path org_id, header org_id, and JWT claim tampering separately
- [ ] Every JSON request body scanned for embedded object references beyond the URL
- [ ] Every JSON response body scanned for object IDs not rendered in the UI, then reused as attack targets
- [ ] OPTIONS called on every object endpoint to reveal all supported methods before assuming GET-only
- [ ] Method-override headers tested against platform-layer method restrictions
- [ ] Nested/parent-child ID combinations tested for parent-mismatch acceptance

---

**Next file:** `03_ID_Type_Bypass_Techniques.md` — how the underlying ID format (sequential, UUID, hashed, GUID, base64) changes what discovery/bypass technique actually applies.
