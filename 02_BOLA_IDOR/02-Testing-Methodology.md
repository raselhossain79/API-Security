# BOLA Testing Methodology — Manual, Step by Step

This file covers the manual testing process. It assumes Burp Suite Community Edition is
configured as an intercepting proxy and traffic from the target application (browser, mobile
app, or direct API client such as Postman/Insomnia) is routed through it. The Burp-specific
tooling workflow (Repeater layouts, Intruder attack configs, Autorize setup) is covered
separately in `04-Burp-Suite-Testing-Workflow.md` — this file focuses on the manual logic that
tooling automates later.

## 1. Prerequisite: build your test accounts and objects before testing

You cannot test BOLA with a single account. Set this up first, every time:

**For horizontal privilege escalation:**
- Two low-privilege accounts, same tenant/organization (Account A, Account B).
- Each account must own at least one distinct object of every type the API manages (order,
  document, message, profile field, invoice, etc.), so you have something concrete to try to
  reach from the other account.

**For cross-tenant BOLA:**
- Two accounts in **two separate, independently created tenant/organization signups** —
  not two users invited into the same workspace. If the product is a B2B SaaS tool with a
  "create your organization" signup flow, run that signup flow twice, fully independently,
  ideally from different email domains, to guarantee no shared tenant scoping exists between
  them.
- Each tenant needs at least one populated object per resource type, same as above.

Record every object ID you own (from both accounts/tenants) in a simple table before you
start: resource type, ID value, ID format (sequential / UUID / hash / encoded), which
account/tenant owns it. You will cross-reference this constantly.

## 2. Step-by-step: horizontal privilege escalation testing

**Step 1 — Enumerate every endpoint that accepts an object identifier.**
Using Burp's proxy history (or an OpenAPI/Swagger spec if available), list every endpoint
where a request contains an ID referring to a specific object: in the path
(`/api/orders/{id}`), in the query string (`?order_id=`), or inside a JSON body
(`{"orderId": 4471}`). Do this exhaustively — BOLA hunting is a coverage exercise, not a
one-shot guess.

**Step 2 — For each endpoint, capture a baseline request as Account A, for Account A's own
object.**
Confirm the request returns Account A's own data normally, with a 200-class response.

**Step 3 — Send the same request, same session/token (still logged in as Account A), but
swap the object ID to one owned by Account B.**
This is the core test. Everything else about the request stays identical: same
Authorization header, same cookies, same headers, same method. The **only** variable changed
is the object identifier.

```
GET /api/v1/invoices/8841 HTTP/1.1
Host: api.target.com
Authorization: Bearer <Account A's token>
```
becomes
```
GET /api/v1/invoices/8842 HTTP/1.1
Host: api.target.com
Authorization: Bearer <Account A's token>
```
Only the invoice ID (`8841` → `8842`, Account B's known invoice) changed. The token proves who
is asking. The ID says which object they're asking for. If the server returns Account B's
invoice data with a 200, the object-level authorization check does not exist for this endpoint
— the server correctly authenticated the caller but never verified the caller owns object
`8842`.

**Step 4 — Repeat step 3 for every HTTP method the endpoint supports, not just GET.**
A very common pattern: GET is correctly protected (returns 403/404 for another user's object),
but PUT, PATCH, or DELETE on the exact same resource path is not, because the read path and
the write path were implemented by different people at different times and only the read path
got an ownership check added. Test each method independently and record the result per method.

```
PUT /api/v1/invoices/8842 HTTP/1.1
Authorization: Bearer <Account A's token>
Content-Type: application/json

{"status": "cancelled"}
```
If this succeeds against Account B's invoice while GET on the same ID correctly 403s, you have
found a write-level BOLA that is more severe than a read-level one — this is a modification/
deletion of another user's data, not just disclosure.

**Step 5 — Interpret the response correctly.**
Do not rely on status code alone.
- `200 OK` with the target's actual data in the body → confirmed BOLA.
- `403 Forbidden` or `404 Not Found` with **no** target data in the body → correctly protected
  (unless the 404 leaks something — see next point).
- `403`/`404`/redirect responses that still leak fragments of the target's data in the body,
  headers, or error message → still a confirmed vulnerability (partial data disclosure), even
  though the status code looks like a rejection. Always read the full response body, not just
  the status line.
- Different response times or different error messages for "object doesn't exist" vs "object
  exists but isn't yours" can itself be an information leak (confirms valid ID ranges) even if
  the object data itself isn't returned — note this as a lower-severity finding.

## 3. Step-by-step: cross-tenant BOLA testing

Run steps 1–5 exactly as above, but using your two independently-created tenant accounts
instead of two users in the same tenant, and adding two extra checks specific to
multi-tenancy:

**Step A — Identify the tenant-scoping parameter, if one is visible.**
Some APIs put the tenant/org ID directly in the URL (`/api/orgs/{org_id}/projects/{project_id}`)
or in a header (`X-Tenant-ID: 118`). If so, test both independently:
1. Correct project ID, but swap only the `org_id` to the other tenant's org ID, keeping your
   own token. Does the server check that the token's tenant matches the `org_id` in the path,
   or does it just use whichever `org_id` is in the URL?
2. Correct `org_id` for your own tenant, but swap only the object ID to one that exists in the
   other tenant. This tests whether object lookups are scoped by tenant internally at the
   database layer, independent of what's in the URL.

These are two different failure points and both need to be tested — an API can get one right
and the other wrong.

**Step B — Test endpoints that have no visible tenant parameter at all.**
Many APIs infer tenant scope entirely from the authenticated token server-side and never put a
tenant ID in the request. These endpoints are actually higher-risk for cross-tenant BOLA,
because there is no tenant parameter for a developer to even think about validating — the only
protection is the backend correctly deriving tenant scope from the token on every single query.
Test these the same way as step 3 above (swap only the object ID, same token), since the
tenant boundary here depends entirely on server-side object ownership logic having a tenant
check baked in, not just a user check.

**Step C — Note the severity distinction explicitly in your report.**
A cross-tenant finding should never be reported at the same severity as a same-tenant
horizontal finding. State plainly in the writeup: "this object belongs to a completely
separate customer organization (Tenant ID X vs Tenant ID Y, verified via two independently
registered accounts)" — this is what elevates the finding from High to Critical in most
industry severity frameworks (e.g., a data confidentiality breach across the entire customer
base rather than one peer user).

## 4. Common mistake to avoid: testing only with your own two accounts against yourself

A frequent methodology error is testing Account A against Account A's own second object
(e.g., two invoices you created yourself under one account) and mistaking a correctly-working
"multiple resources under one owner" feature for a BOLA finding. Always confirm the target
object belongs to a **different authenticated identity**, not just a different object ID under
your own account.

## 5. PortSwigger Web Security Academy lab mapping (difficulty-progression order)

PortSwigger's labs are built around traditional web app IDOR, not API-native BOLA, but the
underlying object-ownership-check logic transfers directly. Work these in this order:

1. **User ID controlled by request parameter** — the baseline horizontal escalation pattern:
   swap a visible ID parameter to another user's ID, same session.
2. **User ID controlled by request parameter, with unpredictable user IDs** — introduces
   non-sequential identifiers, forcing you to find the target ID via disclosure elsewhere in
   the app rather than guessing it (directly relevant to the UUID/GUID testing in file 03).
3. **User ID controlled by request parameter with data leakage in redirect** — teaches the
   "the status code looks like a rejection but the body still leaks data" lesson from step 5
   above.
4. **User ID controlled by request parameter with password disclosure** — a write/read hybrid
   showing how a seemingly minor object-level leak (password reset flow tied to a
   user-controlled ID) escalates to full account takeover.
5. **Insecure direct object references** — static file references (chat transcripts) accessed
   via a predictable filename; maps to path-based object references generally.

**Honest gap disclosure:** PortSwigger's Access Control category does not have a lab that
models a genuine multi-tenant SaaS boundary, a JSON-body object reference (all of these labs
use URL/query parameters, not request bodies), or a lab where you must test multiple HTTP
methods against the same object to find an inconsistent authorization check. Those specific
scenarios are covered instead using OWASP crAPI in the labs below, which is intentionally
built as an API-native, multi-service application rather than a single rendered web app.

## 6. crAPI lab mapping (fills PortSwigger's API-native and multi-tenant gaps)

crAPI ("Completely Ridiculous API") is an OWASP-maintained deliberately vulnerable
microservice application built specifically around API Top 10 vulnerabilities. Work these
BOLA-relevant challenges after the PortSwigger labs above:

1. **Access another user's vehicle location** — the object ID here is a GUID, not a sequential
   integer, so the exercise is entirely about *finding* another user's GUID through a
   disclosure point elsewhere in the app (the community/posts feed leaks other users' vehicle
   IDs) rather than guessing it. This is the direct hands-on equivalent of the UUID/GUID
   disclosure-based testing technique covered in file 03.
2. **Access another user's mechanic report** — a `report_id` query parameter behind a
   "contact mechanic" feature; straightforward sequential-ID horizontal escalation, useful as
   a clean confirmation exercise after the GUID challenge above.
3. **Access another user's order details** — an `order_id`-based endpoint that discloses
   sensitive order and partial payment data; a good exercise in confirming a finding's
   severity based on *what* data the object exposes, not just that data leaked.

Real-world note: all three of these crAPI challenge patterns are explicitly modeled by the
crAPI project on vulnerabilities previously found in production APIs at large consumer
platforms — they are not synthetic academic examples.

## 7. What's next

`03-ID-Types-and-Bypass-Techniques.md` covers the specific technique required per ID format
(sequential, UUID, hashed, encoded) and the non-obvious locations BOLA hides in — request
bodies, response-field-derived references, and method-based gaps.
