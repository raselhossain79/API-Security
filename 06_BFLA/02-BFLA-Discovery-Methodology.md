# BFLA — Discovery Methodology

You cannot test for BFLA against an endpoint you don't know exists. Unlike BOLA (where the vulnerable endpoint is usually already visible in the app, just missing an ownership check), BFLA frequently lives on endpoints that are **never rendered in the UI you're given credentials for**. Discovery is therefore the majority of the work.

---

## 1. Path Guessing / Wordlist-Based Discovery

**Mechanism:** Developers follow predictable naming conventions for privileged routes because it's convenient for their own team's mental model. Testers exploit that same predictability.

Common naming patterns to try, layered onto every discovered base endpoint:

```
/admin/...
/administrator/...
/internal/...
/staff/...
/manage/...
/manager/...
/backend/...
/console/...
/_admin/...
/api/admin/...
/api/v1/admin/...
/api/internal/...
```

And role/action-style variants on existing user endpoints:

```
/api/users/{id}          -> /api/admin/users/{id}
/api/users/{id}          -> /api/users/{id}/admin
/api/orders               -> /api/admin/orders
/api/orders               -> /api/orders/manage
/api/reports              -> /api/admin/reports/export
```

**Tooling:**
- **ffuf / feroxbuster / dirsearch** with API-specific wordlists (SecLists' `api/` and `swagger-common.txt` are good starting points) run against every base path discovered from the app's normal traffic.
- Fuzz **both the path** and **the HTTP method** — a path might 404 on GET but exist on POST/PUT.

**Why this works:** rate limiting and WAFs are usually tuned for the public-facing paths a scanner would naturally crawl (`/login`, `/search`), not for a deep, targeted wordlist against `/api/*/admin/*` — so this technique has a high signal-to-noise ratio when scoped correctly.

---

## 2. JavaScript Source Mining

**Mechanism:** SPAs (React/Vue/Angular) ship the *entire* client-side routing and API-calling logic to the browser, including code paths for roles the current user doesn't have. Admin panels are frequently bundled into the same JS build as the regular user app, just conditionally rendered — the code (and the endpoints it calls) is present even if the UI element is hidden.

**Workflow, step by step:**

1. **Pull every JS bundle** the app loads (Burp's site map, or `wget`/`curl` each `<script src>`). Don't skip chunked/lazy-loaded bundles — admin-only code is often split into its own chunk that only loads *after* a role check on the frontend, but the chunk file itself is still statically served and downloadable regardless of your role.
2. **Check for exposed sourcemaps** (`main.js.map`, `chunk.abc123.js.map`). If present, tools like `source-map-explorer` or manual reconstruction give you near-original, unminified source — including original function/route names like `getAdminUserList()` or `AdminPanel.jsx`.
3. **Grep the (minified or unminified) JS for API call patterns:**
   ```
   grep -oE "(fetch|axios\.(get|post|put|delete|patch))\([\"'][^\"']+[\"']" bundle.js
   grep -oE "['\"]\/api\/[a-zA-Z0-9_\/\-{}]+['\"]" bundle.js
   ```
4. **Run LinkFinder or similar** against each JS file to automatically extract endpoint-like strings:
   ```
   python3 linkfinder.py -i https://target.com/static/js/main.abc123.js -o cli
   ```
5. **Look specifically for role/permission strings** near route definitions — `role === 'admin'`, `isAdmin`, `hasPermission('user:delete')`. Even in minified code these string literals usually survive minification and point you straight at the gated function names and the routes they call.

**Why this works:** the frontend role check ("hide this button unless `user.role === 'admin'`") is a UI convenience, not a security boundary. Finding the JS that would call `/api/admin/users/{id}/ban` tells you the exact request to attempt directly — bypassing the UI gate entirely.

---

## 3. API Documentation Mining

**Mechanism:** OpenAPI/Swagger specs and GraphQL schemas are frequently generated automatically from the backend code and describe the *entire* API surface, including admin-only operations, regardless of who is allowed to call them. Documentation exposure is an authorization failure multiplier: it doesn't create the BFLA bug, but it hands you the map to every candidate endpoint.

**Where to look:**

```
/swagger.json
/swagger-ui.html
/swagger-ui/
/api-docs
/api/swagger.json
/openapi.json
/v2/api-docs
/v3/api-docs
/redoc
/graphql (introspection query)
```

**GraphQL introspection example — broken down:**

```graphql
POST /graphql
Content-Type: application/json

{
  "query": "query IntrospectionQuery { __schema { types { name fields { name } } } }"
}
```
- **What's being tested:** whether the GraphQL endpoint has introspection enabled in production.
- **Why it matters for BFLA:** introspection returns every mutation the schema defines — including `adminDeleteUser`, `adminResetBilling`, `impersonateUser` — even if the current session has no permission to call them. You now have a complete list of privileged mutation names to test directly, rather than guessing.

**In a Swagger/OpenAPI JSON response, scan specifically for:**
- Path segments containing `admin`, `internal`, `manage`, `staff`, `support`.
- Operation `tags` or `summary` fields mentioning roles (`"tags": ["Admin"]`).
- Endpoints with no `security` field defined, or a `security` field that's empty — this often means the spec author didn't wire up auth requirements in the doc even if the backend does enforce them (or, just as often, because the backend *doesn't*).

---

## 4. Response Field Inference

**Mechanism:** APIs frequently over-return data — the backend serializes an entire internal object (including fields the frontend never displays) and lets the frontend cherry-pick what to render. Fields present in a response but unused by the UI are a strong signal of adjacent, undocumented functionality.

**What to look for in every response body, even ones that "look normal":**

```json
{
  "id": 1042,
  "username": "raselhossain79",
  "email": "user@example.com",
  "role": "user",
  "permissions": [],
  "isAdmin": false,
  "accountType": "standard",
  "_links": {
    "self": "/api/users/1042",
    "adminActions": "/api/admin/users/1042/actions"
  }
}
```

**Breakdown of what each field tells you:**
- `"role": "user"` and `"permissions": []` — confirms the API has a role/permission model at all, which means role-gated functions exist somewhere, even if you haven't found them yet.
- `"isAdmin": false` — a boolean like this is a strong hint the backend checks this exact field server-side, and is also a candidate for parameter-based role manipulation testing (file 03, section 3).
- `"_links": { "adminActions": ... }` — HATEOAS-style responses sometimes literally hand you the privileged endpoint URL in the response of a completely ordinary, low-privilege request. This is a direct, low-effort discovery win — always inspect `_links`, `related`, `actions`, or similar hypermedia fields in every JSON response.

Also check **HTTP response headers** — some frameworks leak internal routing info via headers like `X-Powered-By`, `X-Route`, or verbose `Allow:` headers on `OPTIONS` requests (see section 5).

---

## 5. OPTIONS Method Enumeration

**Mechanism:** Many frameworks automatically respond to `OPTIONS` requests with an `Allow:` header listing every HTTP method wired up for that route — including ones with no corresponding UI action.

```
OPTIONS /api/users/1042 HTTP/1.1
Host: target.com
Authorization: Bearer <low-priv-token>
```

**Example response:**
```
HTTP/1.1 204 No Content
Allow: GET, POST, PUT, DELETE, PATCH
```

**Breakdown:** the UI for this endpoint only ever calls `GET` (view profile). The `Allow` header confirms `PUT`, `DELETE`, and `PATCH` handlers also exist on the exact same URL. Each of those is a separate candidate for the HTTP method switching pattern in file 03 — and each needs to be tested independently with the low-privilege token, because the authorization check (if any) may differ per verb even on an identical path.

---

## 6. Testing Non-Admin Credentials Against Discovered Endpoints — Baseline Workflow

Once you have a candidate list from sections 1–5, the actual test is mechanically simple but must be done systematically:

1. **Authenticate as the lowest-privileged role available** (regular user, free tier, unverified account — whichever is lowest). Capture the session token/cookie/JWT.
2. **Authenticate as a higher-privileged role if you have one** (admin test account, or a role provided by the client for authorized testing) purely as a baseline to confirm the endpoint *does* something meaningful and isn't just dead code.
3. **Replay the exact same request** (method, path, headers, body) using only the low-privileged token.
4. **Classify the response, not just the status code:**
   - `200`/`201`/`204` with the expected effect (data returned, record created/modified) → confirmed BFLA.
   - `200` with an empty or error-shaped JSON body but a "successful" HTTP status → **false positive risk**; many APIs return `200 OK` with `{"error": "forbidden"}` in the body instead of a proper `403`. Always read the body, never trust the status code alone.
   - `403`/`401` → correctly enforced, move to next candidate.
   - `404` → could mean "correctly hidden" or could mean "route doesn't exist under this exact path" — worth re-confirming the path is right (via section 5's `OPTIONS` trick or re-checking JS source) before ruling it out.
5. **Confirm real-world effect where safe to do so** — for state-changing actions (POST/PUT/DELETE), coordinate scope and test data with the client before executing against production data. A "successful" `DELETE /admin/users/{id}` response is not proof of impact until you've confirmed (safely, in an authorized test environment or with disposable test data) that the deletion actually occurred.

---

## 7. Practice Environments

- **crAPI** ships multiple BFLA-relevant flows — most notably around the **workshop/mechanic** vs **regular user** role split and admin-only vehicle/service functions. It's the most direct hands-on BFLA practice available since PortSwigger's labs, being generic web-app labs, don't have an API-specific role model (agent/tenant/mechanic) the way crAPI does.
- **PortSwigger Web Security Academy** doesn't have API-labeled BFLA labs, but its **Access Control** category maps directly onto the same mechanism (missing function-level checks) — see file 05 for the exact lab list in progression order and an honest note on where the mapping is and isn't a perfect fit.

---

## 8. What's Next

**File 03** covers the three dominant BFLA exploitation patterns once a candidate endpoint has been found: HTTP method switching, endpoint path manipulation, and parameter-based role manipulation — each broken down request by request.
