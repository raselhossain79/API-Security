# BFLA — Discovery Methodology

Finding the vulnerability is rarely the hard part of BFLA testing. **Finding the endpoint** is. Privileged functions are, by design, not linked anywhere in the UI a low-privilege user sees — there's no button to click. This file covers the four main discovery techniques, in the order they're usually most productive.

---

## 1. Path guessing (predictable REST structure)

APIs are disproportionately predictable because REST conventions push developers toward consistent naming. If you have confirmed a base resource path, the admin/privileged sibling is often a small, guessable transformation of it.

### Method
Take every confirmed endpoint for the regular-user role and mechanically apply common privilege-tier prefixes/suffixes and role-scoped path segments:

```
Confirmed (regular user):
GET  /api/v1/users/{id}
GET  /api/v1/users/{id}/orders
POST /api/v1/orders

Guesses to try:
GET  /api/v1/admin/users/{id}
GET  /api/v1/admin/users
GET  /api/v1/internal/users/{id}
GET  /api/v1/users/{id}/admin
GET  /api/v1/staff/orders
GET  /api/v1/orders/all          <- "all" as a privileged variant of a scoped list
GET  /api/v2/admin/users/{id}    <- check older/other versions too
POST /api/v1/users/{id}/role
PATCH /api/v1/users/{id}/status
DELETE /api/v1/admin/orders/{id}
```

**Why this works mechanistically:** most backend codebases share a single router/controller layer per resource, and admin variants are typically added later by the same developers using the same naming habits — `admin/`, `internal/`, `staff/`, `management/`, `_internal`, `/v1/ops/`, or a `?role=` / `?scope=` query parameter bolted onto the *same* base route rather than a truly separate one.

### Practical wordlist categories to brute with Burp Intruder / ffuf against a confirmed base path

- Path segment prefixes: `admin`, `administrator`, `internal`, `staff`, `manage`, `management`, `ops`, `backend`, `superuser`, `root`, `mod`, `moderator`, `support`
- Path segment suffixes on existing resource: `/all`, `/full`, `/export`, `/bulk`, `/force`, `/override`
- Action-style verbs appended to a resource: `/promote`, `/demote`, `/ban`, `/suspend`, `/impersonate`, `/reset-password`, `/verify`, `/approve`

### Piece-by-piece: why this specific request works when it does
```
GET /api/v1/admin/users HTTP/1.1
Host: target-api.com
Authorization: Bearer <regular-user-JWT>
```
- **What's being tested:** whether the `/admin/users` route exists at all, and if it does, whether its handler enforces a role check before returning data.
- **What "vulnerable" looks like:** HTTP 200 with a JSON array of user objects, returned to a token that has no admin claim/role.
- **Why the check fails:** the route was registered on the same router as public routes, and the middleware chain for that specific route either has no `requireRole('admin')` guard attached, or the guard checks a claim that doesn't exist in this token type (e.g., checks `req.user.isAdmin` but the JWT only carries `role: "user"`, so the check silently evaluates falsy/undefined and the framework's guard logic defaults to "allow" instead of "deny" on an unhandled case — a very common misconfiguration).

---

## 2. JavaScript source mining

Modern frontends (SPA/React/Vue/Angular, or mobile app APKs) ship the **entire** set of API calls the client is capable of making — including calls behind admin-only UI panels that a regular user's account will never render, but that still exist in the bundled JS because frontend teams typically ship one bundle for all roles and use conditional rendering (`if (user.role === 'admin') return <AdminPanel/>`) rather than separate builds per role.

### Method

1. Pull every JS bundle the app loads (not just the main one — look at lazily-loaded chunks too):
   ```
   view-source / DevTools > Sources
   or: wget/curl every .js referenced in Network tab, including chunk-*.js, vendor-*.js
   ```
2. Search bundles for API call patterns:
   ```bash
   grep -oE '"(/api/[a-zA-Z0-9/_\-{}]+)"' bundle.js | sort -u
   grep -oE "fetch\(['\"][^'\"]+['\"]" bundle.js
   grep -oE "axios\.(get|post|put|patch|delete)\(['\"][^'\"]+['\"]" bundle.js
   ```
3. Search specifically for role-gating strings that hint at hidden functionality:
   ```bash
   grep -iE "admin|role|permission|isAdmin|superuser|internal" bundle.js
   ```
4. Beautify minified bundles first for readability:
   ```bash
   npx js-beautify bundle.js > bundle.readable.js
   ```
5. For mobile apps: decompile the APK (`apktool` / `jadx`) and grep the decompiled Java/Kotlin/Smali or any embedded config/Retrofit interface files for endpoint path constants — mobile clients are often even less careful than web SPAs about stripping admin routes from the shipped binary.

### Piece-by-piece: why this matters for BFLA specifically

- **What's being tested:** whether the *client* has knowledge of a function the *server* was supposed to gate by role.
- **Why it's a discovery goldmine, not yet a vulnerability:** finding `/api/admin/reports/export` in the JS bundle only proves the endpoint exists and that the frontend knows about it. It does **not** prove BFLA — you still need to call it with a non-admin token and confirm the server itself, not just the UI, enforces the restriction. This step is discovery; the actual bug confirmation happens in `03-bfla-patterns-and-bypass-techniques.md`.
- **Real-world framing:** this exact technique — reading React/Vue bundle source for hidden API routes — is one of the single most common ways bug bounty hunters find their first BFLA report, because bundling tools don't know or care about authorization boundaries; they just bundle everything reachable from any route in the app.

---

## 3. API documentation gaps

Where the target exposes Swagger/OpenAPI, GraphQL introspection, Postman collections, or even just partial public docs, the **gap** between documented and actual endpoints is a discovery signal in both directions.

### Method

- **Full spec exposed (`/swagger.json`, `/openapi.yaml`, `/api-docs`):** diff the documented endpoint list against what you've actually observed the app call in traffic. Undocumented-but-observed endpoints are worth extra attention — they're often internal/admin routes that got wired up but never publicly documented, sometimes deliberately kept out of docs because "this isn't meant to be called by normal users" (security-by-obscurity, not actual enforcement).
- **Partial/redacted docs:** some organizations publish a "public" OpenAPI spec with admin paths manually stripped out, but the running server still serves the full spec at a slightly different path (`/v1/openapi.json` vs `/v1/internal/openapi.json`, or an old `/v0/` spec left live).
- **GraphQL introspection** (if enabled): query `__schema` for all mutation names — mutations are function calls by nature, so `__schema { mutationType { fields { name } } }` returns every privileged action the schema defines, including ones with no corresponding frontend UI:
  ```graphql
  query {
    __schema {
      mutationType {
        fields {
          name
          args { name type { name } }
        }
      }
    }
  }
  ```
  **Why this works:** GraphQL has one endpoint (`/graphql`) for everything, so there's no path-guessing needed — the schema itself lists every function (mutation) the server implements, admin or not, if introspection hasn't been disabled in production.
- **Postman collections leaked/shared publicly** (GitHub, Postman public workspace search) frequently contain a full internal collection including admin-tagged folders that were never meant to be shared outside the dev team.

### Piece-by-piece: why documentation gaps expose BFLA

- **What's being tested:** whether "not documented for external users" was ever backed by an actual server-side role check, or whether it was purely a documentation/communication decision.
- **Why the check fails when it fails:** teams frequently treat "we didn't tell anyone about this endpoint" as equivalent to "this endpoint is protected." It isn't. Obscurity is not authorization. An endpoint absent from public docs but present in the live OpenAPI spec, GraphQL schema, or Postman collection has had zero actual access control applied — it's just been asked nicely not to be used.

---

## 4. Response field inference

Sometimes the privileged function isn't found by guessing a *path* — it's inferred from *data the API already handed you*, revealing capability names, permission flags, or ID structures that point at an action endpoint.

### Method

Inspect every response body from normal, authenticated, low-privilege usage for:

- **Role/permission fields echoed back**, even if the UI doesn't use them:
  ```json
  {
    "id": 41,
    "username": "wiener",
    "roleId": 1,
    "permissions": ["read:own_profile"],
    "availableActions": ["view", "edit_own"]
  }
  ```
  A field like `roleId` or `availableActions` being present in a *response* — even read-only — is a strong hint that the same field is **also accepted on write requests** (profile update, registration) and might be settable client-side. This connects directly to the parameter-based role manipulation pattern in file 03.

- **Internal object properties not rendered in the UI** — open DevTools Network tab, inspect the raw JSON of a "normal" API call, and look for extra fields the frontend silently ignores:
  ```json
  {
    "video_id": "8f2e...",
    "title": "dashcam_clip.mp4",
    "converted": true,
    "internal_conversion_url": "/api/video/convert_internal/8f2e..."
  }
  ```
  This is a documented crAPI discovery pattern: an internal property (`internal_conversion_url` or similarly-named field) exposed in an ordinary API response reveals the existence and exact path of an admin-only endpoint that isn't linked anywhere in the UI.

- **HTTP `OPTIONS` requests** against any confirmed endpoint — many frameworks respond to `OPTIONS` with an `Allow:` header listing every HTTP method the route supports, even ones the current role can't successfully call:
  ```
  OPTIONS /api/v1/users/41 HTTP/1.1
  Host: target-api.com
  Authorization: Bearer <regular-user-JWT>

  Response:
  HTTP/1.1 204 No Content
  Allow: GET, POST, PUT, DELETE, PATCH
  ```
  **Piece-by-piece:** what's being tested is simply "what methods does this route's handler register," independent of authorization. Why it matters: if `DELETE` and `PATCH` are listed as `Allow`ed on a route you've only ever seen the UI call with `GET`, that's a direct signal to test method-switching (covered fully in file 03) — the server is telling you the handler exists before you've even tried it.

- **Error message differences** — a `403 Forbidden` (route exists, role check explicitly failed) vs a `404 Not Found` (route doesn't exist, or is deliberately masked) is itself information. Some APIs return `404` for both "doesn't exist" and "exists but you can't see it" specifically to prevent this kind of enumeration — noting which behavior the target uses tells you how reliable your path-guessing feedback loop will be.

---

## 5. Consolidating discovery into a test list

By the end of this phase you should have a running list, e.g.:

| Candidate endpoint | Source | HTTP methods to test | Confirmed to exist? |
|---|---|---|---|
| `/api/v1/admin/users` | Path guessing | GET, POST | Yes (200 empty guard) |
| `/api/v1/admin/users/{id}/promote` | JS bundle mining | POST | Yes |
| `/api/video/convert_internal/{id}` | Response field inference | GET, POST | Yes |
| `mutation deleteUser(id)` | GraphQL introspection | POST (GraphQL) | Yes |
| `/api/v1/orders/{id}` method=DELETE | OPTIONS probing | DELETE | Allow header confirms |

Every row on this list becomes a candidate for the pattern-testing methodology in the next file — this is the handoff point between "finding the door" and "testing whether it's locked."

---
*Discovery techniques apply equally to REST and GraphQL APIs; only the enumeration mechanics differ (path guessing vs schema introspection). Both funnel into the same testing methodology once a candidate function is identified.*
