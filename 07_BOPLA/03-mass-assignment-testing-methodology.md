# BOPLA — Broken Object Property Level Authorization
### File 3 of 6: Mass Assignment — Testing Methodology

---

## 1. The Core Testing Principle

Mass assignment testing is **systematic field injection**: for every endpoint that
creates or updates an object (`POST`, `PUT`, `PATCH`), you add fields the documented
request schema does not include, and observe whether the server's behavior — not just its
HTTP status code — changes as a result.

The critical discipline here: **a `200 OK` with the extra field silently ignored is not
a finding. A change in server-side state that reflects the injected field is.** Always
verify impact by reading the object back afterward (`GET`), not just by looking at the
response to the `POST`/`PUT`/`PATCH` itself.

---

## 2. Step 1: Establish the Baseline

Before injecting anything, capture the **normal, documented** request for the
create/update flow you're targeting.

Example — a user profile update:
```
PATCH /api/users/me HTTP/2
Host: target.example.com
Authorization: Bearer <user-token>
Content-Type: application/json
Content-Length: 42

{"full_name":"Rasel Hossain","bio":"Pentester"}
```

Baseline response:
```json
{"full_name":"Rasel Hossain","bio":"Pentester","updated":true}
```

This tells you the two fields the frontend *intends* to send. Anything beyond
`full_name` and `bio` is untested territory as far as the client is concerned — but the
server-side handler behind this endpoint may accept far more.

---

## 3. Step 2: Build a Candidate Field List

Before blindly guessing, gather candidate internal field names from every source
available to you:

1. **Excessive Data Exposure findings (file 2).** Any field you already saw in a raw
   response — `is_admin`, `internal_risk_score`, `account_type`, `balance` — is now a
   high-value candidate to try *writing*, not just reading. This is why the two
   sub-types are tested together in practice: exposure tells you what to inject.
2. **JavaScript source / API client SDKs.** Frontend JS bundles, mobile app
   decompilation, or a published OpenAPI/Swagger spec often reference internal field
   names even if the current UI doesn't expose a form control for them.
3. **Common industry-standard guesses**, when nothing else is available:
   `isAdmin`, `is_admin`, `admin`, `role`, `roles`, `user_type`, `account_type`,
   `permissions`, `is_verified`, `verified`, `email_verified`, `is_active`, `enabled`,
   `balance`, `credit`, `wallet_balance`, `price`, `discount`, `status`, `approved`,
   `id` (attempting to overwrite the object's own primary key or reassign ownership via
   a foreign key like `user_id`/`owner_id`).

---

## 4. Step 3: Inject One Field at a Time and Verify Server-Side Effect

### 4.1 The request

```
PATCH /api/users/me HTTP/2
Host: target.example.com
Authorization: Bearer <user-token>
Content-Type: application/json
Content-Length: 66

{"full_name":"Rasel Hossain","bio":"Pentester","is_admin":true}
```

**Field-by-field breakdown:**
- `full_name` and `bio` — the two legitimate, documented fields, kept unchanged so the
  request still looks like a normal profile edit and doesn't trip obvious anomaly
  detection.
- `is_admin: true` — the injected field. This name was not present in the documented
  request schema and has no corresponding form field in the UI. It is being sent because
  the *response* from a `GET /api/users/me` call (Excessive Data Exposure testing, file 2)
  revealed the backend's internal object has a property with this exact name. The
  hypothesis being tested: does the `PATCH` handler bind **every** key in the JSON body
  onto the user model (mass assignment), or does it only apply the two fields it's
  designed to accept (a proper whitelist)?

### 4.2 Why the API might process this field unexpectedly

If the backend handler looks like (illustrative, framework-agnostic pseudocode):
```
user = get_current_user()
data = request.json
for key, value in data.items():
    setattr(user, key, value)
user.save()
```

...then `is_admin` gets set via `setattr` exactly like `full_name` does — the code has
**no concept** of "which fields am I actually supposed to let this endpoint change."
Every key in the JSON body is trusted equally.

The **correct** implementation would instead read:
```
user = get_current_user()
data = request.json
user.full_name = data.get("full_name", user.full_name)
user.bio = data.get("bio", user.bio)
user.save()
```

...where only two attributes are ever touched, regardless of what else the JSON body
contains. The vulnerability is the *absence* of this explicit mapping, not a bug in any
single line — which is why mass assignment survives in codebases that look otherwise
well-written: the missing whitelist is invisible unless you specifically go looking for it.

### 4.3 Verifying impact

Never trust the `PATCH` response alone. Confirm with a follow-up read:
```
GET /api/users/me HTTP/2
Authorization: Bearer <user-token>
```
```json
{"full_name":"Rasel Hossain","bio":"Pentester","is_admin":true, ...}
```
If `is_admin` now reads `true`, the write succeeded server-side — this is a confirmed
finding, and (scope permitting) you should verify actual privilege escalation by
attempting an admin-only action (see file BFLA-API5 series for that follow-on testing —
BOPLA gets you the flag, BFLA-style testing confirms what it unlocks).

---

## 5. Step 4: Repeat Across Every POST/PUT/PATCH Endpoint

Mass assignment must be tested **per-endpoint**, not per-object-type, because different
handlers touching the same underlying model frequently have inconsistent whitelisting.
Build a checklist from your API recon and work through it systematically:

| Endpoint pattern | Object type | Try injecting |
|---|---|---|
| `POST /api/users/register` | New user | `is_admin`, `role`, `email_verified`, `account_id` |
| `PATCH /api/users/{id}` | Existing user | `is_admin`, `role`, `balance`, `id` (reassign own ID) |
| `POST /api/orders` | New order | `price`, `discount`, `status`, `user_id` (assign to someone else) |
| `PATCH /api/orders/{id}` | Existing order | `status` (`approved`), `total`, `shipping_cost` |
| `POST /api/tickets` (support/helpdesk) | New ticket | `priority`, `assigned_to`, `internal_notes` |
| `PATCH /api/organizations/{id}/members/{id}` | Membership object | `role` (`owner`/`admin`), `permissions` |
| `POST /api/comments` | New comment | `is_pinned`, `author_id` (impersonate another user), `verified_badge` |

A single confirmed mass-assignment endpoint does not mean the whole API is safe or the
whole API is vulnerable elsewhere — each row above is an independent test.

---

## 6. Testing Comparison Across Roles (Write Direction)

Just as file 2 compares **read** access across roles, mass assignment testing should
compare **write** access across roles for the same field:

1. As a low-privilege user, attempt `PATCH .../members/{id}` with `{"role":"admin"}`.
2. As an actual admin (legitimate second test account), perform the same legitimate role
   change and observe what a **correct** request/response pair looks like.
3. If a low-privilege user's identical payload produces the identical state change that
   only an admin should be able to trigger, the endpoint has no property-level
   authorization check gating who is allowed to set that field — only an (missing)
   object/function-level check would have stopped this, and it wasn't there either.

---

## 7. Real-World Note

Mass assignment vulnerabilities were the mechanism behind a widely-cited 2012 GitHub
incident where a researcher demonstrated adding an SSH public key to another user's
account by including an unexpected `public_key` parameter in a form submission that Rails'
then-default mass-assignment behavior bound directly onto the user model — this incident
is largely credited with pushing Rails to make **strong parameters** (explicit whitelisting)
the framework default starting in Rails 4. The underlying pattern is unchanged in modern
JSON APIs: any framework that auto-binds a request body onto a model without an explicit
allowed-fields list reproduces the exact same class of bug, regardless of language.

---

## 8. PortSwigger Lab Mapping (Apprentice → Practitioner → Expert)

| Order | Difficulty | Lab | What it covers |
|---|---|---|---|
| 1 | Apprentice | *Exploiting an API endpoint using documentation* (API Testing topic) | Discovering documented/hidden endpoints and their expected schema — the baseline step (Step 1) of this file's methodology |
| 2 | Practitioner | **Exploiting a mass assignment vulnerability** (API Testing topic) | The direct, dedicated lab for this vulnerability. Exploits a hidden `chosen_discount` parameter accepted by a checkout endpoint that the UI never exposes, to buy an item at a manipulated price — a textbook Step 3 injection-and-verify exercise |
| 3 | Practitioner | *Finding and exploiting an unused API endpoint* (API Testing topic) | Reinforces that undocumented endpoints (candidates for mass assignment) are found through recon, not guesswork alone |

There is no Expert-level PortSwigger lab specifically for mass assignment as of this
writing — the Expert-level API Testing labs at time of writing focus on server-side
parameter pollution (covered as its own topic in this note series, not duplicated here).
Use **crAPI's** profile-update and coupon/discount endpoints (see file 1, section 6) to
practice beyond PortSwigger's single dedicated lab.

---

Continue to **File 4 — Mass Assignment Filter Bypass Techniques**.
