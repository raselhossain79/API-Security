# BOPLA — Overview and Core Concepts

## 1. What BOPLA is

**Broken Object Property Level Authorization (BOPLA)** is ranked **API3** in the OWASP API
Security Top 10 2023. It is not a new vulnerability class — it is a **merger** of two categories
from the 2019 list:

| 2019 category | 2023 status |
|---|---|
| API3:2019 — Excessive Data Exposure | Merged into API3:2023 BOPLA |
| API6:2019 — Mass Assignment | Merged into API3:2023 BOPLA |

OWASP merged them because they share one root cause: **the API controls access at the object
level, but not at the property (field) level.** The server correctly checks "does this user own
this object?" but never checks "which specific fields of that object is this user allowed to
read, and which fields is this user allowed to write?"

That single sentence is the entire concept. Every technique in this series is one of two
directions applied to that same missing check:

- **Read direction → Excessive Data Exposure**: the API returns fields the requester should
  never see.
- **Write direction → Mass Assignment**: the API accepts fields the requester should never be
  able to set.

---

## 2. Why property-level authorization gets missed

Object-level checks are easy to reason about: "is this `order_id` mine?" is a single comparison.
Property-level checks require the developer to enumerate, for every single field on every
object, who is allowed to read it and who is allowed to write it — for every role, every
endpoint, every response shape. Most frameworks do not force this enumeration by default; they
default to "serialize the whole object" and "bind the whole request body." Property-level
authorization has to be added deliberately, and it is the step teams skip under deadline
pressure. This is why BOPLA shows up constantly in real assessments even in codebases that pass
BOLA and BFLA checks cleanly.

---

## 3. Excessive Data Exposure — mechanism

**Definition:** the API returns a full internal object (or a larger slice of it than necessary)
in the response, and relies on the *client* (the UI, the mobile app) to decide which fields to
display. The vulnerability exists the moment the sensitive field leaves the server, regardless
of whether the UI ever renders it.

**Why this happens architecturally:**

- **ORM-to-JSON shortcuts.** Frameworks like Django REST Framework (`ModelSerializer` with
  `fields = '__all__'`), Spring Boot (`@RestController` returning a JPA entity directly), and
  Node.js ORMs (`res.json(user)` on a raw Mongoose/Sequelize document) serialize the entire
  database row by default. Excluding a field is a manual, easy-to-forget step; including
  everything is the path of least resistance.
- **"The frontend doesn't show it, so it's fine" reasoning.** Developers treat the UI as the
  security boundary. It isn't — anyone with Burp Suite, `curl`, or the browser's network tab sees
  the raw response, not the rendered page.
- **Shared serializers across roles.** The same `UserSerializer` is reused for the admin panel
  and the public profile endpoint, so the admin's extra visibility (email, internal flags, risk
  score) leaks into the public response because nobody built a role-aware second serializer.
- **List/collection endpoints leaking single-object detail.** A `GET /api/users` list endpoint
  built by copy-pasting the single-user serializer returns full detail (password hash, tokens,
  PII) for *every user in the list*, multiplying the exposure by the number of records.

**Concrete example — field by field:**

```
GET /api/users/123
Authorization: Bearer <normal_user_token>
```

Response:

```json
{
  "id": 123,
  "username": "wiener",
  "email": "wiener@example.com",
  "password_hash": "$2b$12$K3n9f...",
  "internal_risk_score": 82,
  "is_flagged_for_review": true,
  "stripe_customer_id": "cus_Qk29fAlpha",
  "role": "user",
  "created_at": "2024-01-04T10:22:00Z"
}
```

The requesting user is authorized to view **this object** (it is their own profile — object-level
authorization passes). But field by field:

- `id` — internal database primary key. Low sensitivity alone, but valuable as a pivot for BOLA
  testing on other endpoints once you know real, sequential IDs exist.
- `password_hash` — should never leave the server under any circumstance, regardless of hashing
  algorithm. Its presence in the response means an attacker with any read access to this endpoint
  can take the hash offline and crack it.
- `internal_risk_score` and `is_flagged_for_review` — internal fraud/trust-and-safety fields.
  A user who can read these can time their behavior around detection thresholds.
- `stripe_customer_id` — a third-party billing identifier. If the payment provider's API trusts
  this ID as a capability token (some do, if misconfigured), it can be replayed elsewhere.
- `role` — reveals the exact string the backend uses for privilege comparisons. This is
  reconnaissance for a Mass Assignment attempt (see file 3): now the attacker knows to try
  `"role": "admin"` instead of guessing.

None of these fields were displayed anywhere in the application's UI. That is irrelevant to the
severity — the vulnerability is in what the server sent, not what the browser rendered.

---

## 4. Mass Assignment — mechanism

**Definition:** the API accepts a request body and automatically binds every key in it to a
matching property on an internal object/model, without an explicit allowlist of which properties
a client is permitted to set. The client controls the *keys* it sends; the server, without
realizing it, lets those keys reach fields never meant to be client-writable.

**Why this happens architecturally:**

- **Auto-binding frameworks by default.** Spring's `@ModelAttribute` and Jackson deserialization
  onto a JPA entity, Django REST Framework's `ModelSerializer.save()`, Ruby on Rails' historic
  `Model.new(params)` before Strong Parameters became mandatory, and Mongoose's
  `Model.create(req.body)` in Node.js all take a JSON object and write every matching key onto
  the internal model in one call. The convenience that makes these frameworks fast to develop in
  is the exact mechanism that creates the vulnerability.
- **No allowlist, only a UI-driven blocklist mentality.** Developers build the request DTO to
  match what the *frontend form* sends, then bind that whole DTO straight onto the database
  model. Any field that exists on the model but wasn't anticipated in the form is still bindable
  if a client sends it directly to the API, bypassing the form entirely.
- **Internal/system fields living on the same model as user-editable fields.** `is_admin`,
  `account_balance`, `subscription_tier`, and `email_verified` are frequently columns on the
  exact same `users` table as `display_name` and `bio`. If the update endpoint binds the whole
  table row, all of them are reachable from the same request.

**Concrete example — field by field (registration endpoint):**

Legitimate request the UI actually sends:

```
POST /api/users/register
Content-Type: application/json

{
  "username": "attacker01",
  "email": "attacker01@example.com",
  "password": "Str0ngP@ss!"
}
```

Attacker-modified request:

```
POST /api/users/register
Content-Type: application/json

{
  "username": "attacker01",
  "email": "attacker01@example.com",
  "password": "Str0ngP@ss!",
  "isAdmin": true,
  "role": "admin",
  "account_balance": 999999,
  "email_verified": true
}
```

Breaking down exactly why the server might process each injected field:

- `"isAdmin": true` — if the `User` model has a boolean `isAdmin` column and the registration
  handler does `User.create(requestBody)` (or the Java/C# equivalent binds the request DTO
  directly onto the entity), this key matches the column name and is written on creation. The
  UI never sends this field because the registration form has no admin checkbox — but the server
  never checks whether the field is *allowed* to be sent, only whether it *matches* a model
  property.
- `"role": "admin"` — the attacker learned this exact field name and value from an Excessive Data
  Exposure finding on a different endpoint (see Section 3's `"role": "user"` example). This is
  why the two sub-vulnerabilities compound each other: EDE tells you the field names and valid
  values to try; Mass Assignment lets you set them.
- `"account_balance": 999999` — a financial field that should only ever be set by a
  payment-processing internal service, never by the client that creates the account. If it binds,
  the attacker has created an account with a fraudulent balance before any payment occurred.
- `"email_verified": true` — bypasses the email confirmation flow entirely. Any downstream logic
  that gates sensitive actions behind "is this email verified" is defeated at account creation
  time, before the attacker ever needs to intercept a verification link.

If **any one** of these keys is reflected back as `true`/`admin`/`999999` in the registration
response, or has an observable effect (the new account can access admin-only functionality,
or shows an inflated balance), the endpoint has a Mass Assignment vulnerability. Full testing
methodology, including how to detect binding even when the response doesn't echo the field
back, is in file 3.

---

## 5. BOLA vs BFLA vs BOPLA — telling them apart

These three categories are commonly confused because they all involve "authorization gone
wrong" on an API. The distinguishing question is **what is being checked, and at what
granularity**:

| Category | The question that fails | Typical test |
|---|---|---|
| **BOLA (API1)** | "Does this user own *this specific object instance*?" | Change `user_id=123` to `user_id=124` in the URL/body and see if you get someone else's *entire* object |
| **BFLA (API5)** | "Is this user allowed to call *this endpoint/function* at all?" | Call an admin-only endpoint (`DELETE /api/admin/users/5`) with a normal user's token |
| **BOPLA (API3)** | "Is this user allowed to read/write *this specific field* on an object they otherwise legitimately have access to?" | Read or write `isAdmin`/`internal_risk_score` on an object you are already authorized to access (often your own account) |

A practical way to keep them separate while testing: BOLA and BFLA are about **which object or
endpoint** you can reach. BOPLA is about **which fields** on an object you're already
legitimately allowed to touch. You can pass every BOLA and BFLA check on an endpoint and still
have a critical BOPLA vulnerability sitting inside it, because BOPLA lives one level deeper than
either of those checks — inside the object you were always meant to have.

---

## 6. Real-world impact framing

BOPLA-class findings are consistently among the highest-paying and most frequently reported
findings in API-focused bug bounty programs, for a structural reason: registration, profile
update, and "create resource" endpoints exist on almost every API, are usually reachable by
unauthenticated or low-privilege accounts, and are exactly the endpoints most likely to be built
with auto-binding for developer convenience. A single missed field on a single `PATCH` endpoint
can be the difference between a low-severity information disclosure report and a full account
takeover / privilege escalation chain (see the OAuth account takeover series in this repository
for how BOPLA findings frequently become one link in a longer chain).

Industry-standard references worth knowing by name when writing reports or discussing findings
with a client:

- OWASP API Security Top 10 2023 — API3: Broken Object Property Level Authorization
- OWASP API Security Top 10 2019 — API3: Excessive Data Exposure (superseded, still useful for
  historical CVE/report context)
- OWASP API Security Top 10 2019 — API6: Mass Assignment (superseded, same note)
- OWASP Mass Assignment Cheat Sheet (`cheatsheetseries.owasp.org`)

---

## 7. What's next

- **File 2** covers the full Excessive Data Exposure testing methodology: response-vs-UI diffing
  at scale, cross-role response comparison, and how to systematically catch over-exposure across
  every endpoint instead of stumbling into it by accident.
- **File 3** covers the full Mass Assignment testing methodology: hidden-parameter discovery,
  differential valid/invalid value testing, and every known filter bypass technique.
- **File 4** is the condensed cheatsheet for both, built for use during live engagements.
