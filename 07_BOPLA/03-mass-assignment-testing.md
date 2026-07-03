# Mass Assignment — Testing Methodology and Filter Bypass

This file assumes you've read `01-bopla-overview-and-concepts.md`. It focuses entirely on the
**write direction** of BOPLA: systematically finding fields the API accepts that it shouldn't,
including techniques for when an obvious blocklist is already in place.

---

## 1. Auto-binding mechanics per framework — know what you're attacking

Understanding *why* a framework binds an unexpected field tells you exactly which field name
variations are worth trying and where a fix is likely to be incomplete. This is not background
trivia — it directly shapes the filter bypass techniques in Section 4.

- **Spring Boot (Java)** — `@ModelAttribute` and Jackson's default deserialization onto a JPA
  `@Entity` bind every JSON key that matches a setter/field name, including inherited fields from
  parent classes. A common incomplete fix is `@JsonIgnore` on the getter only, which still allows
  the field to be *written* during deserialization even though it's hidden from output — meaning
  the endpoint stops leaking the field (fixes EDE) while remaining fully vulnerable to Mass
  Assignment on the same field.
- **Django REST Framework (Python)** — `ModelSerializer` with `fields = '__all__'` or a
  `read_only_fields` list that's incomplete binds every model column not explicitly excluded.
  A field removed from the serializer's `fields` list is unreachable; a field left in but only
  marked with client-side form validation is not protected server-side at all.
- **Ruby on Rails** — pre-Rails 4, `Model.new(params[:user])` bound everything with no
  protection by default (the historic GitHub 2012 mass assignment incident is the canonical
  reference case for this vulnerability class). Modern Rails requires Strong Parameters
  (`params.require(:user).permit(:name, :email)`), but a `permit!` call (no arguments) or a
  dynamically built permit list re-introduces the same unrestricted binding.
- **Node.js with Mongoose** — `Model.create(req.body)` or `Model.findByIdAndUpdate(id, req.body)`
  passes the entire request body straight into the document write with no allowlist unless the
  schema explicitly uses `select: false` on sensitive fields (which only affects reads, not
  writes) or the handler manually destructures only permitted keys.
- **.NET model binding** — binding a request body directly onto an EF Core entity via
  `[FromBody] User user` exposes every public property on that entity to client control unless a
  separate DTO/ViewModel is used for the input and explicitly mapped field-by-field onto the
  entity.

The pattern across every framework: **the vulnerability exists whenever the same class/model used
for database storage is also used directly as the request deserialization target.** Any framework
fix that keeps that same class as the binding target — but adds annotations, exclusions, or a
blocklist — is fixing symptoms rather than the root cause, and is the most common source of
bypassable filters (Section 4).

---

## 2. Discovering hidden parameters

Before you can test whether a field is mass-assignable, you need to know it exists. Three
sources, in order of reliability:

**Source 1 — GET responses on the same object (highest value).**
If `GET /api/users/123` returns `isAdmin`, `internal_id`, or `subscription_tier`, those are
confirmed real field names on the internal model — not guesses. This is the direct link back to
file 2: every Excessive Data Exposure finding is a Mass Assignment wordlist entry.

**Source 2 — Client-side code and API documentation.**
JavaScript bundles, mobile app decompilation, OpenAPI/Swagger specs, and GraphQL introspection
(if present) frequently reference internal field names even for functionality not exposed in the
current UI — an admin panel field name left in a shared frontend codebase, for example.

**Source 3 — Automated parameter discovery.**
Burp Intruder with a curated wordlist, or the **Param Miner** extension, systematically add
candidate field names to a baseline request and flag any that change response length, status
code, or timing. Use a wordlist built from common patterns (see file 4's cheatsheet) combined
with application-specific terms gathered during recon.

---

## 3. Core testing methodology — differential valid/invalid value testing

This is the single most reliable technique for confirming mass assignment even when the response
doesn't echo the injected field back to you.

**Step 1 — Establish a clean baseline.**
Send the legitimate request exactly as the UI sends it. Record the exact response: status code,
body, response time.

**Step 2 — Add the candidate field with a plausible value.**
```json
{
  "username": "wiener",
  "email": "wiener@example.com",
  "isAdmin": false
}
```
Compare against baseline. If the response is identical, this alone is inconclusive — the field
could be silently ignored, or it could be accepted with no observable side effect at this step.

**Step 3 — Add the candidate field with an intentionally invalid value.**
```json
{
  "username": "wiener",
  "email": "wiener@example.com",
  "isAdmin": "not_a_boolean"
}
```
This is the critical differential step. If the server:
- **Returns a validation error or 500** referencing the field (`isAdmin must be a boolean`) →
  the field is being processed and type-checked server-side, confirming it reaches the binding
  layer. This is strong evidence of mass assignment even before you've proven privilege escalation.
- **Returns the exact same success response as the valid-value case** → either the field is
  silently dropped before binding (not vulnerable), or it's bound without any type validation at
  all (still vulnerable, just with a weaker signal — proceed to Step 4 to confirm directly).

**Step 4 — Set the field to the exploitable value and verify real impact out-of-band.**
```json
{
  "username": "wiener",
  "email": "wiener@example.com",
  "isAdmin": true
}
```
Then, using the *same account's* session, attempt an action that should require the elevated
privilege (access an admin-only endpoint, view another user's data, perform a restricted action).
A successful privileged action is the only conclusive proof — a 200 OK on the original request
alone is not sufficient for a report, since some APIs return 200 even when a field was silently
ignored.

---

## 4. Filter bypass techniques

When Step 3's response shows the obvious field name is blocked (validation error mentioning the
exact field, or a 400 response), do not stop — a blocklist protecting the literal string
`isAdmin` frequently does not protect every path that reaches the same underlying model property.
Work through these systematically.

### 4.1 Alternate field name casing and formatting

Try every naming convention the codebase might use elsewhere, since serialization layers and
validation layers sometimes use different naming transforms:

```
isAdmin       is_admin      IsAdmin
ADMIN         admin         Admin
adminFlag     admin_flag    is-admin
```
This works because a blocklist written for `is_admin` in a Python/Django backend may not catch
`isAdmin` if a separate camelCase-to-snake_case conversion layer runs *after* the blocklist check
but *before* the actual database write — the check and the binding are looking at the string in
two different forms.

### 4.2 Nested object wrapping

If the top-level field is blocked, try wrapping the same key inside a nested object matching the
model's actual structure, especially if the API supports partial/nested updates:

```json
{
  "username": "wiener",
  "profile": {
    "role": "admin"
  }
}
```
or, for ORMs that support nested relation writes (common in Django REST Framework nested
serializers and some GraphQL mutations):

```json
{
  "username": "wiener",
  "account": {
    "settings": {
      "role": "admin"
    }
  }
}
```
This works because a top-level blocklist check often inspects only the first level of keys in the
request body. If the deserializer recursively binds nested objects onto related models, the
nested `role` key can still reach the same database column through a relation the blocklist never
inspected.

### 4.3 Array/batch endpoint wrapping

If the application has any bulk-update or batch-create endpoint, test the same blocked field
inside array elements:

```json
{
  "users": [
    {"username": "wiener", "role": "admin"}
  ]
}
```
Batch endpoints are frequently built later than their single-object counterparts, reuse different
(often less scrutinized) binding code, and are less likely to have received the same blocklist
fix applied to the single-object endpoint.

### 4.4 Content-Type switching

If JSON is blocked, test the identical logical payload as a different content type. Different
parsers on the backend can have different binding behavior even when they ultimately populate the
same model:

**Form-urlencoded:**
```
POST /api/users/register
Content-Type: application/x-www-form-urlencoded

username=wiener&email=wiener%40example.com&password=Str0ngP%40ss%21&isAdmin=true
```

**XML** (if the API accepts it, or if content negotiation isn't strictly enforced):
```
POST /api/users/register
Content-Type: application/xml

<user>
  <username>wiener</username>
  <email>wiener@example.com</email>
  <isAdmin>true</isAdmin>
</user>
```
This works because a mass-assignment blocklist implemented as JSON-body middleware (inspecting
`req.body` after a JSON-specific parser runs) simply never executes if the request arrives with a
different `Content-Type` header that routes through a different parser — the blocklist code path
is bypassed entirely, not defeated.

### 4.5 HTTP parameter pollution

Send the same key twice with different values, once in the query string and once in the body, or
duplicated within the body if the parser allows it:

```
POST /api/users/123?role=user
Content-Type: application/json

{"role": "admin"}
```
Different frameworks resolve duplicate parameters inconsistently (first occurrence wins, last
occurrence wins, or values are merged into an array). If validation logic reads the query-string
value while the binding logic reads the body value (or vice versa), the check and the actual
write can be looking at two different values.

### 4.6 Unicode and case-normalization tricks

Some blocklists perform a case-sensitive string match. Test full-width Unicode variants or mixed
case that a downstream normalization step might fold back to the blocked key before binding but
after the filter check:

```json
{"ｉｓＡｄｍｉｎ": true}
```
Lower-value technique, but worth a quick try when every other bypass fails and the backend is
known to perform any kind of Unicode normalization (NFKC) during processing.

### 4.7 GraphQL mutation field addition

If the same backend also exposes a GraphQL endpoint alongside REST, check whether the equivalent
mutation accepts the blocked field even though the REST endpoint doesn't — GraphQL schemas and
REST validation layers are frequently maintained separately and drift out of sync with each
other:

```graphql
mutation {
  updateUser(id: 123, input: { username: "wiener", role: "admin" }) {
    id
    role
  }
}
```

### 4.8 When every bypass fails

Confirm the field is genuinely protected by checking whether the endpoint returns a *specific*
error referencing the exact field name and rejecting the request outright (not silently dropping
it) — that's the sign of an actual allowlist implementation (binding onto a dedicated DTO/input
class with only permitted fields, as described in Section 1), which is the correct fix and not
further bypassable through request manipulation alone.

---

## 5. PortSwigger Web Security Academy lab mapping

PortSwigger's API testing topic has one lab built specifically for this vulnerability:

**Lab: "Exploiting a mass assignment vulnerability"** (API testing topic)

Breakdown of the lab's mechanism, mapped to this file's methodology:

1. The lab's checkout flow returns a `GET`/`POST` pair for `/api/checkout`. The `GET` response
   contains a `chosen_discount` object with a `percentage` field set to `0` — this is Source 1
   from Section 2 above: a hidden parameter discovered directly from a GET response on the same
   object.
2. Adding `"percentage": 100` to the `POST /api/checkout` request body is Step 2/4 from Section 3
   — setting the candidate field to an exploitable value and checking for real impact (the order
   total actually drops to reflect a 100% discount).
3. This lab has no filter in place, so Section 4's bypass techniques aren't required to solve it
   — it's the baseline case. Treat it as the confirmation exercise for Sections 1–3 before
   practicing bypasses against a target (or crAPI) that actually has a blocklist to get around.

This is the only lab **in correct progression order** for this specific vulnerability — there is
no dedicated "easy/medium/hard" ladder of mass assignment labs on PortSwigger the way there is
for, say, SQL injection. Honest gap disclosure: build the bypass skills from Section 4 against
crAPI or a intentionally-vulnerable local target (OWASP crAPI, or a deliberately unpatched
Express/Mongoose demo app), since PortSwigger doesn't provide graduated difficulty for this
category yet.

## 6. crAPI reference

crAPI's mechanic report assignment workflow is the standout Mass Assignment scenario: a community
user can submit a mechanic report request, and the endpoint accepting that submission has been
documented in multiple public crAPI walkthroughs as accepting additional fields beyond what the
form sends, including fields that affect report status or assignment. Also check the coupon/
credit-related endpoints in the shop component — mass assignment on numeric fields (discount
percentage, credit balance) is a recurring crAPI pattern that mirrors the PortSwigger lab almost
exactly, making it good practice for Section 3's methodology before Section 4's bypass techniques
against endpoints that do have filtering in place.

---

## 7. Real-world notes

- Registration and account-creation endpoints are the highest-value Mass Assignment targets in
  almost every assessment: they are reachable pre-authentication, and developers are least likely
  to have hardened them since "why would anyone send extra fields when creating a brand-new
  account" is an easy assumption to make and a wrong one.
- Always test every `POST`, `PUT`, and `PATCH` endpoint, not just the ones that "look like" they
  update sensitive data. Comment endpoints, file upload metadata endpoints, and "update
  preferences" endpoints have all been documented as unexpectedly bindable onto sensitive
  columns because they share a model with more sensitive functionality.
- When you find a working mass assignment bug, always check whether the same field can be
  exploited through **every** write endpoint that touches the same model (create, update, bulk
  update, PATCH vs PUT) — a fix applied to one endpoint frequently isn't applied to its siblings.
- Document the exact Content-Type and body used in your report reproduction steps precisely —
  filter bypass findings are the ones most often disputed by development teams ("we already
  blocked that field") because they didn't realize the block only covered the JSON code path.
