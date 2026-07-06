# BOPLA — Broken Object Property Level Authorization
### File 4 of 6: Mass Assignment — Filter Bypass Techniques

---

## 1. When You Need This File

File 3's straightforward field injection (`{"is_admin": true}`) sometimes fails not
because the backend properly whitelists fields, but because a **partial filter** sits in
front of it: a blocklist of known-dangerous field names, a WAF rule, or an API gateway
schema check. A partial filter is not the same as a proper whitelist — it blocks the
*obvious* field name while leaving the underlying mass-assignment logic (`setattr` on
every key, `Model.create(**data)`, etc.) completely intact. The techniques below exploit
that gap.

---

## 2. Technique 1: Alternate Field Names / Casing / Aliases

Blocklists are typically written against **one exact string** (`is_admin`). They rarely
account for every naming convention the backend's deserializer will still accept.

Try systematically:
- Case variants: `IsAdmin`, `ISADMIN`, `isAdmin`, `Is_Admin`
- Naming convention variants: `is_admin` vs `isAdmin` vs `IsAdmin` vs `admin_flag` vs
  `adminFlag`
- Common synonyms: `role` vs `user_role` vs `userRole` vs `account_type` vs `accountType`
  vs `permission_level`
- Legacy/versioned aliases: some codebases keep an old field name as a backward-compatible
  alias after a rename (`admin` as well as `is_admin` both still bound by the ORM even
  though only `is_admin` is documented) — check API changelogs/deprecation notices for
  candidates.

**Why this works mechanically:** many frameworks' model/serializer deserialize based on
whatever attribute exists on the underlying class, case-sensitively matched against the
exact JSON key. A blocklist filtering the string `"is_admin"` at the WAF or middleware
layer does nothing against `"Is_Admin"` if the ORM's attribute lookup is case-insensitive
or if an alias attribute exists — the filter and the binder are not using the same
matching rules, and that mismatch is the exploitable gap.

---

## 3. Technique 2: Nested Object Injection

Instead of injecting the sensitive field at the **top level** of the JSON body (where a
filter is watching), nest it inside a sub-object that the backend still walks into during
deserialization.

### 3.1 Example

Normal, expected request:
```json
{
  "full_name": "Rasel Hossain",
  "bio": "Pentester"
}
```

Nested-injection attempt:
```json
{
  "full_name": "Rasel Hossain",
  "bio": "Pentester",
  "profile": {
    "is_admin": true
  }
}
```

or, if the backend's ORM supports nested/related-object updates (common in Django REST
Framework nested serializers, or Mongoose sub-documents):
```json
{
  "full_name": "Rasel Hossain",
  "account": {
    "settings": {
      "role": "admin"
    }
  }
}
```

**Field-by-field breakdown:** the top-level keys (`full_name`, `bio`) are exactly what a
naive top-level-only filter is scanning. The filter checks "does the request body contain
a key called `is_admin`?" at the outermost JSON level and finds nothing suspicious. But
the deserializer that eventually processes this payload may recursively walk **every**
nested object looking for matching model attributes/relations — especially in ORMs that
support nested writes for convenience (e.g., updating a related `profile` or `settings`
sub-object in the same call as the parent). If the backend's recursive binding is as
permissive as its top-level binding, the nested `is_admin` gets applied exactly the same
way, while a shallow (non-recursive) filter never even looked at that depth.

### 3.2 Array wrapping variant

Some frameworks additionally accept bulk-style payloads:
```json
{
  "users": [
    {"id": 8841, "full_name": "Rasel Hossain", "is_admin": true}
  ]
}
```
if a bulk-update endpoint exists elsewhere in the API and its handler is more permissive
than the single-object endpoint you started with.

---

## 4. Technique 3: Content-Type Switching

Filters and validation logic are frequently written for **one specific content type**
(usually `application/json`, since that's what the frontend sends). The same endpoint's
underlying framework may still accept — and independently parse — other content types
that route around the JSON-specific validation.

### 4.1 Example — switching to form-urlencoded

Original (filtered) request:
```
PATCH /api/users/me HTTP/2
Content-Type: application/json

{"full_name":"Rasel Hossain","is_admin":true}
```
→ blocked/stripped by a JSON-body inspection rule.

Bypass attempt:
```
PATCH /api/users/me HTTP/2
Content-Type: application/x-www-form-urlencoded

full_name=Rasel+Hossain&is_admin=true
```

**Why this can work:** many backend frameworks (Express with `body-parser`, Spring MVC,
Django) register **separate parsers per content type**, but funnel the result into the
**same internal object-binding code path** afterward. A WAF rule or middleware validation
function written specifically to parse and inspect JSON bodies (e.g., using a JSON schema
validator) may not apply the same inspection to a form-urlencoded or multipart body,
even though the framework happily accepts either and binds them identically once parsed
into a key-value map.

### 4.2 Example — switching to XML (where legacy support exists)

If an endpoint's framework has legacy XML deserialization enabled (common in older
Java/Spring or .NET APIs that migrated to JSON but never removed the old content
negotiation path):
```
PATCH /api/users/me HTTP/2
Content-Type: application/xml

<user><full_name>Rasel Hossain</full_name><is_admin>true</is_admin></user>
```
A validation layer built only for the JSON path is bypassed entirely, while the XML
deserializer independently binds `is_admin` onto the same model.

### 4.3 Multipart form-data

For endpoints that also accept file uploads (e.g., "update profile photo + name" combined
endpoints), try adding the extra field as an additional multipart part — some multipart
parsers bind every named part onto the model regardless of whether a corresponding form
field exists in the frontend HTML.

---

## 5. Technique 4: Parameter Pollution as a Filter-Confusion Vector

Where a WAF/gateway inspects only the **first** occurrence of a parameter but the backend
uses the **last** (or vice versa), duplicate keys can smuggle a value past a filter that
believes it already validated that field:
```json
{"role":"user","role":"admin"}
```
Most JSON parsers keep the *last* duplicate key, but a filter written to check the
*first* occurrence of `"role"` (`"user"`, which looks benign) never re-checks later
occurrences. This is the same underlying class of bug as HTTP parameter pollution,
applied to JSON keys instead of query-string parameters — see this note series' dedicated
Server-Side Parameter Pollution files for the query-string-specific version of this
technique.

---

## 6. WAF / API Gateway Detection and Bypass — Dedicated Section

Per this series' convention, this section addresses WAF/gateway relevance directly rather
than omitting it, since (unlike Excessive Data Exposure — see file 1, section 4) mass
assignment genuinely is a request-side pattern that gateways attempt to defend against.

### 6.1 How WAFs / API gateways typically detect mass assignment attempts

- **JSON schema / OpenAPI enforcement at the gateway layer.** Gateways like Kong, Apigee,
  AWS API Gateway, and Azure API Management can be configured to validate incoming request
  bodies against a defined schema and **reject any request containing fields not listed in
  the schema** (`additionalProperties: false` in JSON Schema terms). This is the single
  most effective mitigation, because it operates as a true whitelist rather than a
  blocklist.
- **Sensitive field-name blocklists.** Simpler WAF rules pattern-match known dangerous
  field names (`is_admin`, `role`, `isAdmin`, `admin`) anywhere in the JSON body and block
  or strip the request. This is a blocklist, and blocklists are inherently incomplete —
  see Technique 1.
- **Parameter-count / body-size anomaly detection.** Some WAFs flag requests whose field
  count deviates significantly from a learned baseline for that endpoint (e.g., a
  profile-update endpoint that normally receives 2 fields suddenly receiving 8). This is
  a behavioral heuristic, not a hard block, and is tunable/bypassable by adding only one
  extra field at a time (exactly as file 3's methodology already recommends, for
  detection-avoidance as well as clean testing hygiene).
- **Content-Type allow-listing.** Better-configured gateways restrict accepted
  `Content-Type` headers to only `application/json` for JSON APIs, which would close
  Technique 3 — but this is often not enforced consistently across every endpoint,
  especially older ones added before a security review.

### 6.2 Realistic bypass considerations

- Blocklist-based field-name filters are defeated by Technique 1 (casing/aliases) and
  Technique 2 (nesting) whenever the filter is not recursive and not case-normalized.
- Content-Type restrictions, where inconsistently applied across an API's full endpoint
  surface, are defeated by Technique 3 on whichever endpoints didn't get the restriction
  applied — a full-surface API recon pass (as in file 2 and file 3's methodology) is what
  reveals these inconsistencies, since they are rarely uniform across dozens or hundreds
  of endpoints in a real application.
- True schema-level whitelisting (`additionalProperties: false`) at the gateway is the one
  control in this list that is **not** meaningfully bypassable by the techniques in this
  file, because it inspects the actual parsed structure rather than pattern-matching
  strings — if you encounter this, the correct escalation path is to look for an endpoint
  where the schema definition itself is looser or missing (a documentation/config gap),
  rather than attempting to evade the check itself.
- As with all WAF/gateway testing, confirm findings are genuine backend behavior and not
  an artifact of a misconfigured test environment — always verify via the `GET`
  read-back step from file 3, section 4.3, not just the absence of a block response.

---

## 7. Real-World Note

Content-type switching to bypass JSON-specific validation has been documented in several
public API security write-ups where a validation middleware library (e.g., a JSON Schema
validator plugged into an Express or Flask app) was applied only to the JSON parsing
branch of the request pipeline, while a legacy `multipart/form-data` branch — kept for
backward compatibility with an older mobile app version — remained completely
unvalidated and fed directly into the same database update call. The lesson generalizes:
**any security control applied to only one code path through a shared data sink is not a
control on that sink, it's a control on that path.**

---

## 8. PortSwigger Lab Mapping

There is no PortSwigger Academy lab dedicated to mass-assignment *filter bypass*
specifically (as distinct from the base mass-assignment lab covered in file 3). The
closest applicable labs, useful for the underlying skills this file depends on
(parameter pollution and content-negotiation-based bypasses), in progression order:

| Order | Difficulty | Lab | Relevance |
|---|---|---|---|
| 1 | Practitioner | *Exploiting a mass assignment vulnerability* (API Testing topic) | The base case this file extends — practice this first (see file 3) |
| 2 | Practitioner | *Exploiting server-side parameter pollution in a query string* (API Testing topic) | Same underlying "duplicate key, filter checks the wrong one" logic as Technique 4, applied to query strings instead of JSON bodies |
| 3 | Expert | *Exploiting server-side parameter pollution in a REST URL* (API Testing topic) | Expert-level parameter pollution; trains the mindset of finding where front-end validation and back-end parsing disagree, directly transferable to content-type switching |

Use **crAPI** for hands-on nested-object and content-type-switching practice on live
requests, since PortSwigger's Academy does not currently offer dedicated labs for those
two specific bypass techniques.

---

Continue to **File 5 — CSV/Formula Injection via Data Export Features**.
