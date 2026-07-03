# Excessive Data Exposure — Testing Methodology

This file assumes you've read `01-bopla-overview-and-concepts.md`. It focuses entirely on the
**read direction** of BOPLA: systematically finding fields the API returns that it shouldn't.

---

## 1. The core technique: response vs. UI diffing

Excessive Data Exposure is almost never found by reading code — it's found by **comparing what
the server actually sends against what the application actually displays**, then asking "why is
this extra data here at all?" for every field that doesn't make it to the screen.

### Step-by-step process

**Step 1 — Capture the full raw response.**
With Burp Suite's proxy running and the application open in Burp's browser, perform the normal
user action (view profile, view order, view list of items) and locate the corresponding API
response in Proxy > HTTP history. Send it to Repeater so you have a clean baseline to work from.

**Step 2 — List every field in the JSON response.**
Don't skim it. Expand every nested object and array. A response that looks like a simple user
profile often has 15–30 fields once you include nested objects like `address`, `preferences`,
`metadata`, or `_links`.

**Step 3 — List every field actually rendered in the UI.**
Go back to the rendered page and note exactly what data appears on screen: username, avatar,
bio — whatever is visible or reachable through "view more" / edit forms.

**Step 4 — Diff the two lists.**
Anything present in the response but absent from the UI is a candidate. This does not
automatically mean it's a vulnerability (some fields are legitimately needed by client-side
logic that never renders them directly, like a `permissions` array used to conditionally show
buttons) — but every unrendered field needs a reason to exist in that response, and "the ORM
serialized the whole row" is not an acceptable reason.

**Step 5 — Classify each unrendered field by sensitivity.**
- **Critical**: credentials, tokens, hashes, secrets, full PII (SSN, DOB, government ID numbers)
- **High**: internal IDs used elsewhere, financial data, third-party service identifiers,
  fraud/trust flags, other users' data mixed into a list response
- **Medium**: role/permission strings, internal status flags, timestamps that reveal internal
  process state
- **Low**: internal database sequence IDs with no other exploitable use on their own

**Step 6 — Confirm real exposure, not just presence.**
Some frameworks include fields as `null` or empty placeholders even when no real data exists.
Distinguish "the field exists but is empty" from "the field is populated with real sensitive
data." Only the latter is a reportable finding, though the former is still worth flagging as a
design weakness since it shows the serializer has no allowlist at all.

---

## 2. Testing across user roles — the second half of the methodology

Diffing one response against its own UI only catches over-exposure that's visible to *every*
user. The other half of Excessive Data Exposure testing is **comparing the exact same endpoint's
response across different privilege levels**, because a field that's appropriate for an admin to
see is not appropriate to leak to a normal user hitting the same endpoint.

### Step-by-step process

**Step 1 — Obtain tokens for at least three distinct roles**, if the application has them:
unauthenticated, standard user, and admin/privileged user. If there's a "premium" or "verified"
tier, include it — tier-based exposure differences are common.

**Step 2 — Send the identical request with each token, one field at a time compared.**
Use Burp Comparer (words mode) on the two raw responses. Anything present for the low-privilege
token that shouldn't be is the finding — but also anything present for the *admin* token that
reveals internal system details is worth noting for a separate, lower-severity finding (internal
disclosure to an over-privileged but still external-facing role).

**Step 3 — Pay special attention to list/collection endpoints.**
`GET /api/orders` as a normal user should only ever contain that user's own orders — but check
whether *each order object* in that list contains the same over-exposed fields as the single-order
detail endpoint. A common real-world pattern: the single-object endpoint gets reviewed and
locked down, but the list endpoint reuses the same serializer and is missed.

**Step 4 — Test the same object through every endpoint that returns it.**
The same underlying `User` object might be returned by `/api/users/{id}`, `/api/users/me`,
`/api/orders/{id}` (nested inside a `customer` field), and `/api/reviews?author={id}`. Each of
these can have a different serializer with a different bug. Testing one does not clear the
others.

### Worked example — field by field, role comparison

`GET /api/orders/4471`

**As the order's owner (normal user token):**
```json
{
  "order_id": 4471,
  "status": "shipped",
  "items": [{"sku": "TSHIRT-BLK-M", "qty": 1, "price": 24.99}],
  "shipping_address": "12 Rosewood Ave",
  "customer": {
    "id": 88,
    "name": "wiener",
    "email": "wiener@example.com"
  }
}
```

**Same endpoint, same order, admin token:**
```json
{
  "order_id": 4471,
  "status": "shipped",
  "items": [{"sku": "TSHIRT-BLK-M", "qty": 1, "price": 24.99, "cost_price": 6.10, "supplier_id": "SUP-2291"}],
  "shipping_address": "12 Rosewood Ave",
  "customer": {
    "id": 88,
    "name": "wiener",
    "email": "wiener@example.com",
    "internal_notes": "Chargeback risk - 2 prior disputes",
    "lifetime_value": 812.44
  },
  "internal_fraud_score": 12
}
```

This is *expected* — the admin should see cost price, fraud score, and internal notes. The real
test is: **does the exact same `GET /api/orders/4471` request, sent with the normal user's own
token, ever return any of `cost_price`, `supplier_id`, `internal_notes`, `lifetime_value`, or
`internal_fraud_score`?** If the backend uses one serializer for both roles and only conditionally
hides fields in the *frontend* rendering logic — rather than in the API response itself — the
normal user's raw response will contain all of it. That is the Excessive Data Exposure finding,
and it's a more severe one than a static over-exposure bug because it proves the backend has
*no server-side role-awareness at all* in its serialization layer.

---

## 3. Where mass assignment reconnaissance and EDE testing overlap

Every field name and valid value you learn from an Excessive Data Exposure finding becomes direct
ammunition for Mass Assignment testing (file 3). When you find `"role": "user"` in a GET
response, that is simultaneously:

1. An EDE finding on its own (the exact role string shouldn't need to be exposed to the client)
2. Reconnaissance telling you the precise field name (`role`, not `userRole` or `user_type`) and
   the precise privileged value (`admin`) to try injecting in a PATCH/POST request

Always treat GET response bodies as a wordlist source for later write-direction testing, not just
as read-direction findings in isolation.

---

## 4. Tooling

- **Burp Comparer** — the primary tool for role-based response diffing described in Section 2.
  Send both raw responses to Comparer, diff in "words" mode.
- **Autorize (Burp extension)** — automates re-sending every request in your proxy history with
  a lower-privileged session token and flags responses that still return data. Best used as a
  bulk first pass across an entire application before manual field-by-field review.
- **A custom diff script** — for large APIs, export responses as JSON and diff key sets
  programmatically (Python's `set()` on `dict.keys()` recursively) rather than relying on manual
  reading. Useful when a single object has 40+ fields across nested structures.

---

## 5. PortSwigger Web Security Academy lab mapping — honest gap disclosure

PortSwigger's API testing topic does **not** have a lab named specifically for Excessive Data
Exposure. This is a real gap in their free lab set, not an oversight in this note series — worth
knowing so you don't spend time searching for a lab that isn't there. The closest and most useful
labs to build the underlying skill are:

1. **Exploiting an API endpoint using documentation** (API testing topic) — builds the recon
   habit of reading every field a documented API can return, which is the exact skill Section 1
   of this file depends on.
2. **Access control vulnerability labs** (Access control topic, e.g. "User ID controlled by
   request parameter, with unpredictable user IDs" and related labs) — while framed as BOLA,
   several of these labs involve noticing extra data in a response that reveals another user's
   information. Working through them with an eye specifically on *response field content*, not
   just *which object you accessed*, transfers directly to EDE testing.
3. **crAPI** (see below) is the better hands-on target for EDE specifically, since it was built
   with BOPLA scenarios as an explicit design goal, unlike PortSwigger's labs which predate the
   API3:2023 merge.

## 6. crAPI reference

crAPI's vehicle-location and mechanic-report workflows are built around exactly this class of
bug. Look at the vehicle location history endpoint and the mechanic report retrieval endpoint —
both return more of the underlying object than the corresponding UI screen displays, including
data tied to other users' vehicles when object-level checks are also weak. Testing crAPI's
`/identity/api/v2/user/*` and `/workshop/api/*` endpoint groups with the response-vs-UI diff
process from Section 1 is the fastest way to build muscle memory for this vulnerability class
before taking it into a real assessment.

---

## 7. Real-world notes

- Excessive Data Exposure findings are frequently dismissed by development teams as "informational"
  because "the frontend doesn't show it" — Section 3 of file 1 already covers why that reasoning
  is invalid, but expect to make this argument in every report you write. Always demonstrate
  impact concretely: show the exact `curl` command a non-technical attacker with only browser dev
  tools could run, not just an annotated Burp screenshot.
- Mobile applications are disproportionately affected because mobile API responses are rarely
  inspected as carefully as web responses during development — the assumption that "only our app
  parses this" is common and always wrong; any API response is inspectable with a proxy regardless
  of client type.
- GraphQL APIs have their own over-fetching dynamic (a client *can* request unnecessary fields
  if the schema exposes them, even without a resolver-level authorization bug) — this is
  structurally related to EDE but has its own dedicated testing approach and is out of scope for
  this REST-focused file.
