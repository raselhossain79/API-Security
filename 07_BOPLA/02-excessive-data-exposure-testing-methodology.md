# BOPLA — Broken Object Property Level Authorization
### File 2 of 6: Excessive Data Exposure — Testing Methodology

---

## 1. The Core Testing Principle

Excessive Data Exposure cannot be found by looking at the rendered UI. It is found by
looking at the **raw HTTP response body** and asking: *"Does this JSON contain anything
the UI does not show, and should any authenticated caller — regardless of role — be able
to see it?"*

Every test in this file follows the same three-step loop:

1. Capture the full raw response of an API call (Burp Proxy/Repeater, never the rendered
   page).
2. Diff the fields present in the response against the fields the UI actually renders.
3. For every extra field found, classify it: internal-only (safe), low-sensitivity
   (borderline), or sensitive (password/token/PII/authorization data — a finding).

---

## 2. Step 1: Enumerate Every Field in the Raw Response

### 2.1 Capturing the full response

In Burp Suite:
- Turn on **Proxy → Intercept** or simply browse normally with Burp as your proxy and
  review requests in **HTTP history**.
- Locate every API call the frontend makes (filter HTTP history by MIME type `JSON`, or
  by URL pattern `/api/`).
- Send any endpoint returning user/object data to **Repeater**.

### 2.2 Example — a profile endpoint

Request:
```
GET /api/users/me HTTP/2
Host: target.example.com
Authorization: Bearer <token>
```

Response (raw, as received — before any frontend JS touches it):
```json
{
  "id": 8841,
  "username": "rasel_t",
  "email": "rasel@example.com",
  "full_name": "Rasel T.",
  "profile_photo": "https://cdn.example.com/u/8841.jpg",
  "password_hash": "$2b$12$KIXQ...redacted...",
  "email_verified": true,
  "phone_number": "+8801XXXXXXXXX",
  "is_admin": false,
  "internal_risk_score": 12,
  "created_at": "2025-11-02T08:11:00Z",
  "last_login_ip": "103.X.X.X",
  "stripe_customer_id": "cus_Q8x...redacted...",
  "referral_code": "RT8841X"
}
```

**Field-by-field breakdown of why this is a finding:**

| Field | UI shows it? | Why it's exposed anyway | Risk |
|---|---|---|---|
| `password_hash` | No | The backend serialized the entire user ORM row/object into JSON without an explicit field whitelist | Critical — offline cracking if hash algorithm is weak, or reuse against the same hash elsewhere |
| `is_admin` | No | Same object-dump root cause | High — reveals privilege info; if this same field is writable (see Mass Assignment, file 3), the exposure also tells the attacker exactly which field name to target |
| `internal_risk_score` | No | Same object-dump root cause | Medium — business-internal scoring logic exposed, could aid fraud-detection evasion |
| `last_login_ip` | No | Same object-dump root cause | Medium/High — PII, aids account takeover / geolocation of victim |
| `stripe_customer_id` | No | Same object-dump root cause | High — a real external identifier; if the payment provider's API accepts this ID in another context (support impersonation, SSRF-adjacent abuse), it becomes a pivot |

The mechanism is the same for all five rows: the server did **not** build this JSON with
an explicit list of allowed output fields. It serialized the object as-is (e.g., an ORM
`.to_dict()`/`.to_json()`/default Jackson POJO serialization) and let *every* attribute on
that model reach the wire.

---

## 3. Step 2: Response vs UI Field Comparison — Systematic Method

Do this for **every distinct object type** the API exposes (user, order, ticket, vehicle,
document, etc.), not just the profile endpoint.

1. Load the page/screen in the browser that displays this object.
2. Note every value **visually rendered** on screen.
3. Open the corresponding raw API response in Burp.
4. Build a two-column list: *(a)* fields rendered in UI, *(b)* fields present in raw JSON.
5. Anything in *(b)* not in *(a)* is a candidate finding — evaluate sensitivity per the
   table pattern above.

A quick heuristic for prioritizing which extra fields matter: fields whose names match
`*_hash`, `*_token`, `*_secret`, `*_key`, `internal_*`, `is_*`, `*_admin`, `*_role`,
`*_score`, `*_ip`, `ssn`, `dob`, `*_id` (especially sequential integer IDs useful for BOLA)
are worth flagging immediately even before assessing full business impact.

---

## 4. Step 3: Response Field Comparison Across Roles

This is the step that catches **role-dependent** over-exposure — where the *shape* of the
response is identical between a normal user and an admin, but it shouldn't be.

### 4.1 Method

1. Authenticate as a low-privilege user (User A). Capture the response for
   `GET /api/orders/{id}` on an order **User A owns**.
2. Authenticate as an admin/support-role account (if you have legitimate access to one in
   scope — e.g., a second test account provisioned for you, not privilege escalation).
   Capture the response for the **same order ID** viewed through an admin-facing endpoint.
3. Diff the two JSON bodies field-by-field.
4. If the admin-only fields (e.g., `internal_notes`, `fraud_flag`, `cost_price`,
   `supplier_margin`) are **also present in User A's response**, even though the frontend
   UI for User A never renders them — that is Excessive Data Exposure conditioned on role.

### 4.2 Concrete example

User A's raw response to `GET /api/orders/5521`:
```json
{
  "order_id": 5521,
  "item": "Wireless Mouse",
  "sale_price": 24.99,
  "cost_price": 9.10,
  "supplier_margin_pct": 63.5,
  "fraud_flag": false,
  "status": "shipped"
}
```

**Breakdown:** `cost_price`, `supplier_margin_pct`, and `fraud_flag` are internal
business/security fields. The storefront UI only ever renders `item`, `sale_price`, and
`status`. Their presence in the *customer-facing* order endpoint response proves the
backend uses **one shared serializer for both the admin and customer view** — the
authorization boundary that should exist between roles was never enforced at the property
level. A customer inspecting network traffic (something any user can do with browser
DevTools, no special tooling required) sees their supplier's cost basis and margin on
every item they've ever bought.

### 4.3 What to test across every role pair available to you
- Anonymous vs authenticated
- Regular user vs regular user (their own object vs someone else's, to also catch BOLA
  overlap)
- Regular user vs elevated role (support, admin, moderator) — same object ID, both
  endpoints
- Regular user vs the *mobile app's* API version vs the *web app's* API version — different
  clients sometimes hit different endpoint versions with inconsistent field filtering

---

## 5. Nested and List Endpoints — Don't Stop at the Top Level

Excessive Data Exposure frequently hides in **nested objects** and **array/list
endpoints**, which are easy to skim past:

- `GET /api/orders` (a list) often embeds the **full nested user object** for each order's
  buyer — meaning a list of 50 orders can leak 50 users' full profiles, including fields
  that the single-object `GET /api/users/{id}` endpoint has already been "fixed" to hide.
  Testing one endpoint's fix does not mean a sibling endpoint reusing the same nested
  serializer is also fixed.
- Pagination/search/autocomplete endpoints (`GET /api/users/search?q=ras`) often return
  the same over-exposed object shape as the main profile endpoint, but get less security
  scrutiny because they "just power a dropdown."

---

## 6. Real-World Note

The T-Mobile 2023 API breach (referenced in file 1) was discovered through exactly this
kind of response inspection: security researchers noted that an API endpoint's JSON
response contained far more customer PII fields than the corresponding app screen ever
rendered, for **every** authenticated session — no role comparison was even needed because
the base case was already over-exposed. This underscores that Step 1 (raw response vs UI)
alone, done consistently across every endpoint, catches the majority of real-world
findings; role comparison (Step 3) catches the more subtle subset.

---

## 7. PortSwigger Lab Mapping — Honest Gap Disclosure

**There is currently no PortSwigger Web Security Academy lab dedicated specifically to
"Excessive Data Exposure" as OWASP defines it.** PortSwigger's API Testing learning path
focuses on mass assignment, parameter pollution, and endpoint discovery rather than
response over-exposure as a standalone lab category. This is a genuine coverage gap in
Academy's curriculum, not an oversight in this note series.

The closest related labs, useful for building adjacent skills (API recon and spotting
data leaked in responses that shouldn't be), in Apprentice → Practitioner order:

| Order | Difficulty | Lab | Relevance |
|---|---|---|---|
| 1 | Apprentice | *Exploiting an API endpoint using documentation* (API Testing topic) | Trains discovering hidden/undocumented API endpoints and reading raw responses directly — the core skill this file relies on |
| 2 | Practitioner | *Finding and exploiting an unused API endpoint* (API Testing topic) | Reinforces inspecting full API responses rather than trusting the UI, since the exploited endpoint isn't wired to any UI at all |
| 3 | Apprentice | *User ID controlled by request parameter with data leakage in redirect* (Access Control topic) | Not BOPLA proper, but trains the same "read the raw HTTP data, not the rendered page" reflex |

Use **crAPI's** dashboard and vehicle-location endpoints (section 6, file 1) as your
primary hands-on practice for this specific sub-type, since it is purpose-built to
demonstrate exactly this pattern, unlike PortSwigger's Academy.

---

Continue to **File 3 — Mass Assignment Testing Methodology**.
