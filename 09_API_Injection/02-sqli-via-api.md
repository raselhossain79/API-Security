# SQL Injection via API (JSON Body Context)

> Prerequisite: this file assumes familiarity with core SQLi mechanics (UNION-based,
> error-based, boolean-blind, time-blind) from the standalone SQL Injection series.
> This file covers **only** how those techniques change when delivered through a
> JSON API body instead of a form.

## 1. Why the Injection Point Looks Different

In a form-based target, the vulnerable parameter is visible in the rendered page —
you fill a login box, submit, and Burp shows you `username=admin&password=x`. In an
API-based target, you typically never see a form at all. You reconstruct the request
from:

- Mobile app traffic captured through Burp with a proxy-aware emulator/device
- An OpenAPI/Swagger spec (`/swagger.json`, `/openapi.json`, `/api-docs`)
- JavaScript source (SPA frontends calling `fetch()`/`axios` against a JSON API)

The request you're testing looks like this:

```http
POST /api/v2/auth/login HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "admin",
  "password": "test123"
}
```

The injection point is the **string value** of a JSON key, not a bare form field.

## 2. Basic JSON Body SQLi — Payload Breakdown

### 2.1 Baseline Request

```json
{
  "username": "admin",
  "password": "test123"
}
```

This establishes the normal response — a 401 with a JSON body like
`{"error": "invalid credentials"}`. You need this baseline before injecting, because
API error responses (unlike HTML error pages) can look nearly identical between
"wrong password" and "SQL error was swallowed" — the delta may only be a few bytes.

### 2.2 Injected Request

```json
{
  "username": "admin' OR '1'='1",
  "password": "test123"
}
```

**Breakdown, piece by piece:**

| Fragment | Role |
|---|---|
| `admin` | Intended value the app expects |
| `'` | Closes the string literal the backend query wrapped `username` in, e.g. `WHERE username = 'admin'` becomes `WHERE username = 'admin'` + your injected SQL |
| ` OR '1'='1` | Appends a condition that is always true, turning the `WHERE` clause into a tautology |

The resulting server-side SQL (assuming naive string concatenation) becomes:

```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'test123'
```

**Why this is JSON-syntax-safe:** the payload contains no `"` character, so it drops
into the JSON string value without needing any escaping. This is *why* single-quote
SQLi payloads are the easiest starting point for API SQLi testing — no JSON-escaping
complexity to manage while you're first confirming the injection point exists.

### 2.3 When the Payload Requires a Double Quote

Some payloads (especially ones targeting double-quote-delimited SQL dialects, or
payloads that need to reference JSON-like data) require `"` inside the value. Example
target: a search endpoint using a SQL dialect that wraps identifiers in `"`.

**Raw SQLi payload:** `test" OR "1"="1`

**As it must appear inside the JSON body:**

```json
{
  "search": "test\" OR \"1\"=\"1"
}
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `test` | Intended search value |
| `\"` | Escaped double-quote — required so the *JSON parser* sees a literal `"` character inside the string rather than interpreting it as the end of the JSON string. Without the backslash, the JSON document is invalid and the request is rejected with 400 before reaching the SQL layer. |
| ` OR \"1\"=\"1` | The actual SQL injection payload — once the JSON parser has decoded `\"` back into `"`, the *application/SQL layer* sees `test" OR "1"="1`, which is the tautology payload targeting double-quote string delimiters |

This is the core two-layer encoding concept referenced in the overview file: you are
escaping for JSON first, then relying on the JSON parser to hand the *decoded* string
to the SQL layer, where your actual injection logic executes.

## 3. UNION-Based SQLi in a JSON Body

Target: a product search API.

```http
POST /api/v2/products/search HTTP/1.1
Content-Type: application/json

{
  "query": "laptop",
  "category": "electronics"
}
```

Determining column count (error-based probing), then extracting data:

```json
{
  "query": "laptop' UNION SELECT username, password, NULL, NULL FROM users-- -",
  "category": "electronics"
}
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `laptop` | Intended search term |
| `'` | Closes the original string literal |
| `UNION SELECT username, password, NULL, NULL FROM users` | Appends a second query whose result set is merged with the original; column count and types must match the original `SELECT` (determined beforehand via `ORDER BY` probing or incrementing `UNION SELECT NULL,...` counts) |
| `-- -` | Comments out the remainder of the original query (e.g., a trailing `AND category = 'electronics'` clause) so it doesn't cause a syntax error or filter out your injected rows |

Note the `category` field is left untouched — the injection only needs to happen in
one field per request in this example, but real endpoints often validate multiple
fields, so a full test walks every string-typed key independently.

## 4. Blind SQLi (Boolean-Based) via API

APIs frequently return generic JSON error bodies regardless of the underlying cause,
which removes the visual cues form-based blind SQLi testing relies on. Boolean-blind
testing against JSON APIs instead compares:

- HTTP status code
- Response body length
- Specific field presence/absence in the JSON response

**True condition:**

```json
{
  "productId": "1 AND 1=1"
}
```

**False condition:**

```json
{
  "productId": "1 AND 1=2"
}
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `1` | Intended numeric ID, unquoted context (no `'` needed since this field is likely concatenated as a raw number, not a quoted string) |
| `AND 1=1` / `AND 1=2` | Appends a condition that is always true / always false, without needing to close a string literal — this only works if `productId` is inserted into the query without quotes, i.e., `WHERE id = 1 AND 1=1` |

If the true-condition request returns the product data (200, full JSON body) and the
false-condition request returns an empty result (200, `{"results": []}` or 404), the
delta confirms blind boolean-based SQLi — even though no error message or visible
page difference exists.

## 5. Time-Based Blind SQLi via API

Used when boolean deltas are also suppressed (identical response regardless of
true/false).

```json
{
  "productId": "1 AND (SELECT SLEEP(5))"
}
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `1 AND` | Preserves valid syntax, chains an additional condition |
| `(SELECT SLEEP(5))` | MySQL function forcing a 5-second delay if this branch of the query executes; the response time itself becomes the oracle since there's no visible or content-based signal otherwise |

Measure baseline response time first (`productId: "1"` alone), then compare against
the injected request. A consistent ~5-second delta confirms the injection, independent
of response body content.

## 6. Burp Suite Workflow for API-Context SQLi (vs. Forms)

1. **Capture via Proxy**, filtering by `Content-Type: application/json`.
2. **Send to Repeater.** Use the Inspector's parsed JSON tree (Burp 2023.x+) to edit
   individual values without manually tracking brace/quote balance.
3. **Send to Intruder** for automated payload sweeping:
   - Place the `§` position markers *inside* the string value only:
     `"username": "§FUZZ§"`
   - Load the SQLi payload list (SecLists `Fuzzing/SQLi/*` or a custom list built
     from this file's payloads).
   - **Critical difference from form-based Intruder runs:** enable Burp's
     "URL-encode these characters" setting appropriately for JSON — you generally
     want it **disabled** for JSON bodies (URL-encoding is a form-encoding concern,
     not a JSON one) but you must ensure payloads containing `"` are pre-escaped as
     `\"` in the payload list itself, since Intruder does not auto-escape for JSON.
4. **Grep-Match** on response body length and status code columns to spot deltas
   across the sweep instead of relying on visual inspection of each response.

## 7. PortSwigger Lab Mapping

Complete in this order. Labs are drawn from the SQL Injection category; the ones
listed explicitly involve JSON-body or non-form delivery, or are directly relevant to
practicing the blind/UNION technique in a context you then adapt to JSON manually:

1. **SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**
   — form-based baseline; do this first if not already completed in your web-app
   series, to confirm you understand the core tautology technique before adding JSON
   escaping complexity.
2. **SQL injection UNION attack, determining the number of columns returned by the
   query** and **...retrieving data from other tables** — practice UNION mechanics;
   when repeating against a real API target, adapt the payload into a JSON body per
   Section 3 above.
3. **Blind SQL injection with conditional responses** — practice boolean-blind
   mechanics; this maps directly onto Section 4's technique once the target is JSON.
4. **Blind SQL injection with time delays** — maps directly onto Section 5.
5. **Blind SQL injection with time delays and information retrieval** — combine
   time-based confirmation with data extraction; this is the closest lab analog to a
   real-world blind SQLi finding against a JSON API where no other oracle exists.

**Gap disclosure:** PortSwigger does not currently offer a lab where the *injection
point itself* is a JSON body field (all SQLi labs use form/query-string delivery).
The JSON-context adaptation in this file is a manual extension you apply yourself
when practicing against real API targets (e.g., crAPI, VAmPI, or bug bounty scope) —
there is no lab that tests the JSON-escaping step directly.

## 8. Real-World Notes

- Frameworks using ORMs (Sequelize, Prisma, SQLAlchemy) are generally safe from
  string-concatenation SQLi *unless* the developer drops to raw query methods (`.raw()`,
  `.query()`, `text()`) for "complex" filters — these raw-query escape hatches are
  disproportionately common in **search/filter API endpoints** because ORMs handle
  simple `WHERE` clauses well but struggle with dynamic multi-field search, pushing
  developers toward raw SQL exactly where user input is richest.
- JSON error bodies frequently leak the underlying SQL error message directly (e.g.,
  Node.js + `mysql2` returning the driver's error object serialized into the JSON
  response) — this alone is a common, real, reportable finding (information
  disclosure) even before full exploitation, and it's the fastest way to confirm
  string-concatenated SQL is in play.
- Rate limiting on auth endpoints is common but rarely extends to internal
  search/filter/list API endpoints — these are frequently the most productive place
  to run time-based blind sweeps without triggering account lockout or WAF blocking
  that a login endpoint would trigger.
