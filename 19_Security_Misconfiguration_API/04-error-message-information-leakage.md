# 04 — Error Message and Information Leakage in API Responses

## 1. Why API error leakage is distinct from web app error leakage

The general mechanism — an application returns more internal detail on failure than it should —
is shared with the web app Security Misconfiguration and Information Disclosure content. What's
different for APIs:

- Errors are returned as **structured JSON**, which is trivial to parse programmatically. A stack
  trace embedded in an HTML error page requires some scraping; a stack trace as a JSON field
  (`{"error": "...", "trace": [...]}`) can be extracted and correlated across hundreds of requests
  automatically, making systematic exploitation (e.g., fingerprinting every dependency version
  across every endpoint) far faster against an API than against an HTML app.
- APIs are typically tested with automated fuzzing (malformed types, oversized payloads, wrong
  content-types) far more aggressively than HTML forms, because there's no client-side validation
  layer in the way — this means verbose error paths in APIs get triggered far more easily and far
  more often than the equivalent in a browser-mediated web app, where a lot of malformed input
  never reaches the server at all.

## 2. Stack traces in API error responses

### 2.1 What a stack trace hands an attacker

- **Full internal file paths** (`/var/www/app/src/controllers/PaymentController.php:142`),
  revealing server OS, deployment directory layout, and framework structure.
- **Class/method names**, revealing internal architecture and sometimes business logic naming that
  hints at unlisted functionality (a method named `applyLegacyDiscountOverride` visible in a trace
  is a lead worth chasing even if you never saw a corresponding endpoint in the spec).
- **The exact exception type**, which frequently maps directly to a **known CVE** if it names a
  specific library (`com.fasterxml.jackson.databind.exc.InvalidTypeIdException`,
  `System.Data.SqlClient.SqlException`) — the trace becomes a targeted vulnerability lookup, not
  just generic recon.

### 2.2 Piece-by-piece: how to trigger one

1. **Type confusion.** Send a string where an integer is expected, or vice versa:
   ```json
   {"productId": "not-a-number"}
   ```
   Many frameworks throw an unhandled parsing exception (`NumberFormatException`,
   `TypeError`) before any input-validation middleware gets a chance to produce a clean 400.
2. **Out-of-range values.** Extremely large integers, negative values where unsigned is expected,
   or values exceeding a field's declared max length:
   ```json
   {"quantity": 999999999999999999999}
   ```
   Integer overflow/parsing failures at the deserialization layer (before your application code
   runs) are a common source of raw framework exceptions leaking straight through.
3. **Malformed structure.** Truncated JSON, unexpected nesting, an array where an object is
   expected:
   ```json
   {"user": [1,2,3]}
   ```
   when `user` is documented as an object — deserializer-level exceptions here often include the
   exact library name and version in the error text (Jackson, Gson, System.Text.Json all emit
   distinctive exception class names).
4. **Wrong `Content-Type`.** Send a JSON body with `Content-Type: application/xml` or omit the
   header entirely — some frameworks fail during content negotiation with a verbose 415/500 rather
   than a clean, generic error.
5. **Unexpected null.** Explicitly send `null` for a field the framework's internal code assumes
   is always present after a prior validation step passed — this targets the gap between
   "validation happened" and "the value is actually usable," a common source of
   NullPointerException-class traces.

### 2.3 Piece-by-piece: what to extract once you have a trace

Break the trace down field by field rather than just noting "verbose error, report it":

- **Framework + version** (e.g., `Spring Framework 5.3.x`, `Express 4.17.x`) → cross-reference
  against public CVE databases immediately; a version-specific known RCE or deserialization CVE
  turns this from an informational finding into a critical one.
- **Application-internal namespace/package structure** → tells you the technology stack's naming
  conventions, useful for guessing further internal endpoint or class names for subsequent testing.
- **Database driver class names** (`org.postgresql.util.PSQLException`,
  `com.mysql.cj.jdbc.exceptions.*`) → confirms exact DB engine, informing SQL injection payload
  syntax choices even before you've confirmed an injection point exists.
- **File system paths** → confirms OS (`C:\inetpub\` vs `/var/www/` vs `/opt/`), directly informing
  path traversal payload construction if a file-read vulnerability is found elsewhere.

## 3. Internal paths, DB query fragments, and library versions specifically

These three often appear together in a single error body rather than needing separate triggers,
but are worth breaking apart individually since each has a different downstream use:

### 3.1 Internal paths

Beyond OS/deployment fingerprinting (§2.3), internal paths sometimes reveal **naming conventions
for other internal services** reachable only from inside the network — a path like
`/opt/services/billing-internal/app.py` in a trace is a concrete service name to feed into further
SSRF or internal-recon attempts (cross-reference the SSRF/API7 series).

### 3.2 DB query fragments

**How they leak.** A database exception message frequently includes the **literal fragment of SQL
that failed**, e.g.:
```json
{
  "error": "SQLSTATE[42S22]: Column not found: 1054 Unknown column 'usr.password_hash' in 'field list'",
  "query_fragment": "SELECT id, email, usr.password_hash FROM users usr WHERE ..."
}
```
**Piece-by-piece: what this specific example reveals.**
- The literal table name (`users`) and column name (`password_hash`), confirming a schema detail
  no client-facing documentation would ever state.
- The query's alias convention (`usr`), useful for constructing syntactically valid injection
  payloads if a SQLi point is found elsewhere in the same codebase (consistent aliasing patterns
  across queries are common within one codebase).
- Confirmation that password hashes are selected in this query at all — informs prioritization: an
  IDOR or injection bug found nearby is now known to have direct access to credential material,
  not just profile data.

### 3.3 Library versions

Beyond the framework itself, look for versions of **secondary libraries** surfaced incidentally —
JSON serialization libraries, ORM versions, template engines — each is an independent CVE lookup.
Build a running list per engagement rather than treating each disclosure as an isolated,
one-off finding; a single misconfigured error handler across dozens of endpoints can hand you a
nearly complete dependency inventory over the course of normal testing.

## 4. WAF / API Gateway Relevance for This File

This is the one file in the series where both detection and bypass genuinely apply, for two
separate reasons:

**Detection.** Some WAFs are tuned specifically to recognize *inputs known to trigger* verbose
errors — oversized integers, type-confusion payloads, deeply nested JSON — because these are also
common precursors to DoS or deserialization attacks, not just information-disclosure triggers.
A WAF blocking a request with an absurdly large integer or deeply nested array is not necessarily
"protecting the error message" specifically, but the side effect is the same: your triggering
input never reaches the backend.

**Bypass considerations:**
- **Split the trigger across multiple less-anomalous-looking requests** where possible — e.g., if
  a single deeply nested payload is blocked, test whether a moderately nested payload still
  triggers the same class of exception without tripping a depth-based rule.
- **Vary encoding.** A WAF rule tuned to catch a literal oversized integer in a JSON body may not
  inspect the same value if it's URL-encoded in a query string parameter that the backend also
  accepts, or vice versa.
- **Test via less-common content types.** A WAF ruleset is often tuned primarily around
  `application/json` bodies; the same type-confusion trigger sent as `multipart/form-data` or
  `application/x-www-form-urlencoded` (if the endpoint accepts it) may bypass rules scoped to JSON
  parsing specifically.
- **Gateway-side error sanitization is a real defense, not just a detection layer.** Some API
  gateways rewrite any backend 5xx response into a generic `{"error": "internal error"}` before it
  reaches the client, regardless of what the backend actually returned. If you can find any path
  that reaches the backend directly (a misconfigured direct route, a different subdomain, an
  internal endpoint reachable via SSRF) the same trigger that produced a sanitized response through
  the gateway may produce the full raw trace when the backend is reached directly — always test
  known triggers against every discovered ingress path, not just the primary one.

## 5. PortSwigger Web Security Academy Lab Mapping

All labs below are **Apprentice** difficulty — PortSwigger's Information Disclosure topic does not
extend into Practitioner/Expert tiers, which is stated here rather than implying a progression that
doesn't exist.

1. *Information disclosure in error messages* — directly matches §2.2's type-confusion trigger
   technique (an invalid parameter value reveals a framework/library version in the error).
2. *Information disclosure on debug page* — matches the general "verbose diagnostic output left
   reachable" pattern; in an API context this maps to any `/debug`, `/actuator`, `/health/detail`
   style endpoint left enabled (cross-reference file 02 for endpoint-discovery methodology).
3. *Source code disclosure via backup files* — not error-triggered, but same underlying theme of
   unintended internal detail exposure; relevant to API source maps (`.js.map` files served
   alongside a frontend that calls the API) or backup copies of API config files.
4. *Authentication bypass via information disclosure* — demonstrates the escalation path this whole
   file exists to warn about: a disclosed internal header name (via a verbose response) becomes a
   direct authentication bypass, not just an informational finding.
5. *Information disclosure in version control history* — relevant if a `.git` directory or similar
   is reachable from an API host, exposing config files with embedded DB credentials.

**Gap disclosure:** PortSwigger's labs demonstrate each pattern once, cleanly, in isolation. They
do not model the **systematic, cross-endpoint fingerprinting workflow** described in §2.3/§3.3
(building a dependency inventory across dozens of API routes over the course of an engagement).
For practicing that workflow specifically, **crAPI** is a better fit, since it exposes multiple
verbose error paths across its microservice endpoints that can be chained the way a real API
assessment would.

## 6. Real-World Notes

- Deserialization-library exceptions leaking through 500 errors have directly led to identifying
  known insecure-deserialization CVEs in real assessments — an error message is often the fastest
  path to a critical finding, faster than deliberately searching for a deserialization sink in
  source code that isn't available.
- Query fragment leakage is disproportionately common in APIs using ORMs configured with debug/
  verbose logging modes left on in production — the ORM's own debug output, meant for local
  development, gets piped straight into the client-facing error response because nobody
  distinguished "log this" from "return this to the client."
- Gateway-level error sanitization gaps (finding a direct backend path that bypasses gateway
  cleanup) have been a recurring theme in engagements against microservice architectures where one
  service is fronted by the gateway correctly but a sibling internal service is reachable directly
  due to a network segmentation oversight.

## 7. Remediation Summary

- Catch exceptions at a global handler level and return a generic, consistent error shape
  (`{"error": "invalid_request", "request_id": "..."}`) for every unhandled exception class,
  regardless of what triggered it.
- Log full detail (trace, query fragment, library version) server-side only, keyed to the
  `request_id` returned to the client, so support/debugging is still possible without leaking
  anything client-side.
- Validate types, ranges, and structure at the API boundary before any business logic or ORM code
  runs, so malformed input never reaches a layer capable of throwing a raw framework exception.
- Enforce the same generic-error behavior at the gateway level as a defense-in-depth backstop, and
  regularly verify no internal/direct path bypasses that gateway-level sanitization.
