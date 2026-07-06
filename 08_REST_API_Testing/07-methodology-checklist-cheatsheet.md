# REST API Testing Methodology — 07: Final Checklist & Cheatsheet

This file compresses Files 01–06 into a single sequential run-sheet. Use it during live testing; use Files 01–06 when you need the mechanism-level explanation behind a checklist item.

---

## Phase 0 — Setup (File 01)

- [ ] Located API spec (OpenAPI/Swagger/RAML/Postman collection) or confirmed none is provided
- [ ] If no spec provided, actively searched: `/api-docs`, `/swagger-ui.html`, `/openapi.json`, `/v2/api-docs`, `/redoc`, JS bundle path extraction
- [ ] Extracted from spec: paths, methods per path, security schemes, parameters, request content-types, response schemas, server/base URLs
- [ ] Built endpoint inventory (path, documented methods, auth requirement, discovered-via-UI vs. spec-only)
- [ ] Burp scope set to all API base paths, including versioned/subdomain hosts
- [ ] Burp extensions installed: JWT Editor, Param Miner, Content Type Converter, OpenAPI Parser
- [ ] Burp session handling rule configured for token refresh (if short-lived tokens in use)
- [ ] Postman collection generated from spec (if spec available), environment variables set, proxy routed through Burp
- [ ] Baseline recorded for every endpoint: normal response (status, headers, body shape) per available role
- [ ] Baseline rate-limit behavior recorded (burst test, note throttling threshold)
- [ ] Baseline error-message format recorded (missing param, invalid ID)

## Phase 1 — HTTP Method Testing (File 02)

For every endpoint in inventory:
- [ ] `OPTIONS` sent, `Allow` header recorded (treated as hint, not ground truth)
- [ ] Documented method sent, confirmed matches baseline
- [ ] All undocumented methods sent (`GET/POST/PUT/PATCH/DELETE/HEAD`, `TRACE` where relevant) using low-privilege token against a disposable/non-critical object
- [ ] Empty-body vs. populated-body variant tested for state-changing methods
- [ ] Method-override headers tested (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`) via `POST`
- [ ] Intruder HTTP-verbs sweep run at scale across full inventory (throttled if target shows rate-limit/WAF signals)
- [ ] Any positive hit manually re-verified before recording as a finding

## Phase 2 — Versioning Attacks (File 03)

- [ ] All version references extracted from recon (path segments, `Accept`/custom version headers, query strings, spec `servers` field, response headers)
- [ ] Enumerated downward (older versions) and upward (beta/unreleased) from every known version
- [ ] Header-based/content-negotiation versioning tested independently of path-based, if the target uses this scheme
- [ ] Same authenticated request replayed across every reachable version; diffed for: authorization enforcement, rate-limiting, input validation strictness, response field disclosure
- [ ] Legacy versions tested for support of deprecated/weaker auth mechanisms
- [ ] Checked whether origin is directly reachable, bypassing gateway-level version restrictions

## Phase 3 — Content-Type Manipulation (File 04)

For every endpoint accepting a request body:
- [ ] Malformed body sent to elicit parser error/fingerprint
- [ ] Same logical request sent as: `application/json` (baseline), `application/xml`, `text/plain`, `application/x-www-form-urlencoded`
- [ ] Any unexpectedly-accepted content-type (non-`415` response) flagged for follow-up
- [ ] If XML accepted: pivoted to XXE probe (external entity resolution test) — full exploitation via dedicated XXE series
- [ ] Error verbosity compared across content-types against Phase 0 baseline
- [ ] Content Type Converter BApp run across full inventory once mechanism validated manually

## Phase 4 — Response Differential Analysis (File 05)

- [ ] Role differential: same request sent unauthenticated / low-privilege / high-privilege; diffed for status code, field presence, field value differences
- [ ] Resource-ID differential: same role, adjacent/different resource IDs, checked for cross-object access
- [ ] Content-type differential: same role, JSON vs. XML, diffed field shape and error verbosity
- [ ] Parameter boundary-value differential: clean baseline vs. single-character injection probe, diffed status/timing/length/error content
- [ ] Type-confusion differential: number vs. numeric-string vs. array-of-string for same field
- [ ] Enumerated-value differential: full plausible value range sent for any small-value-space parameter (status/role/tier fields), not just spot-checked
- [ ] Every diff result recorded, including "no difference — control confirmed working" results

## Phase 5 — Parameter Fuzzing Methodology (File 06)

- [ ] Full documented request body schema mapped (types, required/optional, enums, nesting depth)
- [ ] Leaf-value fuzzing per field: string-for-number, negative, zero, extreme magnitude, `null`
- [ ] Structural-type fuzzing per field: array-for-scalar, object-for-scalar
- [ ] Nested-object fuzzing at every level (not just leaves): empty object, `null` object, array-for-object at top level
- [ ] Duplicate-key test within nested JSON structures
- [ ] Array injection: scalar-to-array conversion in query strings (`param[]=`, repeated `param=`)
- [ ] Array injection: unexpected/conflicting objects injected into existing arrays (mixed positive/negative values)
- [ ] Array size-limit probe (proportionate volume, stopped at first sign of server strain)
- [ ] Param Miner run against both query-string and JSON-body positions (body mode explicitly enabled)
- [ ] Candidate hidden parameters derived from: related-endpoint response fields, frontend JS references, naming-convention pattern guessing
- [ ] Any discovered hidden parameter confirmed to actually affect state/data, not merely accepted without error

## Phase 6 — WAF / Gateway Considerations (cross-cutting, all files)

- [ ] Checked for direct-origin reachability bypassing gateway-level controls (relevant to Files 02, 03)
- [ ] Tested whether gateway policies (WAF rules, rate limits, auth enforcement) are applied per-version or globally (File 03)
- [ ] Tested content-type/declared-vs-actual mismatch as a WAF-inspection bypass (File 04)
- [ ] Tested method-override header as a gateway method-restriction bypass (File 02)
- [ ] Confirmed schema-validation gaps on loosely-typed/optional fields as a fuzzing entry point where gateway schema enforcement is present (File 06)
- [ ] Paced all high-volume automated sweeps (Intruder, Param Miner) to avoid triggering volumetric rate-limiting/scanning-signature detection
- [ ] Recorded any distinct WAF block-page/error format differences as fingerprinting signal for future bypass attempts

---

## Quick-reference cheatsheet

### HTTP methods to test on every endpoint
```
GET  POST  PUT  PATCH  DELETE  OPTIONS  HEAD  TRACE
```

### Method override headers to try
```
X-HTTP-Method-Override: DELETE
X-HTTP-Method: DELETE
X-Method-Override: DELETE
```

### Version enumeration surfaces
```
Path:      /v1/  /v2/  /v3/  /api/2023-01-01/
Header:    Accept: application/vnd.company.v1+json
           X-Api-Version: 1
           Api-Version: 2023-06-01
Query:     ?version=1  ?api-version=1.0
Host:      api-v1.target.com
```

### Content-types to rotate on every body-accepting endpoint
```
application/json
application/xml
text/plain
application/x-www-form-urlencoded
multipart/form-data (if uploads also accepted)
```

### Leaf-value fuzz set (per field)
```
"1" (string-for-number)     -1 (negative)     0 (zero)
999999999999999 (overflow)  null              [] / {} (type confusion)
```

### Hidden parameter naming-pattern seeds
```
is_admin  is_staff  is_verified  is_active  is_locked  role  tier  internal
```

### Common API documentation / recon paths
```
/api  /api-docs  /api/docs  /swagger  /swagger-ui.html
/openapi.json  /v2/api-docs  /redoc  /graphql (if applicable)
```

---

## PortSwigger lab progression — full series, Apprentice → Expert

This is the consolidated, correctly-ordered lab list across the entire methodology (individual files above map each lab to its specific technique):

| Order | Lab | Difficulty |
|---|---|---|
| 1 | Exploiting an API endpoint using documentation | Apprentice |
| 2 | Finding hidden parameters | Apprentice |
| 3 | Finding and exploiting an unused API endpoint | Practitioner |
| 4 | Exploiting a mass assignment vulnerability | Practitioner |
| 5 | Exploiting server-side parameter pollution in a query string | Practitioner |
| 6 | Exploiting server-side parameter pollution in a REST URL | Expert |

**Honest gap disclosure (consolidated):** PortSwigger's API testing topic, as it currently stands, has no dedicated lab for: Burp/Postman setup and baselining (File 01), API versioning attacks (File 03), response differential analysis as a standalone mechanic (File 05), or JSON-body array/nested-structure fuzzing specifically (File 06, Sections B–C). These gaps are filled by crAPI (see each file's dedicated section) and, where noted in File 05, by transferable skills from your existing Broken Access Control and Broken Authentication series.

## crAPI — consolidated supplementary coverage

| crAPI area | Fills gap in |
|---|---|
| Community/Workshop services (full multi-microservice mapping) | File 01 — realistic endpoint mapping beyond a single-lab scope |
| Community/Workshop endpoints (undocumented methods) | File 02 — secondary practice ground alongside the Practitioner lab |
| Multiple microservices with independent versioning | File 03 — the primary practice environment for this entire file, since PortSwigger has no lab here |
| Multipart uploads with embedded JSON | File 04 — nested content-type testing, no PortSwigger equivalent |
| Multiple pre-seeded user accounts of differing privilege | File 05 — role-based differential analysis without needing separate lab instances |
| Shop/coupon nested order objects | File 06 — JSON nested-object and array-injection practice, no PortSwigger equivalent |

---

## Closing note on real-world application

This methodology is deliberately sequenced to mirror how a real, time-boxed engagement (bug bounty scope or a client pentest window) actually proceeds: cheap, broad, low-risk recon first (Files 01–03), then progressively more invasive and time-expensive testing (Files 04–06). If you're working under a tight time budget, Phases 0–2 alone will surface a disproportionate share of real findings relative to the time invested — method abuse and version enumeration are consistently among the highest-yield, lowest-effort checks against real-world APIs, which is exactly why they're positioned early in this sequence rather than treated as an afterthought.
