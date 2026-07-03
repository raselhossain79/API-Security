# REST API Testing Methodology — Part 3: API Versioning Attacks

## Series Position

This file assumes Parts 1 and 2 are complete. You have a full endpoint matrix with baselines, and you've swept every method against every endpoint on the API version you initially mapped. This file covers a dimension most testers miss entirely: **the same logical endpoint frequently exists at multiple version paths simultaneously, and older versions are disproportionately likely to have weaker security controls.**

---

## Why Versioning Is an Attack Surface, Not Just a URL Format

APIs evolve. `/v1/` gets built, ships, and accumulates real users. Security issues get found and fixed. `/v2/` gets built with the fixes baked in from the start. But `/v1/` is rarely deleted — deleting it breaks any client still calling it (old mobile app versions still installed on users' phones, third-party integrations that haven't updated, internal tooling nobody remembers exists). So `/v1/` keeps running, receiving little to no further security attention, while all new development and all new security fixes go into `/v2/` or later.

This produces a very specific, very common real-world pattern: **the exact same underlying business logic, reachable at two different paths, with two different security postures.** This is formally recognized as part of OWASP API9:2023 (Improper Inventory Management), which explicitly calls out old API versions as a distinct risk from simply "undocumented endpoints."

**Real-world framing:** this is one of the highest-value, lowest-effort techniques in API testing precisely because it requires no new exploitation skill — you're taking a vulnerability class you may have already ruled out on the current version (rate limiting, input validation, authorization checks) and re-testing the *identical* attack against an older version of the *identical* endpoint, where the fix may never have been backported.

---

## Step 1: Enumerate Every Version Prefix in Use

### 1.1 — Passive Discovery (from Part 1's traffic mapping)

Review your Part 1 site map and JS/mobile bundle search results specifically for version indicators:

- Path-based: `/v1/`, `/v2/`, `/v3/`, `/api/v1/`, `/api/1.0/`
- Header-based: `Accept: application/vnd.company.v1+json`, `X-API-Version: 1`
- Query-parameter-based: `?version=1`, `?api-version=2023-01-01` (date-based versioning, common in enterprise/payment APIs)
- Subdomain-based: `v1-api.target.com` vs `api.target.com`

Record every distinct versioning scheme you find — some APIs use more than one simultaneously (e.g., path-based for major versions, header-based for minor/date revisions), and each scheme needs separate enumeration.

### 1.2 — Active Enumeration

For every endpoint in your Part 1 matrix (which was built against whatever version the primary client uses — usually the current/latest), systematically try adjacent version numbers:

```
GET /api/v2/users/482/profile HTTP/1.1     ← known-working, current version (your baseline)
```

Now test:
```
GET /api/v1/users/482/profile HTTP/1.1
GET /api/v3/users/482/profile HTTP/1.1
GET /api/v0/users/482/profile HTTP/1.1
GET /api/beta/users/482/profile HTTP/1.1
GET /api/internal/users/482/profile HTTP/1.1
```

**What each of these specifically tests:**
- `v1` — the classic "predecessor version still alive" case described above.
- `v3` / higher-than-known — occasionally reveals an in-development or beta version already deployed but not yet linked from any client, which can mean weaker input validation (still being built) or genuinely new functionality not yet documented anywhere.
- `v0` — surprisingly common as an internal/pre-release naming convention that sometimes persists in production routing tables long after `v1` became the public-facing version.
- `beta` / `internal` / `staging` / `dev` — non-numeric version-like path segments that developers use during development and sometimes forget to remove from production routing, or that remain live on the production host itself rather than being properly isolated to a separate internal network.

### 1.3 — Automating the Enumeration

Use Burp Intruder with the version segment as the payload position, against every endpoint in your matrix:

```
GET /api/§v2§/users/482/profile HTTP/1.1
```

Payload list: `v1, v2, v3, v4, v5, v0, v1.0, v1.1, beta, alpha, internal, staging, dev, legacy, old`

**Why sweep the full endpoint matrix, not just one endpoint:** version availability is frequently inconsistent *within the same API* — some routes were migrated to `/v2/` while others were never touched and only ever existed at `/v1/`, or vice versa. Finding that `/v1/users/` 404s tells you nothing definitive about `/v1/orders/` — each endpoint needs its own version sweep.

---

## Step 2: Confirming a Version Is Genuinely Live (Not Just Routed to a Stub)

Getting a non-404 response to `/v1/users/482/profile` doesn't automatically mean you've found something exploitable — some organizations properly deprecate old versions by keeping the route alive but returning a deliberate `410 Gone` or a redirect to the current version. You must confirm the old version is **functionally live**, not just present in routing.

Checklist to confirm genuine functionality:
- Does it return real data matching what you'd expect (compare against your `/v2/` baseline for the same resource ID)?
- Does it accept write operations (`POST`/`PUT`/`PATCH`/`DELETE` from Part 2's method sweep, now repeated against this version)?
- Does the response schema differ from the current version in a way that suggests separate, independently-maintained code (extra fields, different field names, different nesting) — this is a strong signal you've found genuinely separate, unmaintained logic rather than a thin compatibility shim in front of the same current-version code.

---

## Step 3: Testing for Security Control Regression on Older Versions

Once you've confirmed an old version is live and functionally distinct, **re-run your entire Part 1–2 methodology against it**, specifically watching for controls present on the current version but missing on the old one:

### 3.1 — Authorization Regression

Take a request that correctly returns `403` on `/v2/` for a low-privilege token, and replay the identical request against `/v1/`:

```
GET /api/v1/admin/users HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-privilege-token>
```

**What this tests:** whether authorization middleware was added or hardened specifically as part of the `v2` rewrite, and never backported to `v1`'s codebase because `v1` was considered "legacy, low-priority" by the development team even though it remained externally reachable. This is the single most valuable versioning test — a confirmed authorization bypass, reached simply by changing the version segment, is a high-severity, easy-to-reproduce finding.

### 3.2 — Rate Limiting / Brute Force Protection Regression

Compare rate-limit headers (if present) and actual throttling behavior between versions:

```
POST /api/v2/login   → after 5 failed attempts: 429 Too Many Requests
POST /api/v1/login   → after 20+ failed attempts: still 200/401, no throttling observed
```

**What this tests:** whether rate limiting is implemented in newer middleware/gateway layers that only wrap the current version's routes, leaving the old version's login (or password reset, or OTP-verification) endpoints exposed to brute-force at full speed. This pattern is common where rate limiting was added at an API gateway level pointed only at `/v2/*` after a `v1` incident, rather than at the application layer covering all versions uniformly.

### 3.3 — Input Validation Regression

Repeat a payload that's correctly rejected on the current version (oversized input, unexpected type, injection-pattern string) against the old version:

```
PATCH /api/v2/users/482  {"bio": "<script>...</script>"}   → 400 Bad Request, sanitization enforced
PATCH /api/v1/users/482  {"bio": "<script>...</script>"}   → 200 OK, stored unsanitized
```

**What this tests:** whether input sanitization/validation logic was added as a fix specifically to the current version's handler and never applied to the old version's separate (or semi-separate, if code is shared via an old shared library version) handler.

### 3.4 — Deprecated Field / Functionality Exposure

Older versions sometimes still expose fields or entire endpoints that were deliberately removed from later versions for security reasons (e.g., a `v1` endpoint that returned full SSNs or internal account IDs directly, later restricted in `v2` after a privacy review). Compare response schemas field-by-field between versions for the same logical resource.

---

## Step 4: Response Header Version Disclosure

Even where the version isn't in the URL, response headers sometimes leak the internal API/framework version, which helps prioritize which endpoints are worth deeper versioning investigation:

```
X-API-Version: 1.4.2
X-Powered-By: Express
Server: Kestrel
```

**What this tests:** confirms you're dealing with a specific framework/version whose known CVEs or known default-insecure-configuration issues (out of scope for this file, covered under Vulnerable Components — A06) may apply, and can hint at whether the versioning scheme is date-based, semver-based, or otherwise, guiding your Step 1 enumeration wordlist.

---

## Step 5: Content-Negotiation-Based Versioning (Header/Media-Type Versioning)

Some APIs (notably GitHub's public API historically, and many enterprise REST APIs) version via the `Accept` header rather than the URL path. This requires a distinct enumeration approach since Step 1's URL-based sweep won't surface anything:

```
GET /api/users/482 HTTP/1.1
Accept: application/vnd.target.v1+json
```

vs.

```
GET /api/users/482 HTTP/1.1
Accept: application/vnd.target.v2+json
```

**What this specifically tests:** identical concept to URL-based versioning, but the version selector lives in content negotiation instead of the path — meaning a tester who only fuzzes URL segments (Step 1) and never varies the `Accept` header will completely miss this class of API entirely. Always check the API documentation or a sample request/response pair for a custom `vnd.` media type before assuming versioning is purely path-based.

---

## PortSwigger Web Security Academy Mapping

**Honest gap disclosure:** as of this writing, PortSwigger's Web Security Academy does not have a dedicated lab category for API versioning attacks specifically — this is a genuine coverage gap in the academy's current API-testing topic, which focuses primarily on endpoint discovery and BOLA rather than version-based control regression. There is no lab to map here in good faith.

Recommended practice targets instead, since this technique needs a target with genuinely divergent logic between versions to be practiced meaningfully:
- **crAPI** — includes intentionally versioned endpoints with divergent behavior, suitable for practicing Steps 1–3 directly.
- **VAmPI** — explicitly designed around a vulnerable/non-vulnerable version toggle, which directly models the "old version regression" concept in this file.

If PortSwigger releases dedicated versioning labs in the future, this section should be revisited and updated.

---

## Summary — Versioning Attack Checklist

- [ ] All versioning schemes identified (path, header/media-type, query parameter, subdomain)
- [ ] Version enumeration swept across every endpoint in the Part 1 matrix, not just a sample
- [ ] Each discovered old version confirmed functionally live (not a stub/redirect/410)
- [ ] Authorization re-tested on every old version for every role
- [ ] Rate limiting / brute-force protection re-tested on every old version
- [ ] Input validation re-tested on every old version using previously-rejected payloads
- [ ] Response schemas diffed field-by-field between versions for sensitive over-exposure
- [ ] Response headers checked for version/framework disclosure
- [ ] Content-negotiation-based versioning explicitly checked, not assumed absent

Proceed to **Part 4: Content-Type Manipulation**.
