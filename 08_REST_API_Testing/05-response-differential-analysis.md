# REST API Testing Methodology — Part 5: Response Differential Analysis

## Series Position

This file assumes Parts 1–4 are complete. This is the file that formalizes a technique used implicitly throughout the entire series: **systematic, controlled comparison of responses across a single changed variable, to surface differences that indicate authorization flaws or information leakage.** Parts 2–4 each applied this idea along one axis (method, version, content-type). This file generalizes the technique and covers the axes not yet fully addressed: role, parameter value, and object ownership.

---

## Why Differential Analysis Is the Core API Testing Technique

A huge share of real-world API vulnerabilities are not "the server does something wrong in isolation" — they're "the server does something *inconsistently* across two conditions that should produce identical or predictably-different results." You cannot detect an inconsistency by looking at a single response. You detect it by holding every variable constant except one, and comparing.

This is precisely why Part 1's baselining step is non-negotiable: differential analysis is only as good as the baseline you're comparing against. Every comparison in this file is of the form:

```
Request A (control) → Response A
Request B (single variable changed) → Response B
Diff(A, B) → interpret the meaning of any difference
```

**Real-world framing:** this is the exact technique underlying tools like Burp's Autorize extension and is the single most repeatable way to find Broken Object Level Authorization (BOLA, OWASP API1:2023) and Broken Function Level Authorization (BFLA, OWASP API5:2023) — currently the two most-reported API vulnerability classes across bug bounty platforms, precisely because they are structural (an authorization *check* that exists for one condition and not another) rather than payload-based, and structural bugs are found by comparison, not by throwing attack strings.

---

## Step 1: Differential Axis 1 — Role (Horizontal and Vertical Privilege)

### 1.1 — Vertical: Low-Privilege vs. High-Privilege Role, Same Object

```
Request A (control — high-privilege role accessing an admin function):
GET /api/v2/admin/users/482/full-profile HTTP/1.1
Authorization: Bearer <admin-token>
→ 200 OK, full profile including internal notes field

Request B (variable changed — identical path, low-privilege token):
GET /api/v2/admin/users/482/full-profile HTTP/1.1
Authorization: Bearer <low-priv-token>
→ ???
```

**What this specifically tests:** whether the `/admin/` path segment is enforced by actual authorization middleware or is merely a *naming convention* the developers relied on without backing it with a real role check — a surprisingly common gap, since the path looking restricted can create false confidence during development that it *is* restricted. Only the token changed; everything else (path, method, headers) is byte-for-byte identical, which is what makes any difference in outcome attributable specifically to the role.

### 1.2 — Horizontal: Same Privilege Level, Different Owned Object (the core BOLA test)

This is the single highest-value differential test in API security testing.

```
Request A (control — user 482 accessing their own resource):
GET /api/v2/orders/1001 HTTP/1.1
Authorization: Bearer <user-482-token>
→ 200 OK, order 1001 belongs to user 482

Request B (variable changed — same token, different object ID):
GET /api/v2/orders/1002 HTTP/1.1
Authorization: Bearer <user-482-token>
→ ???  (order 1002 belongs to user 483, not 482)
```

**What this specifically tests:** whether the server checks *ownership* of the requested object against the *authenticated identity*, or only checks that *a* valid token was presented. Only the object ID in the path changed. A `200 OK` returning order 1002's real data is a confirmed BOLA — the server correctly authenticated the request but never authorized it against the specific resource. This exact pattern, run systematically across every object-ID-parameterized endpoint in your Part 1 matrix, is the single most productive use of time in an API engagement, and should be run on **every** endpoint that takes an object identifier, not spot-checked on a few.

### 1.3 — Constructing the Test Matrix for Every Role Pair

For an API with N roles, you need every meaningful pair, not just "lowest vs. highest":

```
unauth        → any protected endpoint
low-priv A    → low-priv B's owned objects   (horizontal, same tier)
low-priv      → admin-only endpoints          (vertical)
tenant A      → tenant B's data (if multi-tenant — often the highest-severity class, since it crosses a customer boundary, not just a role boundary)
```

**Why tenant-boundary testing deserves special emphasis:** in multi-tenant SaaS APIs, a BOLA that crosses tenant boundaries (Tenant A's authenticated user reading Tenant B's data) is typically treated as more severe than a same-tenant role-based BOLA, because it violates the fundamental data-isolation promise the product is built on. Always confirm you have test accounts under at least two separate tenants before considering role differential testing complete for a multi-tenant target.

---

## Step 2: Differential Axis 2 — Parameter Value (Same Endpoint, Same Role, Varied Input)

This axis targets information leakage and business-logic differences triggered purely by input value, independent of authorization.

### 2.1 — Boundary and Sentinel Value Comparison

```
Request A: GET /api/v2/search?query=validterm     → 200, N results
Request B: GET /api/v2/search?query=               → ??? (empty — does it return everything, or error?)
Request C: GET /api/v2/search?query=*              → ??? (wildcard — does the backend treat this literally or as a search-engine wildcard operator?)
Request D: GET /api/v2/search?query=%00             → ??? (null byte — does backend/downstream string handling break?)
```

**What each specifically tests:** empty and wildcard values probe whether the endpoint has an implicit "return everything if no real filter is applied" fallback — a common accidental behavior where a missing filter condition in an ORM query (e.g., a `WHERE` clause that isn't applied when the input is falsy) results in an unfiltered full-table-equivalent response, potentially exposing every user's data through what looks like a normal search endpoint. Null byte and other sentinel values probe for string-handling inconsistencies between the API layer and whatever it passes the value to downstream (database driver, filesystem call, shell-out, if any).

### 2.2 — Response Field Presence Across Valid vs. Invalid Requests

```
Request A: GET /api/v2/users/482    (existing user)      → 200, full object
Request B: GET /api/v2/users/999999 (non-existent user)  → ???
Request C: GET /api/v2/users/abc    (wrong type entirely) → ???
```

**What this specifically tests:** whether error responses for "doesn't exist" vs. "exists but you can't see it" vs. "malformed input" are distinguishable — and if so, whether that distinguishability itself is a leak. A `404` for non-existent IDs and a `403` for existing-but-forbidden IDs lets an attacker enumerate which object IDs are valid without ever being authorized to view them (a user-enumeration / existence-oracle issue), which is a real, commonly-reported finding distinct from BOLA itself — BOLA is being able to *read the data*; an existence oracle is being able to infer *that the data exists* even when direct access is properly blocked. Both matter, and differential testing across A/B/C is what surfaces the distinction.

### 2.3 — Case and Type Coercion Differentials

```
Request A: GET /api/v2/users?role=admin       → filters correctly
Request B: GET /api/v2/users?role=ADMIN       → ???
Request C: GET /api/v2/users?role[]=admin     → ??? (array syntax where a string was expected)
Request D: GET /api/v2/users?role=admin&role=user  → ??? (duplicate parameter — which does the backend honor?)
```

**What this specifically tests:** each of these probes a different type-coercion or parameter-parsing ambiguity. Duplicate parameters (Request D) are a genuinely high-value test — many frameworks/proxies/WAFs disagree on which duplicate value "wins" (first occurrence, last occurrence, or an array), and a WAF that filters based on the first value while the application logic acts on the last (or vice versa) creates a filter-bypass gap purely from this inconsistency, independent of any payload sophistication.

---

## Step 3: Differential Axis 3 — Response Size / Timing (Blind Differential Signals)

When response *bodies* look identical but you suspect a behavioral difference exists (e.g., testing for a blind BOLA where the API deliberately returns a generic `404` for both "doesn't exist" and "exists but forbidden" to prevent the Step 2.2 oracle), fall back to secondary signals:

```
Request A: GET /api/v2/orders/1001  (own order)          → response time: 42ms
Request B: GET /api/v2/orders/1002  (other user's order)  → response time: 118ms
```

**What this specifically tests:** if the backend still performs a full database lookup and ownership comparison *before* returning the generic denial (i.e., it fetches the record, checks ownership, then discards and returns a generic 404), that extra work frequently produces a measurable timing difference compared to a genuinely non-existent ID that short-circuits at the database layer with no matching row at all. This is a lower-confidence signal than a direct body/status difference and needs multiple samples (5–10 requests per condition, discarding outliers) before drawing a conclusion — a single timing sample is not reliable evidence on its own.

---

## Step 4: Building a Repeatable Differential Workflow

### 4.1 — Burp Autorize (Role Axis Automation)

Configure Autorize with your low-privilege token. Browse/replay the application's full request set (from your Part 1 site map) using your high-privilege session normally in the browser; Autorize automatically re-issues each request with the low-privilege token and flags any that return an unexpectedly similar response to the original — directly automating Step 1's role-pair comparisons across your entire mapped endpoint set rather than requiring manual pair-by-pair Repeater work.

### 4.2 — Manual Repeater Group Comparisons for Object-ID Axis

For Step 1.2's ownership testing, group related requests in Repeater tabs and use **"Compare"** (right-click → Send to Comparer, or the dedicated Comparer tool) to get a structured word-level or byte-level diff between two full responses — this makes subtle field-level differences (a single extra field present in one response but not the other) far easier to catch than eyeballing two raw JSON blobs side by side.

### 4.3 — Recording Results for Report Writing

For every differential test that produces an unexpected match (i.e., a security-relevant finding), record the **exact request pair** (both full requests, not just a description), the **diffed response pair**, and a one-sentence statement of which variable changed and why that specific change should have produced a different, safer outcome. This exact-pair format is what makes a differential-analysis finding immediately reproducible by whoever reads the report — critical for API findings specifically, since (unlike a self-evidently dangerous payload like an XSS PoC) a BOLA finding's severity is only clear once the reader sees the *paired* comparison, not either response in isolation.

---

## PortSwigger Web Security Academy Mapping

Correct difficulty-progression order for the concepts this file formalizes:

1. **Access control → "Unprotected admin functionality"** and **"User role can be modified in user profile"** — foundational vertical-privilege differential concept.
2. **Access control → "Insecure direct object references"** — the classic, foundational version of Step 1.2's horizontal/BOLA technique.
3. **API testing → "Exploiting a mass assignment vulnerability"** — combines the differential mindset with the content-type/parameter axis from Parts 2 and 4.

**Honest gap disclosure:** PortSwigger's labs demonstrate each of these concepts individually and in isolation. They do not require or model the *systematic full-matrix* differential sweep (every role × every object × every endpoint) described in Step 1.3, nor the timing-based blind differential technique in Step 3 — both of these are drawn from real engagement practice rather than a specific lab, and are best practiced at scale against **crAPI**, which has enough interrelated objects and roles (multiple users, multiple vehicles/orders per user) to make full-matrix practice meaningful in a way a single-lab, single-object PortSwigger environment cannot fully replicate.

---

## Summary — Response Differential Analysis Checklist

- [ ] Vertical role differential run on every endpoint that appears restricted by naming or documentation
- [ ] Horizontal (BOLA) differential run on **every** object-ID-parameterized endpoint, not sampled
- [ ] Tenant-boundary differential run separately from role differential, if the target is multi-tenant
- [ ] Parameter value differential run for empty/wildcard/null-byte/type-mismatch/duplicate-parameter cases
- [ ] Error-response distinguishability checked for existence-oracle leakage (404 vs 403 vs 400 patterns)
- [ ] Timing differential attempted (multi-sample) where body/status differentials are inconclusive
- [ ] Every positive finding recorded as a full request/response **pair**, not a single request

Proceed to **Part 6: Parameter Fuzzing Methodology**.
