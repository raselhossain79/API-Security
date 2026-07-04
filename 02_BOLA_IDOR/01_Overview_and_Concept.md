# BOLA — Overview and Concept

**OWASP API Security Top 10 2023 — API1:2023 Broken Object Level Authorization**

---

## 1. What BOLA Actually Is

Broken Object Level Authorization (BOLA) occurs when an API endpoint receives an object identifier from the client (a user ID, order ID, invoice ID, vehicle ID, document ID — anything that points at a specific record) and the server uses that identifier to fetch or modify data **without independently verifying that the requesting, authenticated user is actually entitled to that specific object**.

The critical detail is the word "independently." Authentication tells the server *who is asking*. Object level authorization is a separate check that must ask *"does this specific user own or have rights to this specific object?"* — every single time an object-scoped operation runs. BOLA is what happens when that second check is missing, incomplete, or only applied to some code paths.

This is why BOLA sits at #1 in the OWASP API Security Top 10 (2019 and again in 2023): it is structurally the easiest high-impact API vulnerability to introduce, because REST and GraphQL APIs are built almost entirely around resource identifiers in URLs, bodies, and query strings. Every endpoint that takes an ID is a candidate.

---

## 2. BOLA vs IDOR — Same Root Cause, Different Context

This is the distinction most people get fuzzy on, so it's worth being precise.

### They are the same underlying flaw

Both BOLA and IDOR describe **exactly the same logic defect**: a user-controllable reference to an object is used to retrieve or manipulate that object without a server-side ownership/permission check. There is no technical difference in the root cause. If you strip away the surrounding architecture, "IDOR" and "BOLA" point at the identical broken pattern.

### Where the terms diverge

| Aspect | IDOR | BOLA |
|---|---|---|
| Origin | Popularized by the OWASP 2007 Top Ten, in the context of traditional web applications | Coined explicitly for the OWASP API Security Top 10 (first published 2019, retained in 2023) |
| Typical surface | Server-rendered pages, query string parameters, hidden form fields, cookies referencing DB rows or files | JSON/XML request bodies, REST path parameters, GraphQL node IDs, API query parameters |
| Discovery method | Browsing the app as a normal user, noticing an ID in a URL, manually walking the UI | Reading an OpenAPI/Swagger spec, intercepting raw API calls, testing endpoints that may have **no UI representation at all** |
| Object model | Usually one flat object type (e.g., account ID) exposed per page | Often nested/relational — an org has users, users have vehicles, vehicles have service reports — meaning ownership must be validated across multiple joined entities |
| Attack surface size | Bounded by what's rendered in the UI | Bounded by the entire API surface, including internal/undocumented ("shadow") endpoints never exposed in any UI |
| Testing methodology | Crawl visible pages, alter parameters, observe rendered content | Enumerate the API contract itself (spec, traffic capture, JS bundle analysis), test every HTTP method per resource, test nested resource paths, test nested objects returned in JSON that never appear on screen |

### Why the terminology split happened

Web apps present a curated UI — you generally can't reach an endpoint the UI doesn't link to (aside from forced browsing). APIs, by design, expose direct, structured, machine-readable access to backend resources, frequently including endpoints that exist only for mobile clients, internal microservice-to-microservice calls, admin tooling, or partner integrations that were never intended for direct end-user use but are technically reachable. This dramatically expands both the number of ID-referencing endpoints and the difficulty of achieving full coverage during testing — hence a distinct term to describe the API-specific manifestation and the different professional workflow it requires (spec review, method-by-method testing, tenant boundary testing) rather than URL/form-parameter tampering.

**Practical implication for your testing workflow:** treat "IDOR" as the general vulnerability class in access control theory, and "BOLA" as the same class applied specifically to API endpoints — meaning your BOLA testing checklist must include things a classic IDOR checklist often omits: HTTP method coverage per resource, request-body object references (not just URL/path parameters), and multi-tenant boundary checks, all covered in file `02_Testing_Methodology.md`.

---

## 3. Horizontal vs Cross-Tenant BOLA (Preview)

Two distinct scenarios get grouped under "BOLA" that deserve separate mental models (fully covered with testing steps in file 2):

- **Horizontal privilege escalation** — User A, within the *same* application/tenant, accesses User B's object. Both users belong to the same organization/account boundary; the flaw is purely at the individual-object level.
- **Cross-tenant BOLA** — In multi-tenant SaaS, User A (belonging to Tenant/Org X) accesses an object belonging to Tenant/Org Y entirely. This is a more severe failure because it breaks the outermost isolation boundary the platform is supposed to guarantee, not just an inner one between peers.

Treating these as one undifferentiated "BOLA" bug during testing causes people to stop after proving horizontal escalation within their own test tenant and never actually prove the cross-tenant boundary is broken — which is usually the higher-severity finding a client or bug bounty program cares about.

---

## 4. WAF / API Gateway Relevance to BOLA — Why This Section Exists and What It Actually Covers

Your other note series include dedicated WAF bypass sections for injection-class vulnerabilities (SSTI, XXE, LDAP injection). BOLA is fundamentally different, and it's worth stating precisely why, rather than silently skipping the topic.

### Why signature-based WAF detection is structurally irrelevant to BOLA

A WAF (ModSecurity, AWS WAF, Cloudflare WAF, etc.) and most API gateway security layers work by pattern-matching the **content** of a request — looking for characters, syntax, or payload structures associated with known attack classes: `' OR 1=1`, `<script>`, `../../../etc/passwd`, template injection syntax, and so on. This works because injection payloads are *syntactically abnormal* compared to legitimate input.

A BOLA request has **no abnormal syntax whatsoever**. Consider:

```
GET /api/v2/invoices/8842 HTTP/1.1
Authorization: Bearer <valid-token-for-user-A>
```

versus the exploit:

```
GET /api/v2/invoices/8841 HTTP/1.1
Authorization: Bearer <valid-token-for-user-A>
```

The only difference is a single digit in a URL path — and that digit is a completely legitimate value that the *same endpoint* returns valid data for when it happens to belong to the requester. There is no payload to fingerprint. The authentication token is genuinely valid. The HTTP method is correct. The content-type is correct. Every byte of the request is well-formed and indistinguishable, at the network layer, from an authorized request. A WAF cannot know that `8841` belongs to a different customer than the one holding the bearer token — that mapping only exists in the application's database and business logic, which the WAF has no visibility into.

**This is the core reason BOLA is described in OWASP materials as a business logic / authorization design flaw rather than an injection-class vulnerability** — and it's exactly why it can't be patched or meaningfully mitigated at the perimeter. The fix has to live in the application's authorization layer, not the network security layer.

### Where gateway/API-security tooling *does* play a real role

It would be inaccurate to say infrastructure is entirely irrelevant, so here is what legitimately applies:

**1. Behavioral / anomaly-based detection (not signature-based).** Modern API security platforms (e.g., dedicated API security gateways that do runtime behavioral baselining) can flag BOLA *attempts* — not by content, but by pattern of access:
- A single token requesting a rapidly incrementing sequence of object IDs in a short window (classic enumeration signature).
- A single token/IP accessing object IDs that statistically fall outside the range that user has ever legitimately touched.
- A sudden spike in 403/401 responses interspersed with 200s for the same endpoint from one identity, suggesting active probing.

This is *detection of the attack in progress*, not prevention of the underlying flaw, and it's the closest thing to a "WAF-equivalent" control for BOLA.

**2. Gateway-enforced authorization policy.** Some API gateways can enforce coarse-grained authorization rules centrally (e.g., "this route requires scope X," or ABAC/RBAC policy evaluated at the gateway before the request even reaches the backend). When properly configured with resource-level (not just route-level) policy, this is a legitimate *fix*, not a perimeter control layered on top of a vulnerable app — worth noting during a pentest as a compensating control if present, but its absence or misconfiguration is usually itself part of the root cause finding.

**3. Rate limiting as a partial dampener.** Aggressive rate limiting slows down brute-force enumeration of sequential/short-hash IDs (see file 3), but does nothing against disclosure-based discovery of UUIDs/GUIDs pulled from other legitimate responses, and does nothing at all once an attacker already has the specific target ID.

### Realistic "bypass" considerations, honestly framed

Because there is no signature to bypass, "bypass" in the BOLA context really means **evading behavioral/rate-based detection**, not defeating a WAF ruleset:

- **Pacing:** spreading enumeration requests over a longer time window, below whatever threshold the anomaly system uses, rather than firing them in a tight Burp Intruder burst.
- **Non-sequential ordering:** if targeting a known range of sequential IDs, requesting them in randomized order rather than ascending/descending, to avoid tripping "monotonic sequence" heuristics.
- **Distributing across sessions:** using multiple legitimately-obtained low-privilege tokens rather than hammering one token, if the anomaly detection is scoped per-identity rather than per-IP.
- **Single high-value confirmation instead of mass scraping:** once methodology (file 2) confirms the check is missing on one object, a single targeted request against a specific object of interest is usually far quieter — and sufficient for proof of concept — than a scraping run across the entire ID space.

None of this is about crafting a payload that slips past a rule — it's operational tradecraft around not triggering volume/pattern-based alerting while confirming the same authorization defect a WAF was never able to see in the first place.

---

## 5. Real-World Notes

- BOLA/IDOR-class flaws are consistently among the highest-payout categories on HackerOne and Bugcrowd because the impact (full account takeover, mass PII exposure, cross-tenant data breach) is easy to demonstrate concretely and severity is rarely disputed once ownership-bypass is proven.
- The 2021 Peloton API breach and numerous fintech/telecom API breaches disclosed publicly have all traced back to this exact pattern: an endpoint trusting a client-supplied ID without a server-side ownership check.
- In real engagements, BOLA is frequently found not on the "main" documented API but on internal/partner/mobile-only endpoints discovered via traffic interception, JS bundle analysis, or an exposed OpenAPI/Swagger file — reinforcing why spec review is a first-class step in file 2, not an afterthought.
- Multi-tenant SaaS products (the majority of B2B software today) are the highest-stakes environment for this bug class, because a single missed `tenant_id` check can expose an entire customer's data to every other customer on the platform simultaneously — this is why cross-tenant testing is treated as its own methodology track in file 2, not folded into generic horizontal testing.

---

**Next file:** `02_Testing_Methodology.md` — manual, step-by-step testing procedure covering horizontal escalation, cross-tenant boundaries, and non-obvious object reference locations.
