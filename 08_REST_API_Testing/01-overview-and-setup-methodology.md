# REST API Testing Methodology — Part 1: Overview & Setup Methodology

## Series Position

This is the foundational file in the REST API-Specific Testing Methodology series. Every other file in this series (HTTP method testing, versioning attacks, content-type manipulation, response differential analysis, parameter fuzzing) assumes you have completed the process described here first. This file is not about finding vulnerabilities — it is about building the map and the baseline you need before any vulnerability hunting is meaningful.

This series is procedural, not a vulnerability-class catalogue. For specific vulnerability classes (BOLA, Broken Authentication, Mass Assignment, SSRF, Injection, etc.) refer to the OWASP API Security Top 10 series and the web application vulnerability series. This series answers a different question: **"Given an arbitrary REST API, in what order do I work, and what do I set up before I start attacking it?"**

---

## Why Methodology-First Matters for APIs

Web application testing has a visual surface — you can click through pages and the attack surface reveals itself as you browse. REST APIs have no visual surface. An endpoint that is never called by the documented client (mobile app, SPA, partner integration) is invisible unless you deliberately go looking for it. This is the single biggest practical difference between web app testing and API testing, and it is why undocumented/shadow endpoints are one of the most common real-world API findings (OWASP API9:2023 — Improper Inventory Management).

Because of this, API testing methodology places much heavier emphasis on **reconnaissance and mapping before attack** than web app testing does. Attacking before mapping means you attack only the endpoints you happened to observe in traffic, and you miss everything else — which in practice is often the majority of the actual attack surface.

**Industry framing:** In real bug bounty and pentest engagements against API-first products (fintech apps, SaaS platforms, mobile backends), the reconnaissance phase frequently consumes 40–60% of total engagement time. Rushing to attack with an incomplete endpoint map is the single most common reason junior testers under-report findings that senior testers later catch in the same target.

---

## Step 1: Acquire and Read the API Specification

### 1.1 — Locate the Specification

Before touching Burp or Postman, find out if a machine-readable spec exists. Check, in this order:

1. **OpenAPI/Swagger JSON or YAML** — commonly at:
   - `/swagger.json`
   - `/swagger/v1/swagger.json`
   - `/openapi.json`
   - `/api-docs`
   - `/v2/api-docs` (older Swagger 2.0 convention)
   - `/.well-known/openapi.json`
2. **GraphQL introspection** (if the API is GraphQL, not REST — different methodology, not covered in this REST-specific series)
3. **Postman public collections** — search `postman.com/explore` and public workspace links associated with the target
4. **Developer portal / partner API docs** — many companies publish full REST documentation for third-party integrators (Stripe, Twilio-style docs). These are gold: they document parameters, required fields, and expected response shapes that the client-side app might not exercise at all.
5. **Mobile app decompilation** — if no public spec exists, decompiling the mobile APK/IPA often reveals full endpoint lists, including admin or internal-only routes never called by the public-facing app. (Covered in depth in the mobile API recon reference, out of scope here — flagged as a technique, not detailed.)

**Why this matters:** A published spec is effectively the target handing you their own attack surface map. Skipping this step and relying only on proxy-captured traffic means you test only the paths the application's normal user flow happens to trigger.

### 1.2 — What to Extract From the Spec

Read the spec methodically and extract into a working sheet (spreadsheet or Markdown table) — not just skim it:

| Field to extract | Why it matters for testing |
|---|---|
| Every path + method combination | This becomes your endpoint matrix (Step 2) |
| Required vs optional parameters | Optional parameters are prime targets — they're often unvalidated because "normal" clients never send them |
| Parameter data types | Type confusion is a real attack surface (see Part 6: Parameter Fuzzing) |
| Defined enum values | Values outside the enum are a fuzzing target |
| Auth requirements per endpoint | Endpoints marked "no auth required" are worth double-checking — sometimes this is a documentation error, sometimes it's intentional and reveals what's meant to be public |
| Response schemas (per status code) | Lets you detect information leakage — extra fields returned that aren't in the documented schema are a real, common finding |
| Deprecated/internal flags | Deprecated endpoints frequently still work and frequently have weaker security controls (this feeds directly into Part 3: Versioning Attacks) |

**Real-world note:** OpenAPI specs are often stale relative to the live API — fields get added to the implementation without the spec being updated. This means the spec is your *starting* map, not your *complete* map. Traffic-based mapping (Step 3) is what closes that gap.

---

## Step 2: Build the Endpoint Matrix

Create a structured table — this is the single most important artifact you produce before testing begins. Recommended columns:

```
Endpoint | Method | Auth Required (per spec) | Role Tested | Content-Type(s) | 
Response Code (baseline) | Notes | Tested? (Y/N) | Findings
```

For a target with 40 documented endpoints and, say, 3 distinct user roles, this matrix will have well over 100 rows once you factor in method variations (Part 2). Tracking this in a spreadsheet or Burp's own annotation features is not optional at any meaningful engagement size — without it, testers reliably lose track of what's actually been covered, which produces both wasted duplicate effort and, worse, false confidence that coverage is complete when it isn't.

**Why this discipline matters:** API engagements fail most often not because the tester lacked skill, but because the tester lost track of coverage. A missed endpoint-method combination is a missed finding, full stop.

---

## Step 3: Traffic-Based Mapping (Closing the Gap Left by the Spec)

Even with a complete spec, you must still map by traffic, because:
- Some endpoints are never documented (shadow APIs)
- Some parameters exist in the implementation but not the spec
- Client-side logic sometimes reveals conditional endpoints (e.g., admin panels that only appear in JS bundles for certain roles)

### 3.1 — Proxy Everything

Route all traffic — web app, mobile app (via device proxy config or an intercepting proxy on the mobile network), and any browser extension companion apps — through Burp Suite. Use every feature of the target application as a normal user would, across every available role, to populate Burp's site map / Proxy history with the real traffic set.

### 3.2 — Passive Spec Discovery from JS/Mobile Bundles

Search JavaScript bundles (web) and decompiled app resources (mobile) for:
- Hardcoded API base URLs, especially internal/staging subdomains
- API route strings (regex search for patterns like `/api/v\d+/`, `/graphql`, path-like strings inside JS string literals)
- Feature-flagged or commented-out endpoint references

This is a static-analysis complement to dynamic proxy capture, and it frequently reveals endpoints that no test account has permission to trigger through the UI, meaning proxy capture alone would never surface them.

---

## Step 4: Establish a Baseline of Normal Behavior

This is the step most testers skip or do too quickly, and it is the reason differential analysis (Part 5) fails when they get there. You cannot detect an abnormal response if you never recorded what normal looks like.

### 4.1 — What "Baseline" Means

For every endpoint in your matrix, before you send a single malicious or abnormal payload, send the **documented-correct request** and record:

- Exact status code
- Exact response headers (especially `Content-Type`, caching headers, and any custom headers like `X-RateLimit-*`)
- Full response body shape (field names, types, nesting — not just "it returned JSON")
- Response time (rough baseline — useful later for blind/time-based issues)
- Behavior across each distinct role you have test credentials for (unauthenticated, low-privilege user, high-privilege user, and any tenant/org-boundary role if the API is multi-tenant)

### 4.2 — Why Baseline-First Is Non-Negotiable

Every later phase in this series depends on comparison against this baseline:

- **HTTP method testing (Part 2):** you need to know the baseline response for the *documented* method before you can tell whether an undocumented method's response is meaningfully different (i.e., actually processed) versus just a generic 405/404 template.
- **Content-type manipulation (Part 4):** you need the baseline JSON response to know if switching to XML or `text/plain` changes parsing behavior, error verbosity, or status code.
- **Response differential analysis (Part 5):** the entire technique *is* baseline comparison, formalized across roles/content-types/parameters.
- **Parameter fuzzing (Part 6):** you need to know what a *valid* value returns so an *invalid* value's response can be judged as verbose-error, silent-fail, or unexpectedly-accepted.

**Real-world note:** in real assessments, testers who skip baselining commonly misreport findings — e.g., flagging a 500 error as an authorization bypass when in fact that specific malformed input always produces a 500 regardless of role, because the *baseline itself* already breaks that way. Recording the baseline first prevents this class of false positive, which matters directly for report credibility with clients.

---

## Step 5: Setting Up Burp Suite for API-Specific Testing

Default Burp configuration is tuned for web app testing (HTML/form-heavy). APIs need adjustments.

### 5.1 — Import the OpenAPI Spec

If you have a spec (Step 1), import it directly:
- Burp Suite Professional: **Extensions → BApp Store → "OpenAPI Parser"** (or use the built-in importer in newer versions) to auto-populate the site map with every documented path+method, even ones you haven't manually triggered yet.

**What this achieves:** you get every documented endpoint sitting in Burp's site map ready for manual testing or inclusion in scans, without needing to have organically triggered each one through the UI first.

### 5.2 — Configure Match and Replace for Repeated Header Injection

Under **Proxy → Options → Match and Replace**, set up rules for anything you'll be toggling constantly across the whole engagement, e.g.:
- Swapping the `Authorization` bearer token between role A and role B test accounts (lets you replay a captured low-privilege request with a high-privilege token, or vice versa, without manually editing every request — this is the core mechanic Part 5's differential analysis depends on)
- Injecting a tracking header like `X-Test-Marker: <engagement-id>` if your rules of engagement require identifiable test traffic

### 5.3 — Configure Burp's JSON Handling

- Ensure **Proxy → Options → "Automatically update Content-Length header"** is enabled — critical for API testing because JSON body length must match exactly or many servers will reject the request outright with a generic parsing error, masking whatever behavior you were actually trying to observe.
- In Repeater, use Burp's built-in JSON syntax highlighting/folding (Burp 2023.x+) to navigate large nested bodies without introducing manual formatting errors, which is a common self-inflicted false negative when testers hand-edit deeply nested JSON.

### 5.4 — Burp Suite Extensions Worth Installing for API Work

- **JSON Web Tokens** — decode/edit/re-sign JWTs inline (feeds into the separate JWT attack series)
- **Autorize** — automates the differential-by-role comparison described in Part 5, flagging responses that succeed with a low-privilege token where they shouldn't
- **Param Miner** — useful for discovering hidden/unlinked parameters not present in the spec (feeds into Part 6)

---

## Step 6: Setting Up Postman for API-Specific Testing

Postman is not a substitute for Burp's interception/repeater workflow — it's complementary, and better suited to some specific tasks:

### 6.1 — Import the Spec as a Collection

**File → Import → OpenAPI spec URL or file.** Postman auto-generates a full collection with one request per documented endpoint, correctly pre-filled with documented parameters and example bodies.

**What this gives you that Burp's import doesn't:** Postman collections are better for *systematic, repeatable* method-matrix testing (Part 2) because you can duplicate a request, change only the method, and keep both side by side in an organized folder structure — this is more ergonomic for producing the endpoint-matrix coverage described in Step 2 than working purely inside Burp's Repeater tabs.

### 6.2 — Environments for Role Switching

Set up separate Postman **Environments** (not just variables) for each test role: `unauth`, `low-priv-user`, `high-priv-user`, `tenant-a`, `tenant-b` (if multi-tenant). Store the bearer token / cookie / API key for each role as an environment variable, and reference it in the collection's Authorization tab as `{{auth_token}}`.

**Why environments specifically, not just variables:** switching the entire testing context (role) with a single dropdown selection, and re-running the same request unmodified, is exactly the mechanic differential analysis (Part 5) needs — you're proving the *only* thing that changed between two requests was the identity making them.

### 6.3 — Postman Console for Baseline Recording

Use **View → Show Postman Console** while running through your baseline pass (Step 4). It logs full raw request/response pairs including headers, which you can export and keep as your baseline reference set for the rest of the engagement.

---

## Step 7: Confirm Scope and Rate Limits Before Attacking

Before any of the subsequent files' techniques are applied:

- Confirm the written scope explicitly includes the API host(s) you've mapped — subdomain or shadow-API discovery sometimes surfaces hosts (staging, internal, partner) that are *not* in scope even if they belong to the same organization.
- Identify rate-limiting behavior during the baseline pass (Step 4), not during active fuzzing — hitting an undocumented WAF/rate-limit threshold mid-fuzzing-run produces noisy, hard-to-interpret results and can trigger IP bans that stall the rest of the engagement.

---

## PortSwigger Web Security Academy Mapping

This file is preparatory methodology, so no single lab maps directly to it — but the following labs are the correct **starting point** for the API-specific tracks used throughout this series, and should be done in this order before proceeding to Part 2:

1. **API testing → "Exploiting an API endpoint using documentation"** — direct practice of Steps 1–2 (spec reading, endpoint mapping) against a real target with intentionally-discoverable documentation.
2. **API testing → "Finding and exploiting an unused API endpoint"** — direct practice of Step 3 (traffic-based/shadow endpoint discovery) where the spec alone is insufficient.

Both labs are listed by PortSwigger under the **API testing** topic, and are explicitly the first two labs in that topic's own difficulty ordering — consistent with the honest-gap-disclosure convention used across this series: PortSwigger's API-testing topic currently has a small lab count relative to topics like SQLi or XSS, so this series' methodology depth intentionally extends beyond what PortSwigger's labs alone cover.

---

## Summary — What You Should Have Before Moving to Part 2

- [ ] API specification acquired and fully read (or documented as unavailable, with traffic-mapping as primary source)
- [ ] Endpoint matrix built (every path + method + role combination as a trackable row)
- [ ] All traffic proxied and site map populated from real usage across every available role
- [ ] JS bundles / mobile app resources searched for undocumented routes
- [ ] Baseline response recorded for every endpoint, per role, per documented method
- [ ] Burp configured: spec imported, Match and Replace rules for token swapping, Content-Length auto-update confirmed
- [ ] Postman configured: spec imported as collection, per-role environments built
- [ ] Scope and rate-limit behavior confirmed

Once every item above is checked, proceed to **Part 2: HTTP Method Testing**.
