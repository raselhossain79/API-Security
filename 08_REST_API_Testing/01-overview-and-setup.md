# REST API Testing Methodology — 01: Overview & Pre-Testing Setup

## Purpose of this series

This series is a procedural framework, not a vulnerability-class writeup. It answers the question: *"I've been handed a REST API — where do I start, and in what order do I test it?"* Every other OWASP API Top 10 note you've built (BOLA, BFLA, JWT, OAuth, injection, etc.) assumes you've already found the endpoint and understood its behavior. This series covers the recon and baseline-establishment work that happens **before** any of those vulnerability classes can be tested meaningfully.

The six technical files in this series map onto one continuous workflow:

1. Read the spec, map the surface, set up tooling, establish a baseline (this file)
2. Abuse HTTP methods across every endpoint
3. Attack API versioning
4. Manipulate content types
5. Run differential analysis across roles/inputs
6. Fuzz parameters at the API-specific level (JSON structure, arrays, hidden params)

File 7 compresses all of this into a single-pass checklist you can run against any target without re-reading the theory.

## Why order matters

Testing HTTP methods on an endpoint before you understand what the endpoint *normally* does is close to useless — you won't recognize an anomaly if you don't know the baseline. Similarly, fuzzing parameters before you've mapped the full endpoint list means you're fuzzing 20% of the attack surface and calling it done. The procedural order enforced in this series is:

```
Spec/Recon → Tooling setup → Baseline behavior → Method testing → 
Version testing → Content-type testing → Differential analysis → Parameter fuzzing
```

Skipping steps doesn't just lose coverage — it produces false negatives. An endpoint that looks unauthenticated in your first pass might actually require a `X-Api-Version: v1` header you didn't know existed because you never enumerated versions.

---

## Step 1: Reading the API specification first

### Why the spec comes before anything else

An API specification (OpenAPI/Swagger, RAML, GraphQL SDL, Postman collection, or even just internal wiki docs) is a **map of the intended attack surface handed to you by the developers themselves**. Skipping it and going straight to Burp's browser means you rediscover, by trial and error, information that was sitting in a JSON file. Worse, undocumented endpoints found *without* reference to the spec are easy to miss entirely.

### What to extract from the spec, mechanically

When you open an OpenAPI/Swagger document (`openapi.json`, `swagger.json`, `/v2/api-docs`, `/api-docs`), extract these fields systematically — don't just skim:

| Spec field | What it tells you | Why it matters for testing |
|---|---|---|
| `paths` | Every documented endpoint and path parameter | Your base endpoint inventory |
| `paths.<endpoint>.<method>` | Which HTTP methods the developer *intended* to support | Baseline to compare against actual server behavior (File 02) |
| `security` / `securitySchemes` | Auth mechanism (API key, OAuth2, Bearer JWT, Basic) | Determines what "unauthenticated" testing even means |
| `parameters` (per operation) | Documented required/optional parameters, types, `enum` values | Your starting fuzz list before you look for hidden ones (File 06) |
| `requestBody.content` | Which content-types the endpoint claims to accept (`application/json`, `application/xml`) | Baseline for content-type switching (File 04) |
| `responses` | Documented status codes and response schemas | Lets you spot when a response schema leaks extra fields (mass assignment discovery) |
| `servers` | Base URLs, sometimes including staging/versioned hosts | Seed list for version enumeration (File 03) |

### Finding the spec when it isn't handed to you

If no spec was provided, actively look for it before assuming there isn't one:

- Common documentation paths: `/api`, `/api/docs`, `/api/swagger`, `/swagger/index.html`, `/swagger-ui.html`, `/openapi.json`, `/v2/api-docs`, `/api-docs`, `/redoc`
- Investigate the **base path** of any endpoint you do find. If you see `/api/v1/users/123`, walk back and check `/api/v1/users`, `/api/v1`, and `/api` — documentation is frequently hosted at a parent path of a resource you already know about.
- Search JavaScript bundles served to the frontend for hardcoded API paths (`fetch(`, `axios.`, `.get(`, `.post(` followed by string literals). Burp's **JS Link Finder** BApp automates this extraction at scale; do it manually first on a small target so you understand what the tool is actually finding.
- Google/search-engine dorking for exposed Swagger instances (`site:target.com inurl:swagger`) is standard recon for external engagements, but only within your authorized scope.

**Real-world note:** In production environments, Swagger/OpenAPI docs are frequently left publicly accessible on staging or internal-facing hosts that get inadvertently exposed — this is common enough that PortSwigger built a dedicated Apprentice-level lab around exactly this scenario (see Lab Mapping below). Treat an exposed spec as a finding in itself (information disclosure) even before you use it to find further bugs.

---

## Step 2: Mapping all endpoints and HTTP methods

Once you have whatever spec exists, build a working inventory — a spreadsheet, a Burp project's Site Map filtered to `/api`, or a plain markdown table. For every endpoint, record:

- Full path, including path parameters (`/api/users/{id}`)
- HTTP methods *documented* as supported
- Auth requirement as documented
- Whether you've *observed* it being called by the front-end, vs. only *read about it* in the spec (undiscovered documented endpoints are high-value — they're often less tested by developers because no UI path exercises them)

### Passive discovery (do this before touching Intruder)

- Crawl with Burp Scanner, then manually walk through every application feature with Burp's browser so the proxy captures real traffic.
- Review every JavaScript file loaded by the app, not just the ones triggered during your click-through. Client-side routing and conditionally-loaded bundles often reference endpoints never called during a shallow crawl.
- Note field names in JSON responses that hint at unshown functionality — a `user` object containing an `isAdmin` field you never saw exposed in any UI is a signal worth flagging for later (mass assignment testing, File 06).

### Active discovery

- Use Burp Intruder against path segments once you've identified a naming pattern. If you know `PUT /api/user/update` exists, sniper-fuzz the `/update` segment with a wordlist of common REST verbs-as-nouns (`delete`, `create`, `add`, `remove`, `edit`, `list`, `export`) — many APIs use verb-like path segments instead of relying purely on HTTP method semantics.
- Use API-aware wordlists (not generic web wordlists) for content discovery — SecLists' `api/` and `api-endpoints.txt` combined with terms specific to the target's domain vocabulary pulled from your passive recon.

---

## Step 3: Setting up Burp and Postman correctly for API testing

### Burp Suite configuration

- **Scope**: set target scope explicitly to the API's base path(s), including any versioned or subdomain-based API hosts (`api.target.com`, `target.com/api/v1`, `target.com/api/v2`) — version testing later depends on all of these being in scope from the start, not added ad hoc.
- **Match and Replace**: pre-configure rules if you already know the auth header format (e.g., automatically attach a valid `Authorization: Bearer <token>` to all in-scope requests) so you're not manually re-adding it to every Repeater tab.
- **Session handling rules**: for APIs using short-lived tokens, configure a session handling rule with a macro that re-authenticates automatically, otherwise every testing session degrades into chasing 401s instead of testing logic.
- **Extensions to install before you begin** (matches your existing tooling from other series):
  - **JWT Editor** — for any Bearer-token API (near-universal in REST APIs)
  - **Param Miner** — hidden parameter and header discovery, directly feeds File 06
  - **Content Type Converter** — for the content-type manipulation work in File 04 (auto-converts JSON ⇄ XML request bodies)
  - **OpenAPI Parser** — if a machine-readable spec exists, this lets Burp Scanner crawl and audit it directly rather than you manually transcribing every operation
- **Repeater organization**: group requests into tabs per endpoint-family, not per single request. You'll be sending the same endpoint with varied methods, content-types, and roles — keeping them adjacent makes differential comparison (File 05) far faster than hunting through history.

### Postman configuration

Postman is not a replacement for Burp here — it's for **structured, repeatable, spec-driven request construction**, particularly when a machine-readable spec exists.

- Import the OpenAPI/Swagger spec directly into Postman to auto-generate a collection of every documented operation with correct parameter placeholders. This gives you a clean, complete baseline collection before you've manually touched anything.
- Set up **environment variables** for base URL, auth token, and any per-version host so you can pivot between `v1`/`v2`/`v3` hosts by switching one variable rather than editing every request (this directly supports File 03).
- Configure Postman's proxy setting to route all traffic through Burp (`127.0.0.1:8080`), so every Postman-generated request is also visible and replayable in Burp Repeater. Testing exclusively inside Postman means you lose Burp's Intruder/Repeater/extension tooling on requests you built there.
- Use Postman primarily for the "does this documented operation still work as documented" pass, then hand off anything interesting to Burp for the abuse-testing steps in Files 02–06.

---

## Step 4: Establishing a normal behavior baseline before testing begins

This is the step most testers skip, and it's the reason differential analysis (File 05) becomes guesswork instead of a rigorous comparison. Before running a single attack, document:

- **For each endpoint**: exact response for a fully valid, in-scope request — status code, response headers (especially caching headers, `Server`, rate-limit headers), and full response body structure.
- **For each role available to you** (unauthenticated, low-privilege user, high-privilege user/admin if you have credentials for both): the same request/response baseline. You cannot detect a broken authorization difference later if you never recorded what "correct" looks like for each role.
- **Rate limiting behavior**: send a small burst of legitimate requests and note whether/when you get throttled (`429`, `Retry-After` header). If you don't establish this baseline early, later testing that trips rate limits will look identical to testing that trips a WAF — you won't be able to tell the two apart.
- **Error message baseline**: trigger a few naturally-occurring errors (missing required parameter, invalid ID) and record the exact error format. Verbose error responses are often your best signal later when content-type switching or method abuse produces a change in error verbosity — but only if you know what the "normal" error looks like first.

**Real-world note:** in professional engagements, this baseline documentation is what separates a defensible finding from a false positive. If you report "PATCH exposes a hidden field" without a recorded baseline showing the field is genuinely new (not something visible elsewhere you missed), a client's engineering team can — and will — push back on the finding.

---

## WAF / API Gateway relevance for this file

This file covers **recon and setup**, not attack delivery, so WAF/API gateway bypass techniques are not directly applicable here. However, two things from this stage directly affect later WAF-relevant work:

- **API gateways frequently enforce different rules per version** (see File 03) — your baseline pass should specifically test whether the same request against `/v1/` and `/v3/` of an endpoint receives different gateway-level treatment (different rate limits, different WAF rule sets, different auth enforcement). Recording this now saves re-testing later.
- **Establishing your baseline through the gateway** (not by hitting an internal/staging host directly, if both are reachable) ensures your baseline reflects real-world defended behavior, rather than an undefended internal path that would give you a false sense of what's actually reachable by an attacker.

Method-specific, content-type-specific, and parameter-specific WAF/gateway detection and bypass considerations are covered in their dedicated sections in Files 02, 04, and 06 respectively, where they are directly actionable.

---

## PortSwigger lab mapping

The PortSwigger Web Security Academy **API testing** topic is the primary lab environment for this entire series, and its "API recon and documentation" material maps directly onto this file's content.

| Lab | Difficulty | Maps to |
|---|---|---|
| Exploiting an API endpoint using documentation | Apprentice | Steps 1–2 above (finding and using exposed API documentation to discover an undocumented method) |

**Honest gap disclosure:** PortSwigger does not have a dedicated lab purely for "Burp/Postman setup" or "baseline establishment" — these are testing hygiene practices, not exploitable vulnerability classes, so no lab targets them directly. The Apprentice documentation-discovery lab is the closest practical exercise, since solving it requires you to do real endpoint mapping and base-path investigation exactly as described in Step 2.

### crAPI supplementary practice

crAPI (Completely Ridiculous API, OWASP's intentionally vulnerable API project) is a better fit than PortSwigger for the *setup and mapping* work specifically, because it is a full multi-service application rather than a single-vulnerability lab:

- **Community/Workshop endpoints**: use these to practice full endpoint mapping against a realistic multi-microservice REST + GraphQL surface — a more representative "what does a real target's attack surface look like" exercise than any single PortSwigger lab.
- **Mechanic/Service endpoints**: good for practicing the "find the spec, then find what's not in the spec" workflow, since crAPI ships with an OpenAPI spec that deliberately doesn't cover 100% of the deployed surface.

---

## What's next

File 02 picks up immediately after this baseline is established: systematically testing every HTTP method against every mapped endpoint, regardless of what the spec claims is supported.
