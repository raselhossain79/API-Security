# API Gateway Cache Poisoning

## Cross-Reference

This file assumes you've read the **Web Cache Poisoning** notes in the web
application series for the general concept of unkeyed inputs, cache keys,
and cache probing methodology. That file covers the mechanism in full for
CDN/reverse-proxy caches in front of monolithic web applications. This file
does **not** repeat that mechanism explanation — it focuses on what changes
when the cache sits inside an API gateway rather than a general-purpose web
cache, and how to adapt the same testing methodology to that context.

## Trust Assumption Being Exploited

Same root cause as web cache poisoning: the gateway's cache stores a
response keyed by a subset of the request (usually just method + path,
sometimes plus a small explicit allowlist of headers/query params), while
the backend may generate different content based on inputs **outside**
that key. The gateway assumes "if the keyed inputs match, the response is
interchangeable for all consumers." That assumption is only valid if the
backend's output genuinely depends *only* on the keyed inputs. If it
doesn't — because the backend also reads a header, cookie, or query
parameter the gateway wasn't told to include in the key — the cache will
happily serve one consumer's personalized or attacker-influenced response
to every other consumer who requests the same cache-key-equivalent route,
until the entry expires or is evicted.

## What's Different at the Gateway Layer vs a General Web Cache

1. **Cache key configuration is usually explicit and product-specific**,
   rather than inferred from default CDN behavior. Kong's `proxy-cache`
   plugin, AWS API Gateway's caching (API Gateway REST APIs support
   built-in response caching per stage, keyed by explicitly configured
   "cache key parameters"), Azure APIM's `cache-lookup`/`cache-store`
   policies, and Apigee's `ResponseCache` policy all require an admin to
   explicitly list which query parameters and/or headers participate in
   the key. This means the unkeyed-input surface is often *larger* than a
   typical CDN, because gateway admins frequently cache-key on path only
   and forget headers entirely, especially for APIs where the team didn't
   think of caching as a security-relevant configuration choice at all —
   it was added purely for performance.
2. **The consumers are API clients, not browsers**, so the "victim" isn't
   necessarily a human loading a poisoned page — it's every other API
   consumer (mobile app users, other backend services, partner
   integrations) hitting the same endpoint, which can mean the blast
   radius per poisoned entry is very large and very fast if the API is
   high-traffic.
3. **JSON/XML response bodies are the payload**, not HTML — so the impact
   categories shift from "stored XSS via reflected header in HTML" toward
   "stored data corruption / cross-consumer data leakage / cross-tenant
   data leakage," which is arguably more severe for API-to-API
   consumption where the calling service trusts the response body's data
   integrity without an HTML-rendering/XSS-filtering step in between.

## Step-by-Step Testing Methodology

### Step 1 — Identify Cacheable Routes

1. Look for cache-indicating response headers on GET requests:
   `X-Cache: HIT`/`MISS` (common convention, but header name varies by
   product — Kong's `proxy-cache` plugin uses `X-Cache-Status`; AWS API
   Gateway doesn't expose a client-visible cache-status header by default,
   so timing-based inference is needed instead), `Age`, `Cache-Control`
   from the gateway (distinct from any `Cache-Control` the backend itself
   set).
2. Send the same request twice in quick succession and compare response
   timing — a cached response is typically returned faster (no backend
   round-trip) — as a fallback for products that don't expose a cache
   status header.
3. Send the same request with a deliberately unique, harmless marker in a
   likely-unkeyed location (see Step 2) and check whether it's reflected
   in the (still fresh, not-yet-cached) response — this confirms the
   backend actually uses that input at all before testing whether the
   cache ignores it.

### Step 2 — Identify Candidate Unkeyed Inputs

Test each of these systematically, the same way as the general web cache
poisoning methodology, but weighted toward what's realistic in an API
context:

1. **Headers used for content negotiation or personalization**:
   `Accept-Language` (localized error messages or content), `Accept`
   (content-type variants), custom tenant/org identification headers
   (`X-Tenant-Id`, `X-Org-Id` — very common in multi-tenant SaaS APIs, and
   extremely high impact if unkeyed, since it can cause **cross-tenant
   data leakage** through the cache).
2. **Authentication-adjacent headers that influence response content but
   which the gateway strips before caching consideration**: if the gateway
   caches a response to an *authenticated* GET request without including
   the identity in the cache key (because "caching authenticated
   responses" wasn't something the admin thought through), the first
   requester's personalized data gets served to every subsequent
   requester of that route regardless of who they are. This is the single
   highest-impact gateway cache poisoning scenario and worth testing
   first: hit an authenticated, user-specific GET endpoint (e.g.,
   `/api/v2/me` or `/api/v2/orders?userId=me`) as two different
   authenticated users in sequence and check whether the second user
   receives the first user's cached data.
3. **`X-Forwarded-Host` / `X-Forwarded-Proto`** if the backend builds
   absolute URLs (pagination links, webhook callback URLs, HATEOAS-style
   `_links` fields common in REST APIs) from these headers — poisoning the
   cached response to contain attacker-controlled absolute URLs served to
   every subsequent consumer, functionally identical to classic web cache
   poisoning via Host header but delivered as JSON link fields instead of
   HTML.
4. **Query parameters not included in the explicit cache-key allowlist.**
   Since gateway cache-key config is an explicit list (not inferred), any
   query parameter the backend reads but the admin forgot to add to that
   list is a candidate. Test by adding parameters the backend is known (or
   suspected, from API documentation or client-side code/SDKs) to read —
   pagination cursors, field-selection/`fields=` filters, format
   selectors (`?format=xml`) — while requesting the same path.
5. **Cookies**, if the API also accepts cookie-based auth for
   browser-based clients (common for BFF — Backend-for-Frontend — API
   gateways serving a SPA) but the cache key is path/query only.

### Step 3 — Poison and Confirm Impact

1. Send a request including the candidate unkeyed input set to a
   deliberately distinctive/attacker-controlled value (e.g.,
   `X-Tenant-Id: attacker-marker-value` or `Accept-Language: xx-XX` with a
   response you can uniquely identify), targeting a cacheable route.
2. Immediately re-send the *canonical* request (without your injected
   value, as a normal client would send it) and check whether the
   distinctive marker now appears in this "clean" request's response —
   confirming the cache served your poisoned entry to a request that never
   asked for it.
3. Determine cache scope and blast radius: is this a global cache shared
   by all consumers of the route, or is it segmented in some other way you
   hadn't accounted for (per-stage, per-region for multi-region gateway
   deployments)? Test from a second network vantage point / API client
   identity if possible to confirm cross-consumer impact rather than just
   cross-request-from-yourself impact.
4. Assess real impact based on what the unkeyed input controls: cross-user
   data leakage (Step 2.2) and cross-tenant data leakage (Step 2.2 variant)
   are typically critical severity; poisoned absolute URLs (Step 2.3) are
   typically high severity (can be chained into phishing/redirect abuse of
   trusted API consumers, or SSRF if another backend service consumes the
   poisoned URL programmatically); localized-content poisoning is
   typically lower severity unless it enables injection into a downstream
   system that doesn't expect attacker-controlled strings in that field.

---

## PortSwigger Lab Mapping (Web Cache Poisoning Labs, Translated to Gateway Context)

Work these in order; each maps directly to a step above. Translate "web
cache"/"CDN" in the lab to "API gateway cache" and "HTML response" to "JSON
response body" as you go — the underlying parser-differential and
unkeyed-input reasoning is identical.

**Apprentice:**
- *"Web cache poisoning with an unkeyed header"* — directly maps to Step
  2.1/2.3 here: find a header that influences backend output but isn't
  part of the cache key. In the gateway context, treat any custom header
  you can add as a candidate the same way this lab treats an arbitrary
  header.
- *"Web cache poisoning with an unkeyed cookie"* — maps to Step 2.5.

**Practitioner:**
- *"Web cache poisoning with multiple headers"* — maps to combining
  multiple unkeyed inputs (e.g., a tenant header plus a format header)
  when a single unkeyed input alone doesn't produce a distinguishable
  poisoned response.
- *"Targeted web cache poisoning using an unknown header"* — maps to the
  discovery methodology in Step 2 when you don't have API documentation or
  client SDK source to hint at which headers the backend reads; requires
  systematic header fuzzing against a cacheable route.
- *"Web cache poisoning via an unkeyed query string"* — maps directly to
  Step 2.4.
- *"Web cache poisoning via a fat GET request"* — relevant if the target
  API accepts a request body on GET (unusual but present in some poorly
  designed APIs) or if body parameters are used interchangeably with query
  parameters by a permissive backend framework.

**Expert:**
- *"Parameter cloaking"* — maps to Step 2.4's "query parameter not in the
  explicit allowlist" scenario when the gateway's cache-key parser and the
  backend's query-string parser disagree about parameter boundaries (e.g.,
  differing behavior on `;` vs `&` as a parameter separator, or duplicate
  parameter handling) — directly analogous to the route-normalization
  differentials in file 03, applied to cache-key generation instead of
  rate-limit-key generation.
- *"Internal cache poisoning"* — maps to multi-layer gateway deployments
  (e.g., a CDN in front of the API gateway, which is in front of the
  backend) where poisoning an inner cache layer (the gateway's) has
  effects that propagate through an outer cache layer (the CDN's) —
  relevant for public APIs fronted by both a CDN and an API gateway, which
  is common for high-traffic public API products.

## Supplementary Practice (Vendor-Based)

Configure Kong's `proxy-cache` plugin (or AWS API Gateway stage-level
caching with an explicitly short cache-key parameter list) in front of a
backend that reads an extra header/query param the cache config doesn't
include, and practice Steps 1–3 against your own instance. This is
valuable because product-specific cache-key syntax (Kong's
`cache_control`/`vary_headers` config vs AWS API Gateway's per-method
`CacheKeyParameters`) directly determines what's realistically forgettable
by an admin, and seeing the config side clarifies what to look for from
the outside.

---

## Real-World Notes

- Multi-tenant SaaS API gateway cache poisoning (tenant header excluded
  from cache key) is one of the most consistently reported gateway-layer
  vulnerability classes in bug bounty programs for B2B SaaS products,
  precisely because tenant-scoping headers are a relatively recent
  architectural addition that predates a lot of teams' caching
  configuration and gets missed when caching is added later by a different
  engineer than the one who added multi-tenancy.
- AWS API Gateway's built-in caching is per-stage and requires the
  `CacheKeyParameters` to be explicitly set per method in the method
  request configuration; teams enabling caching purely for cost/latency
  reasons on a stage with many methods have been observed applying a
  single cache-key configuration copy-pasted across methods that actually
  have different meaningful inputs, causing exactly this class of bug
  across multiple unrelated endpoints at once.
