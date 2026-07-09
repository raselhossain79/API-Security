# Gateway-Level Rate Limit Bypass

## Trust Assumption Being Exploited

The gateway's rate limiter tracks requests against a **route key** — a
representation of "which endpoint is this" derived from the path (and
sometimes method). The gateway assumes that its route key accurately
represents "the same backend resource" every time it matches. The backend
assumes rate limiting is handled entirely upstream and typically implements
none of its own. When the gateway's idea of "same route" and the backend's
idea of "same route" diverge — because they use different path
normalization rules — an attacker can send requests that the gateway counts
under one bucket (or fails to match to any rate-limited route at all) while
the backend serves them as the real, rate-limit-worthy endpoint. This
gap exists because gateway route matching and backend URL routing are
implemented by two independent codebases with independent, often
undocumented normalization behavior, and nobody explicitly tested that they
agree.

---

## Step 1 — Establish the Baseline

Before testing bypasses, confirm rate limiting exists and measure it
precisely:

1. Send repeated identical requests to the target route and record the
   response headers on each. Most gateways surface rate-limit state via
   headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
   `X-RateLimit-Reset` (Kong's `rate-limiting` plugin), or
   `x-amzn-RateLimit-Limit`/throttling behavior (AWS API Gateway usage
   plans), or `Retry-After` on a `429`.
2. Determine whether the limit is applied per-IP, per-API-key, or
   per-authenticated-user by varying one of those at a time while holding
   the others constant.
3. Note the exact threshold and window (fixed window resets at a clock
   boundary; sliding window doesn't) — ask for `X-RateLimit-Reset` and
   observe whether the remaining count resets predictably or continuously.

## Step 2 — Test Route Normalization Differences

For each variation below, send the request both through the gateway
(observing whether it's rate-limited the same as the canonical route) and,
if backend direct access is available (file 02), confirm whether the
backend treats it identically to the canonical route. A bypass exists when
the gateway treats the variant as a *different* route (not counted against
the same limit, or not matched to any rate-limited route definition at
all) while the backend treats it as the *same* resource.

1. **Trailing slash differences.**
   ```
   GET /api/v2/orders          (rate-limited route, baseline)
   GET /api/v2/orders/         (test: does the gateway match this to the same rule?)
   ```
   Many gateway route-matching engines (including Kong's default path
   matching depending on configured strip/regex behavior) treat a trailing
   slash as part of an exact-match string, while most backend web
   frameworks treat `/orders` and `/orders/` as equivalent by default.

2. **Case sensitivity differences.**
   ```
   GET /api/v2/Orders
   GET /API/v2/orders
   ```
   Path matching is case-sensitive in most gateway configurations
   (matching the literal configured route string) but the backend web
   server or framework may run case-insensitively depending on OS
   (Windows-hosted backends) or framework configuration, or may simply
   route case-insensitively due to a catch-all handler.

3. **URL-encoding differences.**
   ```
   GET /api/v2/orders
   GET /api/v2/%6frders        (o -> %6f)
   GET /api/v2/orders%2F       (encoded trailing slash)
   GET /%61pi/v2/orders        (a -> %61)
   ```
   If the gateway matches routes against the raw, undecoded path string
   (common for performance reasons — avoiding a decode step before route
   lookup) but decodes the path before forwarding, or if the backend
   decodes and the gateway doesn't, an encoded character can cause the
   gateway's matcher to miss the route entirely (no rate limit applied at
   all) while the backend decodes and serves the real resource normally.

4. **Path parameter / matrix parameter injection.**
   ```
   GET /api/v2/orders;jsessionid=x
   GET /api/v2/orders%00
   ```
   Some backend frameworks (historically Java-based ones) strip matrix
   parameters (`;param=value`) before routing, treating
   `/orders;foo=bar` identically to `/orders`, while the gateway's literal
   string matcher does not, causing a rate-limit miss at the gateway with
   an identical hit at the backend.

5. **Double-slash and dot-segment normalization.**
   ```
   GET /api//v2/orders
   GET /api/v2/./orders
   GET /api/v2/x/../orders
   ```
   Compare whether the gateway normalizes these before or after matching
   against its route table, versus how the backend's router or underlying
   HTTP server normalizes them. A common gap: the gateway normalizes
   *after* route-matching decisions are logged/limited but *before*
   forwarding (or vice versa), meaning the limiter and the forwarder are
   effectively looking at two different strings.

6. **Query string and fragment noise.**
   ```
   GET /api/v2/orders?
   GET /api/v2/orders?a=1&a=1
   GET /api/v2/orders#x
   ```
   Confirm the rate-limit key doesn't naively include the full raw query
   string in a way that makes every request with a unique/random query
   parameter appear as a "new" route to a poorly configured key-generation
   function (this is the inverse failure mode — over-differentiation
   rather than under-differentiation — but produces the same practical
   bypass: append a random cache-busting-style query parameter on each
   request to always land in a fresh bucket).

7. **Host header / virtual host variations**, if the gateway routes by
   virtual host and rate-limits per-host: test alternate `Host` header
   casing or an IP-literal `Host` value alongside the real path, per the
   Host Header Injection notes' techniques adapted to route-matching
   rather than absolute-URL-generation contexts.

## Step 3 — Confirm and Weaponize

1. Once a normalization mismatch is found, script sending the real
   attack traffic (credential stuffing, resource enumeration, expensive
   query flooding — tie back to the API4 Unrestricted Resource
   Consumption notes for what "expensive" means for the specific backend)
   using the bypassing path variant on every request, rotating through
   several equivalent variants if the gateway eventually starts
   rate-limiting the variant itself once it sees enough traffic on it
   (some WAF/gateway combos adapt).
2. Verify actual backend-side effect (not just "the gateway returned 200
   instead of 429") — confirm the backend performed the real operation
   each time, since the goal is bypassing enforcement, not just getting a
   different status code from the gateway.

---

## PortSwigger Lab Relevance

PortSwigger's Web Security Academy does not have a dedicated "gateway rate
limiting" topic area. Apply reasoning from adjacent topic areas:

- **Business Logic Vulnerabilities > Practitioner**: labs covering
  insufficient workflow validation and inconsistent handling of state
  across parts of an application map conceptually to "two components of
  the same system disagree about state" — the same root pattern as
  gateway/backend rate-limit-key disagreement, though framed differently.
- Path-normalization skills used here (double-slash, dot-segment, encoding
  differentials) are the same skills exercised in **Web Cache Poisoning**
  and **HTTP Request Smuggling** labs (see the notes for both in the web
  application series) — those labs are the best hands-on practice for the
  underlying technique of finding a parser differential between two
  components, even though neither is framed as "rate limiting."

## Supplementary Practice (Vendor-Based)

Build a local Kong (or Nginx `limit_req`) instance in front of a simple
backend, deliberately configure the rate-limit plugin on an exact-string
route (e.g., `/orders`, not a regex/wildcard), and test each normalization
variant above against your own setup to observe exactly which variants the
gateway's matcher misses. This is the most reliable way to build intuition
for a specific product's matcher behavior, since it varies significantly
between Kong, Nginx, AWS API Gateway (which uses a different matching
engine for REST APIs vs HTTP APIs), and Apigee.

---

## Real-World Notes

- Multiple public bug bounty writeups describe bypassing login
  rate-limiting by appending a trailing slash or toggling path casing on
  the login endpoint specifically because the gateway's WAF/rate-limit
  rule was configured against the exact literal path used in the frontend
  application's code, and never accounted for equivalent path forms.
- AWS API Gateway REST APIs (the older API type) use a different, stricter
  route-matching implementation than HTTP APIs (the newer, cheaper type);
  teams that migrated from REST to HTTP APIs for cost reasons have
  reported behavioral differences in how greedy path variables and
  trailing slashes are matched, occasionally reintroducing bypasses that
  didn't exist under the original REST API configuration.
- Rate-limit-key generation that includes the full query string verbatim
  (rather than just the path) is a common implementation shortcut in
  hand-rolled Nginx `limit_req_zone` configurations using
  `$request_uri` as the key, which is vulnerable to the query-string-noise
  bypass in Step 2.6 above.
