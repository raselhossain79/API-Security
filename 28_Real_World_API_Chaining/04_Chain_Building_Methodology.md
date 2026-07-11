# API Security — Real-World Exploitation and Vulnerability Chaining
## Part 4: Chain Building Methodology

Part 2 showed ten fully-worked chains as finished products. This section
covers the thinking process that produces a chain in the first place, on a
target where nobody has told you the chain exists in advance.

### Step 1: Map the Full API Attack Surface Before Attempting to Chain

Chaining is a pattern-matching exercise across a surface, not a single-point
exploitation exercise — it is structurally impossible to find most chains
without first having a reasonably complete map, because chain links are
frequently on endpoints that look unrelated to each other until viewed
together.

**Sources to build the map from, in priority order:**

1. **Official API documentation** (Swagger/OpenAPI, GraphQL schema, Postman
   public workspace if published) — the fastest, most complete source when
   available, but must never be treated as exhaustive; undocumented and
   deprecated endpoints (Chain 6) will never appear here by definition.
2. **Client application traffic capture** — proxy every action available in
   the web app, mobile app, and any partner/admin portal through Burp or a
   similar intercepting proxy while manually exercising every feature,
   including edge-case flows (password reset, account deletion, org
   invite/transfer, billing) that testers commonly skip because they are
   tedious to click through manually.
3. **Client-side code review** — JS bundles (search for `fetch(`,
   `axios.`, `.get(`, `.post(` patterns and string-literal API paths),
   decompiled mobile APKs/IPAs (search for base URL constants and endpoint
   path strings), and any exposed source maps, which frequently reveal
   endpoints never triggered during manual traffic capture.
4. **Passive/historical recon** — Wayback Machine snapshots of API
   documentation pages, GitHub code search against the target's known
   organization for accidentally public repos referencing internal API
   paths, and JS bundle diffing across app versions to spot endpoints added
   or removed over time (removed-from-current-bundle paths are exactly the
   deprecated-version candidates from Chain 6).
5. **Active enumeration** — content discovery wordlists tuned for API
   patterns (common version prefixes `/v1/` `/v2/` `/internal/` `/admin/`,
   common resource-name wordlists) run against the base path, plus HTTP
   method enumeration (`OPTIONS` requests, or simply trying
   `PUT`/`PATCH`/`DELETE` against every discovered `GET` endpoint, since
   authorization checks are frequently method-specific per Part 3's
   resource-family-inheritance warning).

**Record every discovered endpoint in a structured surface map** — at
minimum: path, method, required auth (yes/no/unknown until tested), role
requirement (if documented), request parameters, and response shape. This
becomes the working document that both the cross-role loop (Part 3) and the
chain-spotting process below operate against; without it, chain-spotting
degrades into trying to remember dozens of separate findings from memory,
which does not scale past a handful of endpoints.

### Step 2: Track Low-Severity Individual Findings and Why They Matter for Chaining

The single biggest mistake in chain discovery is discarding or
under-documenting findings that look unexploitable in isolation. Every
finding — no matter how minor it looks standalone — should be logged with
three explicit fields beyond the standard description:

- **What does this finding expose or grant?** (a value, an access level, a
  capability)
- **Is that value/capability normally something an untrusted party would
  supply?** If the finding lets the attacker control something that another
  part of the system implicitly trusts came from a legitimate source, flag
  it as a chain candidate immediately.
- **Which other endpoints, from the Step 1 surface map, consume a value or
  capability of that type?** Cross-reference against the map rather than
  relying on memory.

Concrete example of why this matters: an endpoint that echoes back a
user-controlled `redirect_after_action` parameter without validation might
be dismissed as "cosmetic, no security impact" if tested in isolation with
no obvious open-redirect consequence visible. But logged with the three
questions above — *this hands me control over a URL the server will later
use* / *yes, that's normally meant to be a trusted, pre-registered value* /
*the OAuth authorization endpoint consumes a URL in exactly this way* — it
becomes the first link of Chain 3 in Part 2 the moment the OAuth flow is
mapped as a separate surface item.

**Practical logging discipline:** maintain a running "candidate primitives"
list separate from the main findings list — one line per primitive
discovered (a leaked ID pattern, a forgeable token type, an SSRF-capable
parameter, a role field discovered to be mass-assignable) — and revisit it
every time a new endpoint is added to the surface map, not just at the end
of testing. Chains are far easier to spot while the surface map is still
being actively built, because new endpoints are fresh in mind and can be
immediately checked against existing primitives.

### Step 3: Finding Where One Vulnerability's Output Becomes Another's Input

This is the mechanical core of chain-building, formalized from the mental
model introduced in Part 1. Work through the candidate primitives list
built in Step 2 systematically:

For each primitive, categorize it into one of these types, since each type
has a characteristic set of "consumer" endpoints to check against:

| Primitive type | Example | Typical consumers to check |
|---|---|---|
| Leaked/forgeable identity value | user ID, forged JWT claim, leaked API key | Any endpoint taking that ID/claim/key as an authorization input |
| Attacker-controlled URL | webhook callback, redirect_uri, image-fetch-by-URL feature | SSRF-reachable internal services, OAuth flows, anything issuing server-side outbound requests |
| Attacker-controlled structured data | mass-assignable field, unsanitized template input | Endpoints deserializing that data model elsewhere, template/rendering engines |
| Excess disclosed schema/structure | GraphQL introspection, verbose error messages, stack traces | Any endpoint whose name/parameters were only discoverable via that disclosure |
| Bypassable rate/volume control | spoofable rate-limit key, batching-exploitable endpoint | Any endpoint whose security assumption depends on limited attempt volume (brute force targets, especially auth and OTP) |

Walk the surface map against this table methodically rather than relying on
intuition alone — intuition catches the chains that resemble ones you have
seen before (which is exactly why Part 2's ten patterns are worth
memorizing as templates), but a deliberate table walk catches
target-specific chains that don't resemble a known pattern.

### Step 4: API-Specific Chain Opportunities Not Present in Web Apps

Beyond the general output-to-input search, actively check for these three
API-specific structural opportunities, since they have no real web-app
equivalent and are therefore easy to overlook if testing methodology is
adapted from web app habits rather than built API-first:

**Versioning mismatches.** Any time multiple API versions coexist, treat
each version as carrying an independent risk of having missed a fix applied
to a sibling version. Explicitly re-run key authorization tests (from the
Part 3 cross-role loop) against every discovered version of a shared
resource, not just the current one — this is precisely Chain 6 in Part 2,
and it is a repeatable methodology step, not a one-off finding.

**Shadow endpoints.** Endpoints that exist in the deployed application but
were never intended for the audience that can reach them — most commonly,
endpoints built for an internal admin tool or a partner integration that
share the same API gateway/base domain as the public API, distinguished
only by path prefix or a header value rather than by network-level
isolation. Discover these via the JS bundle and mobile app decompilation
steps in Step 1 (internal tooling occasionally shares a frontend codebase
or API client library with the public app, leaking path references), and
via GraphQL introspection (Chain 4) where a single shared schema exposes
mutations meant only for internal callers.

**Service-to-service trust.** In microservice architectures, an internal
service calling another internal service (e.g., the order service calling
the inventory service) often skips the authentication/authorization rigor
applied to externally-facing traffic, on the assumption that "if a request
reaches this internal service, it must have come from another trusted
internal service, because the network is private." Any SSRF primitive
(Chain 5) or any bug allowing the attacker to make the public-facing API
issue an internal request on their behalf becomes disproportionately
powerful in this architecture, because it inherits whatever trust level the
internal network itself assumes for all internal traffic — this is worth
explicitly testing for by attempting to reach internal-only service ports
or internal DNS names (`http://inventory-service.internal/`,
`http://localhost:8080/admin`) via any confirmed SSRF primitive, not just
the cloud metadata endpoint shown in Chain 5.

### Real-World Notes

- On real engagements, the surface-mapping step (Step 1) frequently
  consumes 30-40% of total testing time on a mature API and this is time
  well spent — chains discovered this way tend to be higher-severity and
  more defensible in a report than chains found by opportunistic testing,
  because the report can show the full discovery trail rather than an
  isolated "I got lucky" finding.
- Client engineering teams are generally far more receptive to remediation
  guidance for a chain when the report can point to the specific surface
  map entries and candidate-primitives log entries that led to the
  discovery — it demonstrates the finding is reproducible via a
  documented process, not a one-off fluke that resists validation.
- Revisit the candidate-primitives list at the end of every testing day,
  not only at the end of the engagement — new endpoints discovered on day
  three may unlock a chain from a primitive logged on day one that seemed
  like a dead end at the time.

---
Next: `05_Postman_Chain_Documentation.md`
