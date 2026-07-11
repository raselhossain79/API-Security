# API Security — Real-World Exploitation and Vulnerability Chaining
## Part 3: Multi-Role API Testing Methodology

Cross-role testing is the single most productive technique in API security
testing. Nearly every chain in Part 2 either starts or ends with a
cross-role authorization gap. This section covers how to set up and
systematically execute cross-role testing in both Burp Suite and Postman.

### Why Multi-Role Testing Is the Core Discovery Loop

BOLA and BFLA cannot be found by testing a single account in isolation —
both are defined by comparison: does the response for Role A differ from
what it should be relative to Role B's actual authorization level? This
means the minimum viable test setup for any serious API assessment is a
minimum of three concurrently maintained sessions:

- **Role A:** a standard/low-privilege user
- **Role B:** a second standard/low-privilege user (a different account,
  same privilege tier as A — needed specifically to test BOLA between
  peers, not just between tiers)
- **Role C:** an elevated-privilege user (admin, or whatever the highest
  documented tier is)

Some targets warrant a fourth: an **unauthenticated** "session" (no token
at all) to test whether authentication is enforced consistently across
every endpoint, which directly supports Chain 6 in Part 2 (deprecated
version with missing authentication).

### Setting Up Multiple Role Sessions in Burp Suite

**Session token management via Burp's built-in session handling rules:**

1. Log in as each role once through the browser (with Burp's proxy active)
   to capture each role's initial authentication flow in the Proxy history.
2. In **Project options → Sessions**, create a session handling rule per
   role. Each rule uses a macro (a recorded sequence of requests — here, the
   login flow) to fetch a fresh valid token/cookie whenever a request in
   that rule's scope receives an authentication failure, so long-running
   test sessions don't die mid-test when a token expires.
3. Define the macro under **Sessions → Macros → Add**, selecting the
   captured login request(s) from Proxy history. For token-based APIs, the
   macro must also extract the token from the login response body (Burp
   supports this via the "Custom parameter" extraction option pointing at a
   JSON key such as `access_token`) and inject it into subsequent requests'
   `Authorization` header automatically.
4. Scope each session handling rule to a **distinct set of tools/tabs** —
   the cleanest approach is running each role through a separate Burp
   **project tab** (if using Burp Professional's multi-tab support) or
   using **Repeater tab groups**, one group per role, each with its own
   session handling rule applied via URL scope matching combined with a
   custom header or cookie jar distinguishing which role's macro should
   fire.
5. For simple cases with only 2-3 roles, a lighter-weight alternative to
   session handling rules is maintaining each role's token as a **Repeater
   environment variable** (Burp 2023.x+) and manually selecting the right
   variable set per tab group — faster to set up, at the cost of not
   auto-refreshing expired tokens.

**The practical cross-role workflow in Burp:**

1. Send every candidate endpoint (built from the attack surface map — see
   Part 4) to Repeater three times, once per role tab group.
2. Use **Repeater's "Send group in sequence"** feature (where available) to
   fire all three role variants back-to-back and get responses side by side.
3. Diff the three responses. Burp's built-in response comparison
   (right-click → "Compare responses," or the standalone Comparer tool) is
   the fastest way to spot a subtle authorization difference in an
   otherwise near-identical JSON body — critical for catching partial
   authorization bugs where most fields are correctly restricted but one
   sensitive field (e.g. `ssn`, `internal_notes`) leaks through regardless
   of role.

### Setting Up Multi-Role Environments in Postman

Postman environments are the natural home for role management because
Postman explicitly supports switching the active environment per request
without editing the request itself.

1. Create one **Postman Environment** per role: `Role A - Standard User`,
   `Role B - Standard User (Peer)`, `Role C - Admin`, `Role D -
   Unauthenticated`.
2. In each environment, define the same variable names with role-specific
   values: `base_url`, `access_token`, `refresh_token`, `user_id`. Keeping
   variable *names* identical across environments (only values differ) is
   what allows a single collection of requests to be reused unmodified
   across all roles — every request references `{{access_token}}` and
   `{{user_id}}` generically, and only the active environment determines
   which role actually fires.
3. Populate `access_token` per environment either manually (paste a
   captured token) or automatically via a **login request with a test
   script** that writes the response token into the current environment:

```javascript
// Test script on the "Login" request, run once per role
// by switching the active environment before sending
const response = pm.response.json();
pm.environment.set("access_token", response.access_token);
pm.environment.set("user_id", response.user.id);
```

4. Build the endpoint collection once, referencing only environment
   variables. To test an endpoint across all roles, switch the active
   environment (top-right environment selector) and re-run — the same
   request definition, three different outcomes.
5. For efficient bulk cross-role testing, use the **Collection Runner**
   with each environment selected in turn, exporting each run's results,
   then diff the three result sets. This scales far better than manual
   per-request switching once the endpoint list exceeds roughly 20-30
   requests.

### The Systematic Cross-Role Test Loop

This is the actual discovery procedure — the setup above only enables it.

1. **Enumerate the full endpoint list** first (see Part 4 for surface
   mapping) before starting cross-role passes — testing role-by-role against
   an incomplete endpoint list means re-doing the entire loop later when
   more endpoints surface.
2. For every endpoint in the list, in order:
   - Call it as **Role A**. Record status code, response body shape, and
     any object IDs referenced.
   - Call it as **Role B**, using an object ID that belongs to Role A where
     the endpoint takes an ID parameter (`GET /orders/{roleA_order_id}`
     called with Role B's token) — this is the core BOLA test.
   - Call it as **Role C** (admin). Record whether functionality Role A/B
     cannot reach is exposed, and separately, whether admin-tier data
     fields appear that lower roles' identical endpoint calls omit (useful
     for catching inconsistent field-level authorization).
   - Call it **unauthenticated** (no token). Record whether it still
     returns data — this is the BFLA/missing-authentication test.
3. **Diff systematically, not impressionistically.** For each endpoint, ask
   explicitly:
   - Did Role B receive Role A's data? → BOLA candidate.
   - Did Role A/B successfully invoke a function the documented permission
     model says should be Role C-only? → BFLA candidate.
   - Did the unauthenticated call succeed? → missing authentication
     candidate.
   - Did status codes differ from response bodies in a way that leaks
     information even on "denied" paths (e.g., a 403 for a nonexistent
     object ID vs a 404 for a real one owned by someone else — a
     information-disclosure-via-error-differentiation issue that also
     assists BOLA enumeration by confirming which IDs exist)?
4. Log every discrepancy immediately with the exact request/response pair,
   even ones that seem minor — Part 3's chain-building methodology (next
   file) depends on having a complete inventory of small findings to
   combine later, not just the ones that look independently severe.

### Identifying and Testing Role-Specific Endpoints Efficiently

Not every endpoint needs the full four-role pass — prioritize based on
recon signals:

- **Client-side code review** (JS bundles for SPAs, decompiled mobile app
  API clients) frequently reveals role-conditional UI logic
  (`if (user.role === 'admin') { fetchAdminStats() }`) that names
  admin-only endpoints directly, even if those endpoints are never called
  by a standard-role user's normal usage — test these first, as they are
  disproportionately likely to have thin or missing server-side
  enforcement (the team may have relied on hiding the button rather than
  gating the endpoint).
- **API documentation** (Swagger/OpenAPI specs, GraphQL schemas via
  introspection — see Chain 4 in Part 2) often lists an endpoint's intended
  role requirement directly in a description field or tag
  (`tags: ["admin"]`) — treat every documented admin/internal tag as a
  mandatory cross-role test target.
- **Naming pattern heuristics**: endpoints containing `/admin/`,
  `/internal/`, `/manage/`, `/staff/`, `/support/`, or plural-resource
  endpoints without an ID (`GET /users` returning *all* users rather than
  the single-object `GET /users/{id}`) are high-yield BFLA candidates and
  should be prioritized over routine CRUD endpoints already confirmed to
  enforce authorization correctly elsewhere in the same resource family.
- **Resource family inheritance assumption is a trap**: do not assume that
  because `GET /orders/{id}` correctly enforces ownership,
  `DELETE /orders/{id}` or `PATCH /orders/{id}/status` on the same resource
  does too — authorization checks are frequently implemented per-handler,
  not per-resource, meaning each HTTP method on the same path is a
  distinct test target, not a single test target.

### Real-World Notes

- On real targets, expect Role C (admin) accounts to be harder to obtain
  than in a lab — client-provided test credentials may only include
  standard-tier accounts. Where an admin account genuinely cannot be
  provisioned for testing, this must be explicitly noted as a testing
  limitation in the report rather than silently skipping BFLA testing
  against the admin tier.
- Session handling rules in Burp are worth the setup time on any engagement
  running more than a day — the time lost to manually re-logging-in three
  role sessions every time a token expires compounds quickly across a full
  endpoint list.
- When client organizations have more than three role tiers (common in
  B2B SaaS with organization-scoped roles — e.g., org-owner, org-admin,
  org-member, and a separate customer-support role), the same loop applies
  per meaningful role *pair* most likely to reveal a boundary violation
  (adjacent tiers first: org-member vs org-admin, then org-admin vs
  org-owner) rather than attempting an exhaustive all-pairs matrix against
  every tier combination, which rarely justifies its time cost.

---
Next: `04_Chain_Building_Methodology.md`
