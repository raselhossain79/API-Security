# 05 — Default Credentials and Unnecessary HTTP Methods

## Part A: Default and Test Credentials on API Management Surfaces

### A.1 Why this category is distinct from "weak passwords" in Broken Authentication

The Broken Authentication series covers credential-guessing and brute-force against an
application's *own* login mechanism. This section covers something narrower and more
API-specific: **management/administration surfaces that ship with a known, documented default
credential**, installed either by the API framework itself (Swagger UI's optional basic-auth
wrapper) or by the surrounding infrastructure (API gateway admin APIs). These are not "weak"
passwords a user chose — they are **vendor-published defaults**, meaning the credential is not
guessed, it's looked up in public documentation.

### A.2 Swagger UI default auth

Some deployments wrap Swagger UI in HTTP Basic authentication as a lightweight "we didn't want to
disable it entirely" compromise. This is frequently done with a hardcoded or example credential
copy-pasted from a tutorial or the framework's own quick-start documentation and never changed.

**Piece-by-piece exploitation:**
1. When a request to a Swagger UI path (see file 02 §2.2) returns `401` with a `WWW-Authenticate:
   Basic` header, this confirms Basic auth is the *only* control in front of the docs — not OAuth,
   not session-based auth, just a static credential pair.
2. Try common defaults seen in framework quick-start guides and tutorials:
   `admin:admin`, `swagger:swagger`, `admin:password`, `docs:docs`, the project name itself as
   both username and password.
3. **Why this works more often than it should:** Basic-auth-wrapped Swagger UI is usually set up
   once, early in a project, by whoever first noticed the docs shouldn't be fully public — this is
   often not the security team, and the credential is rarely rotated afterward because nobody
   treats "docs auth" as a real access control requiring the same lifecycle as a production admin
   account.
4. Once authenticated, you're back to the full exploitation flow in file 02 §2 — this section is
   purely about the *access gate*, not a distinct exploitation technique beyond that gate.

### A.3 API gateway admin consoles

API gateways are themselves applications with their own administrative APIs, and each ships (or
historically shipped) with default credentials that are extensively documented publicly — because
they're meant to be changed on first setup, and are frequently not.

**Kong (self-hosted, older versions / Kong Manager):**
- Kong's Admin API is unauthenticated by default in many self-hosted deployments unless
  explicitly locked down — this isn't a "default credential" so much as "no credential required at
  all" if the operator never enabled `RBAC` or bound the Admin API to `0.0.0.0` instead of
  `127.0.0.1`. **Piece-by-piece:** an internet-reachable Kong Admin API on its default port (`8001`
  for HTTP, `8444` for HTTPS admin) lets anyone `GET /services`, `GET /routes`, `GET /consumers`
  to enumerate the entire proxied API topology, and `POST` to that same API to add malicious
  routes, plugins, or consumers — effectively full compromise of everything the gateway fronts.

**Apigee (Google Cloud):**
- Apigee's management is Google-account-based rather than a fixed default credential pair in
  modern SaaS deployments, so "default credentials" in the classic sense is less applicable here.
  Where this category still applies is **API proxy-level basic auth or API key defaults**
  configured by whoever built the proxy — test any Apigee-fronted API for a hardcoded test API key
  or a `X-Apigee-*` debug header left enabled from the proxy development/trace phase (Apigee's
  trace tooling can leak request/response detail if a trace session is left active or a debug
  session policy is misconfigured to be reachable without proper authorization).

**AWS API Gateway:**
- AWS API Gateway itself is IAM-protected by AWS's own auth model, so there's no "default
  password" to test in the traditional sense. What actually shows up here in practice:
  - **API keys with placeholder/example values** left active from initial setup, sometimes visible
    in leaked client-side code or public repos.
  - **Resource policies or authorizers misconfigured to allow `"Principal": "*"`**, effectively
    making an IAM-gated endpoint publicly callable — functionally equivalent to a default-
    credential bypass even though no password is literally involved.
  - **Usage plans without throttling limits**, which is more of an API4 (resource consumption)
    concern but is commonly discovered during the same recon pass as credential testing, worth
    noting as a related finding rather than ignoring it because it's technically a different OWASP
    category.

### A.4 General testing approach for gateway admin surfaces

1. **Fingerprint the gateway first** — response headers (`Via`, `X-Kong-*`, `Server`), default
   error page styling, or default port behavior often identify the product before you need to
   guess anything.
2. **Check the gateway's own default admin port**, not just the proxied API's port — gateways
   almost universally separate the data-plane port (where API traffic flows) from the
   control-plane/admin port, and the admin port is the one that matters for this section.
3. **Look up the current vendor documentation for that product's default credential or
   default-open-admin behavior** rather than relying on memorized defaults, since these do change
   across major versions — treat this as a live lookup step during an engagement, not a fixed
   payload list.
4. **Once inside an admin console, the impact is almost always "control over the whole fronted
   API surface,"** not just the console itself — enumerate what services/routes/consumers exist,
   since this environment gives you the same endpoint-map advantage as an exposed OpenAPI spec
   (file 02), but with write access on top.

---

## Part B: Unnecessary HTTP Methods Left Enabled

### B.1 Why this is a misconfiguration category and not just an access-control bug

Some HTTP-method exposure overlaps with Broken Access Control (method-based bypass of an
authorization check, e.g., blocked on `GET` but not on `POST` to the same route) — that mechanism
is covered in the Broken Access Control series and is only briefly cross-referenced here. This
section's focus is narrower: methods that are **enabled at the framework/server level by default**
and were never intentionally designed as part of the API's functionality at all — they exist
because a web server or framework ships them on by default, not because a developer wrote a
handler for them.

### B.2 Methods to test on every discovered API endpoint

**`OPTIONS`** — nearly always allowed, and its response (`Allow:` header) is the fastest way to
enumerate every method a given route accepts, without needing to guess:
```
OPTIONS /api/v1/users/42 HTTP/1.1
Host: api.example.com
```
```
Allow: GET, POST, PUT, DELETE, PATCH
```
**Piece-by-piece:** if this route is documented (client-side or in a spec) as only supporting
`GET`, the presence of `PUT`, `DELETE`, `PATCH` in the `Allow` header is a direct signal that
write/delete functionality exists on this route whether or not it's ever called by the real
client — test each listed method individually rather than assuming the `Allow` header is
aspirational or inaccurate.

**`TRACE`** — designed to echo the exact request back in the response body for diagnostic
purposes. If enabled:
```
TRACE /api/v1/account HTTP/1.1
Host: api.example.com
Cookie: session=abc123
X-Custom-Internal-Auth: 9f8e7d6c
```
The response body echoes this entire request verbatim, **including headers a reverse proxy or
gateway silently appended** (internal authentication headers, forwarded-for chains) that the
client never explicitly set — this is how `TRACE` becomes an information-disclosure technique
specifically: it reveals headers injected *between* the client and the backend, which is otherwise
invisible to the client entirely.

**`CONNECT`** — rarely relevant on typical API routes, but worth a quick check on any endpoint that
might be acting as an internal proxy or gateway pass-through; an enabled `CONNECT` handler on an
unexpected route can indicate a debugging/tunneling feature left active.

**`PUT`/`DELETE`/`PATCH` on routes only ever called with `GET`/`POST` by the real client** —
test every discovered route (from file 02's documentation exposure, or from `OPTIONS`
enumeration above) with every method the `Allow` header lists, checking specifically whether:
- Authentication/authorization is enforced identically across all listed methods (if not, this is
  the Broken Access Control overlap — cross-reference that series for exploitation depth), or
- The method is enabled but was simply never meant to be reachable at all — e.g., a resource
  framework (Rails, Django REST Framework, Spring Data REST) auto-generating a full CRUD method set
  for every model by convention, including a `DELETE` handler nobody explicitly asked for or
  reviewed, on a resource the developer only intended to expose read-only.

**Method override headers** — many frameworks support overriding the actual HTTP method via a
header or body parameter for clients that can't send arbitrary methods (`X-HTTP-Method-Override`,
`X-Method-Override`, `_method` form field). **Piece-by-piece:** if a gateway or WAF blocks `DELETE`
requests directly but the backend framework honors `X-HTTP-Method-Override: DELETE` on a `POST`
request, this is a direct bypass of the edge-level method restriction — always test the override
header pattern against any endpoint where a method appears blocked at the network edge but the
underlying framework is known (or suspected) to support overrides.

### B.3 Impact framing

The impact of an unnecessary method depends entirely on what handler is actually wired up behind
it — this ranges from "no real impact, the method is enabled but returns 404/405 for this specific
route" up to "full unauthenticated delete of a resource" if the auto-generated handler has no
independent authorization check. Always confirm actual handler behavior per-route rather than
reporting "method X is listed in `Allow`" as a finding on its own — the `Allow` header is a lead,
not a vulnerability by itself.

## Part C: WAF / API Gateway Relevance for This File

**Default credentials (Part A):** not a payload-inspection problem — same reasoning as file 02.
Logging in with `admin:admin` is a syntactically normal authentication request. The relevant
control is **network exposure**, i.e., whether the gateway's admin plane is reachable from the
internet at all — this is a network/firewall and gateway-binding configuration question, not a WAF
signature question.

**Unnecessary HTTP methods (Part B)** is the one place in this file where WAF/gateway detection
and bypass genuinely apply:
- **Detection.** Gateways and WAFs commonly allow-list HTTP methods at the edge (e.g., only
  `GET`/`POST` permitted to the public gateway listener, everything else rejected before it ever
  reaches the backend). This is a legitimate and common defense specifically against the
  auto-generated-CRUD-handler problem in §B.2.
- **Bypass considerations:**
  - **Method override headers** (§B.2) are the primary bypass vector — if the edge only inspects
    the literal HTTP method verb and the backend honors an override header, the restriction is
    fully bypassed without ever sending a "blocked" method across the wire.
  - **Case manipulation** — some naive method allow-lists do a case-sensitive string match; sending
    `DeLeTe` instead of `DELETE` has, in some misconfigured implementations, slipped past a filter
    matching only the exact uppercase verb, while the underlying HTTP library normalizes and
    processes it correctly regardless of case.
  - **Testing both the gateway listener and any direct backend path** — exactly as in file 04 §4,
    if a direct route to the backend exists, method restrictions enforced only at the gateway layer
    won't apply there at all.

## Part D: PortSwigger Web Security Academy Lab Mapping

**Gap disclosure — read first:** PortSwigger has **no lab modeling API gateway admin console
default credentials** (Kong/Apigee/AWS API Gateway) — this is inherently outside what a web-app-
focused training platform can simulate, since it requires standing up a real gateway product
rather than a vulnerable web app. This is stated directly rather than mapping an unrelated
authentication lab to this section just to have an entry. For hands-on practice specifically on
this pattern, standing up Kong or Apigee locally in a lab VM (not PortSwigger) and testing their
documented default-admin-exposure behavior is the realistic substitute — cross-reference any
Active Directory / infrastructure-hardening notes in this library for the broader "test the
management plane separately from the data plane" mindset, which is the same principle applied to
gateways instead of Windows infrastructure.

For unnecessary HTTP methods, PortSwigger's coverage lives inside the **Access Control** topic
rather than as a standalone "HTTP methods" topic, and is method-based-*bypass* framing rather than
"unnecessary method left enabled" framing:

**Practitioner**
1. *Access control — Bypassing access control checks* variants that use method or header
   manipulation to reach a restricted function overlap conceptually with §B.2's method-testing
   approach, though the lab framing is access-control rather than pure configuration. Full
   exploitation detail for this pattern belongs in the Broken Access Control series in this
   library; this file only covers the *discovery* angle (finding which methods are live at all).

## Part E: Real-World Notes

- Internet-reachable Kong Admin APIs with no authentication configured have been a recurring
  finding across cloud security scanning research and bug bounty reports — the default behavior of
  binding to all interfaces rather than localhost has repeatedly been the root cause, not a guessed
  credential.
- Framework-auto-generated CRUD endpoints (Django REST Framework's `ModelViewSet`, Rails' scaffold
  generators, Spring Data REST's repository exports) are a frequent real-world source of
  unintentionally-live `DELETE`/`PUT` handlers — developers use the convenience of the framework to
  stand up a read endpoint quickly and don't realize the same generator wired up full write access
  by default.
- `TRACE` being enabled has, in real assessments, been the specific technique that revealed an
  internal authentication bypass header (mirroring PortSwigger's own *Authentication bypass via
  information disclosure* lab almost exactly) — this is a useful case study in why a
  "low-severity" informational method like `TRACE` deserves the same testing attention as
  higher-profile methods.

## Part F: Remediation Summary

- Rotate every default credential on any management surface immediately after installation, and
  track this as part of a documented setup checklist rather than relying on individual engineer
  memory.
- Bind gateway admin/control planes to internal-only interfaces or a separate management VPC/
  network segment; never expose the admin port on the same listener as the public data plane.
- Explicitly define the allowed method set per route at the framework/routing layer rather than
  relying on framework defaults or auto-generated scaffolding for anything reaching production.
- Disable `TRACE` and `CONNECT` at the web server/gateway level unless a specific, reviewed reason
  requires them.
- If method override headers are supported for legitimate client compatibility reasons, apply the
  exact same authorization checks to the overridden method as would apply if it were sent directly
  — never let an override header bypass a check that the literal verb would have triggered.
