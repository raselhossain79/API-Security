# API Gateway Security — Cheatsheet & Lab Mapping

Quick-reference for use during an active engagement. Assumes familiarity
with the full reasoning in files 01–06; this file intentionally omits
mechanism explanations.

---

## Quick Checklist by Category

### 1. Backend Direct-Access
- [ ] DNS/CT log enumeration for backend subdomains (`crt.sh`)
- [ ] `subfinder`/`amass` + `httpx` against apex domain
- [ ] Compare gateway-specific response headers (Kong `Via`, AWS
      `x-amz-apigw-id`) present vs absent across routes
- [ ] Shodan/Censys for org ASN / known cloud account fingerprints
- [ ] Direct request to candidate backend IP/host with **no** credential
- [ ] Cloud: check target security group / NetworkPolicy / VPC Link scope

### 2. Path Routing Confusion
- [ ] `//`, `/./`, `/../` variants on sensitive paths
- [ ] Trailing slash on blocked/internal paths
- [ ] Case variants on blocked/internal paths
- [ ] Unstripped-prefix path sent directly to backend
- [ ] Method probing (`OPTIONS`, unexpected verbs) direct to backend

### 3. Rate Limit Bypass
- [ ] Baseline: identify limit, window, key (IP/key/user) via
      `X-RateLimit-*` headers
- [ ] Trailing slash variant
- [ ] Case variant
- [ ] URL-encoded character substitution (`%6f` etc.)
- [ ] Matrix parameter injection (`;x=y`)
- [ ] Double-slash / dot-segment variants
- [ ] Random/unique query string per request (over-differentiation check)
- [ ] Host header casing/IP-literal variant (if host-based rate limiting)

### 4. Gateway Cache Poisoning
- [ ] Identify cache indicator (`X-Cache`, `X-Cache-Status`, `Age`,
      timing differential)
- [ ] Confirm backend reflects candidate input before testing cache
- [ ] Test unkeyed header: `Accept-Language`, `X-Tenant-Id`, `X-Org-Id`
- [ ] Test authenticated-response caching across two different users
- [ ] Test `X-Forwarded-Host`/`X-Forwarded-Proto` reflected in absolute
      URLs / HATEOAS links
- [ ] Test query params not in explicit cache-key allowlist
- [ ] Test cookie-based unkeyed input (BFF gateways)
- [ ] Confirm poisoned response served to a clean follow-up request

### 5. Default Creds / Exposed Admin
- [ ] Kong: scan `8001`/`8444`, unauthenticated root path check
- [ ] Kong: enumerate `/services`, `/routes`, `/consumers`, `/plugins`
- [ ] AWS: test default `execute-api` endpoint directly, bypassing custom
      domain protections
- [ ] AWS: check "disable default endpoint" setting (if access allows)
- [ ] AWS: review resource policy `Principal`/`Condition` for staleness
      or overly broad `*`
- [ ] Apigee: search GitHub/CI configs for leaked management tokens/
      service account keys
- [ ] Apigee: check management UI/API reachability for hybrid/private
      cloud deployments

### 6. Header Trust Exploitation
- [ ] Identify candidate headers from docs/SDKs/client code
- [ ] Send candidate header with **no** credential — should fail entirely
- [ ] Send candidate header with **valid low-priv** credential —
      check for privilege escalation
- [ ] Test duplicate header (client + gateway both set) — check which
      value backend honors
- [ ] Test case-variant header names against strip logic
- [ ] If internal JWT/assertion pattern used: check signature
      verification, key exposure, unsanitized claim sourcing

---

## Common Header Reference

| Header | Product/Context | Meaning |
|---|---|---|
| `Via: kong/x.x.x` | Kong | Confirms Kong data plane; version fingerprint |
| `X-Consumer-Id` / `X-Consumer-Username` | Kong | Auto-injected identity after `key-auth`/`jwt`/`oauth2` plugin |
| `X-Cache-Status` | Kong `proxy-cache` plugin | Cache hit/miss/bypass state |
| `x-amz-apigw-id`, `X-Amzn-Trace-Id` | AWS API Gateway | Confirms AWS API Gateway data plane |
| `X-RateLimit-Limit/Remaining/Reset` | Common convention (Kong, others) | Rate-limit state |
| `x-amzn-RateLimit-Limit` | AWS API Gateway | Throttling/usage plan state |
| `X-Auth-Request-User` | Nginx `auth_request` pattern | Identity forwarded from auth subrequest |
| `X-Gateway-Authenticated` | Generic/custom | Common naming convention for a "pre-authenticated" signal |
| `X-Forwarded-Host` / `X-Forwarded-Proto` | Generic | Used by backend to build absolute URLs — cache-poisoning-relevant |

---

## Full PortSwigger Lab Mapping (Apprentice → Practitioner → Expert)

Organized by sub-topic, in the order to work through them.

### Web Cache Poisoning (→ File 04, Gateway Cache Poisoning)
1. **Apprentice** — Web cache poisoning with an unkeyed header
2. **Apprentice** — Web cache poisoning with an unkeyed cookie
3. **Practitioner** — Web cache poisoning with multiple headers
4. **Practitioner** — Targeted web cache poisoning using an unknown header
5. **Practitioner** — Web cache poisoning via an unkeyed query string
6. **Practitioner** — Web cache poisoning via a fat GET request
7. **Expert** — Parameter cloaking
8. **Expert** — Internal cache poisoning

### Broken Access Control (→ Files 02, 05, 06)
1. **Apprentice** — Unprotected admin functionality
2. **Apprentice** — Unprotected admin functionality with unpredictable URL
3. **Practitioner** — URL-based access control can be circumvented
4. **Practitioner** — User role controlled by request parameter
5. **Practitioner** — User role can be modified in user profile

### HTTP Request Smuggling (→ File 06, header trust / duplicate handling)
Work through the full existing progression in the HTTP Request Smuggling
notes file — Apprentice through Expert — as general-purpose training for
parser-differential reasoning. Not re-listed here to avoid duplicating
that file's mapping; cross-reference it directly.

### JWT Attacks (→ File 06, internal assertion tokens)
Work through the full existing progression in the JWT attacks notes file —
apply the same lab sequence to any internal gateway-to-backend assertion
token discovered during testing, not just the external user-facing token.

### Business Logic Vulnerabilities (→ File 03, conceptual only)
Practitioner-level labs on inconsistent state handling — useful
conceptual practice for gateway/backend disagreement reasoning generally;
no direct one-to-one technical mapping.

---

## Gaps Not Covered by PortSwigger (Use Vendor-Based Local Labs)

PortSwigger Web Security Academy has no dedicated API gateway product
labs. For hands-on practice specific to product behavior, build local
labs per the "Supplementary Practice" section in each file:

- **Kong OSS via Docker Compose** — covers files 02, 03, 05, 06
  (Admin API exposure, route matching behavior, header stripping
  behavior, rate-limit plugin matching)
- **AWS API Gateway (sandbox account)** — covers files 02, 04, 05
  (security group/VPC Link misconfiguration, stage caching key
  configuration, resource policy conditions, default endpoint exposure)
- **Nginx with `auth_request` module** — covers file 06 specifically
  (the most common real-world DIY gateway auth-forwarding pattern)
- **Apigee** — no free local equivalent; rely on documentation review and
  credential-leakage-focused OSINT (file 05) rather than a hands-on sandbox
  unless a trial/sandbox org is available.

---

## Severity Quick-Reference (for report writing)

| Finding | Typical Severity | Why |
|---|---|---|
| Backend fully reachable, no auth at all | Critical | Complete authentication bypass |
| Backend reachable, header-trust forgeable | Critical | Equivalent to full auth bypass once combined with file 02 |
| Kong Admin API unauthenticated & reachable | Critical | Full control-plane compromise |
| AWS resource policy stale condition + default endpoint enabled | High–Critical | Depends on what's exposed behind it |
| Cross-tenant/cross-user cache poisoning | Critical | Direct data leakage across trust boundaries |
| Rate limit bypass via path normalization | High | Enables credential stuffing / resource exhaustion at scale |
| Poisoned absolute URLs via cache (no cross-user leakage) | High | Phishing/SSRF chaining potential |
| Apigee leaked read-only management token | Medium–High | Depends on org role scope |
| Path routing confusion without further impact demonstrated | Medium | Informational until chained with a concrete impact |
