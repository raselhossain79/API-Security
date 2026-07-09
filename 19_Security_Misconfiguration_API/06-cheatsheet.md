# 06 — API Security Misconfiguration Cheatsheet

Condensed quick-reference for this series. Full mechanism, exploitation detail, and remediation
live in files 01–05 — this file is for fast lookup during an active engagement, not first-time
learning.

## Quick Checklist

### Exposed documentation
- [ ] Sweep common Swagger/OpenAPI paths (unauthenticated): `/swagger-ui.html`, `/swagger-ui/`,
      `/api-docs`, `/v2/api-docs`, `/v3/api-docs`, `/openapi.json`, `/docs`, `/redoc`
- [ ] If a spec is reachable: extract `paths`, `servers`, `security`, `description`/`example`
      fields via `jq`
- [ ] Confirm GraphQL endpoint (`{"query":"{__typename}"}`) at `/graphql`, `/api/graphql`,
      `/v1/graphql`, `/query`
- [ ] Send full introspection query; if blocked, try whitespace-mutated `__schema {`, `GET` with
      query param, `x-www-form-urlencoded` content-type
- [ ] Query for schema fields the production client never actually requests

### CORS
- [ ] Send `Origin: https://<random-domain>` to every authenticated endpoint, not just login
- [ ] Send `Origin: null` separately
- [ ] Check `Access-Control-Allow-Credentials: true` paired with a reflected/null origin
- [ ] Confirm `Access-Control-Allow-Origin: *` cases actually have zero auth requirement before
      flagging
- [ ] Check `Vary: Origin` presence when a non-wildcard origin is returned (cache-poisoning signal)
- [ ] Test `OPTIONS` preflight response independently of the real request

### Headers
- [ ] `Content-Type: application/json` explicit and correct on every response
- [ ] `X-Content-Type-Options: nosniff` present
- [ ] `Cache-Control: no-store` on token/PII-bearing endpoints
- [ ] `Access-Control-Expose-Headers` not wildcarded / not exposing internal debug headers

### Error leakage
- [ ] Send type-confused values (string where int expected, and vice versa)
- [ ] Send out-of-range / overflow integers
- [ ] Send malformed structure (array vs object mismatch)
- [ ] Send wrong/absent `Content-Type`
- [ ] Send explicit `null` for normally-present fields
- [ ] Compare gateway-fronted response vs. any direct-backend path for sanitization gaps

### Default credentials / methods
- [ ] Test Swagger UI Basic-auth defaults if `401 WWW-Authenticate: Basic` observed
- [ ] Check gateway admin ports (Kong `8001`/`8444`, others per current vendor docs) for
      unauthenticated or default-credential access
- [ ] `OPTIONS` every discovered route, test every method listed in `Allow`
- [ ] Test `TRACE` for injected internal headers
- [ ] Test method-override headers (`X-HTTP-Method-Override`, `X-Method-Override`, `_method`)
      against any edge-blocked method

## Payload Quick-Reference

```
# GraphQL — confirm endpoint
POST /graphql
{"query":"{__typename}"}

# GraphQL — introspection (send via Burp GraphQL tab for full query)
POST /graphql
{"query":"{__schema{types{name fields{name}}}}"}

# GraphQL — introspection filter bypass (whitespace)
POST /graphql
{"query":"{__schema {types{name}}}"}   # note the space after __schema

# GraphQL — introspection via GET
GET /graphql?query=query{__typename}

# CORS — reflected origin test
GET /api/v1/account
Origin: https://attacker-controlled.example

# CORS — null origin test
GET /api/v1/account
Origin: null

# Error leakage — type confusion
POST /api/v1/orders
{"productId": "not-a-number"}

# Error leakage — overflow
POST /api/v1/orders
{"quantity": 999999999999999999999}

# Method enumeration
OPTIONS /api/v1/users/42

# TRACE header disclosure
TRACE /api/v1/account
Cookie: session=...

# Method override bypass
POST /api/v1/users/42
X-HTTP-Method-Override: DELETE
```

## WAF / Gateway Relevance Summary

| Category | WAF/Gateway bypass relevant? | Why |
|---|---|---|
| Exposed documentation | No — request is syntactically normal | Gateway routing/allow-list is the real control, not signature detection |
| CORS misconfiguration | No — enforced entirely by the browser | Gateway can *set* CORS headers via a plugin, but there's nothing to "bypass" at the network layer |
| Missing security headers | No — omission, not an attack to block | Gateway response-transformation can add headers; nothing to bypass |
| Verbose error messages | **Yes** | WAFs may block known error-triggering inputs; gateways may sanitize backend error bodies — both have real bypass techniques (encoding variation, alternate content-types, direct-backend paths) |
| Default credentials | No — valid-looking auth request | Network exposure/binding is the real control, not detection |
| Unnecessary HTTP methods | **Yes** | Gateways/WAFs commonly allow-list methods at the edge; override headers and case manipulation are real bypass vectors |

## PortSwigger Lab Index (this series, in progression order)

**Apprentice**
1. Accessing private GraphQL posts
2. Bypassing GraphQL introspection defenses
3. CORS vulnerability with basic origin reflection
4. CORS vulnerability with trusted null origin
5. Information disclosure in error messages
6. Information disclosure on debug page
7. Source code disclosure via backup files
8. Authentication bypass via information disclosure
9. Information disclosure in version control history

**Practitioner**
10. Finding a hidden GraphQL endpoint
11. CORS vulnerability with trusted insecure protocols

**Expert**
12. CORS vulnerability with internal network pivot attack

**No PortSwigger lab exists for:** OpenAPI/Swagger spec exposure specifically, internal-hostname
leakage inside a spec, API gateway admin console default credentials (Kong/Apigee/AWS API
Gateway), `Access-Control-Expose-Headers` over-exposure, cache-control gaps on token endpoints,
and the systematic cross-endpoint dependency-fingerprinting workflow. **crAPI** is the recommended
supplementary practice target for all of these, since it models real API/gateway-adjacent
behavior that a web-app-focused lab platform can't reproduce.

## Cross-References

- CORS mechanism fundamentals → web app series, CORS notes
- General misconfiguration testing methodology → web app series, Security Misconfiguration notes
- Method-based access control bypass exploitation depth → Broken Access Control series
- Internal hostname leakage → SSRF series (API7)
- GraphQL exploitation beyond introspection → GraphQL Security series
- Broader endpoint discovery methodology → API Reconnaissance series
