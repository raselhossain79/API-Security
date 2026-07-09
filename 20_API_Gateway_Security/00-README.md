# API Gateway Security Testing

A note series on the security of the API gateway layer itself — Kong, AWS
API Gateway, Apigee, Azure API Management, and Nginx-based gateways — as
distinct from backend application logic covered in the web application
security and API security (OWASP API Security Top 10) series.

The API gateway sits in front of nearly every modern production API and is
frequently misconfigured in ways that create a false sense of security:
the backend appears protected because "the gateway handles that," while
the actual enforcement gap sits in the trust boundary between the two
components.

## Files

| File | Topic |
|---|---|
| [01-api-gateway-overview.md](01-api-gateway-overview.md) | Gateway role: auth offloading, rate limiting, routing, caching — mechanism first. Why misconfiguration creates false security. |
| [02-gateway-auth-bypass-backend-direct-access.md](02-gateway-auth-bypass-backend-direct-access.md) | Testing direct backend reachability when the gateway is bypassed; path-based routing confusion between gateway and backend. |
| [03-gateway-rate-limit-bypass.md](03-gateway-rate-limit-bypass.md) | Route normalization differentials (trailing slash, case, encoding) exploited to bypass gateway rate limiting. |
| [04-api-gateway-cache-poisoning.md](04-api-gateway-cache-poisoning.md) | Unkeyed-input cache poisoning at the gateway layer. Cross-references the Web Cache Poisoning notes for the general concept. |
| [05-default-creds-exposed-admin-interfaces.md](05-default-creds-exposed-admin-interfaces.md) | Kong Admin API exposure, AWS API Gateway resource policy misconfiguration, Apigee management plane exposure. |
| [06-gateway-backend-header-trust-exploitation.md](06-gateway-backend-header-trust-exploitation.md) | Spoofing gateway-injected trust headers (`X-User-Id`, `X-Gateway-Authenticated`, etc.) when the backend can't verify their origin. |
| [07-cheatsheet-lab-mapping.md](07-cheatsheet-lab-mapping.md) | Engagement checklist, header reference, full PortSwigger lab mapping (Apprentice → Practitioner → Expert), vendor-based supplementary lab setups, severity reference. |

## Conventions

Consistent with the rest of the note library:

- Mechanism explained before technique in every file
- Every technique broken down step by step, with the specific
  gateway/backend trust assumption being exploited stated explicitly
- PortSwigger Web Security Academy labs mapped in Apprentice →
  Practitioner → Expert order wherever applicable, with honest disclosure
  of gaps where no dedicated lab exists
- Vendor documentation-based local lab setups (Kong, AWS API Gateway,
  Nginx `auth_request`) provided as supplementary practice for gaps
  PortSwigger doesn't cover
- Real-world notes included in every file
- Cross-references to sibling series (Web Cache Poisoning, Host Header
  Injection, HTTP Request Smuggling, JWT Attacks, Broken Access Control,
  BOLA, API4 Unrestricted Resource Consumption) rather than repeating
  content already covered there
- Full English throughout

## Suggested Reading Order

Read files 01 → 06 in order on a first pass. File 07 is a standalone
reference for use during an active engagement once the material is
familiar.
