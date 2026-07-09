# API Gateway Security — Overview

## Series Scope

This series covers the security of the **API gateway layer itself** — the
component (Kong, AWS API Gateway, Apigee, Azure API Management, Nginx-based
gateways such as Kong OSS, KrakenD, or a hand-rolled Nginx reverse proxy) that
sits in front of backend APIs in almost every modern production deployment.

This is a distinct attack surface from the backend application logic covered
in the web application security series and the OWASP API Security Top 10
series. Those series assume requests arrive at the backend as sent. This
series questions that assumption: it examines what happens *between* the
client and the backend, where a gateway rewrites, filters, authenticates,
rate-limits, and caches traffic — and where every one of those operations can
silently diverge from what the backend assumes is happening.

Cross-references: this series assumes familiarity with the BOLA, Broken
Authentication, JWT, and OAuth 2.0 notes in the API series, and the Web Cache
Poisoning and Host Header Injection notes in the web application series. It
does not repeat mechanism explanations already covered there in full; it
extends them to the gateway context.

---

## What an API Gateway Actually Does

An API gateway is a reverse proxy with additional policy-enforcement
responsibilities. Understanding each responsibility mechanically is required
before testing any of them, because every vulnerability in this series is a
**gap between what the gateway enforces and what the backend assumes is
already enforced**.

### 1. Authentication Offloading

**Mechanism.** Instead of every backend microservice implementing its own
API key validation, JWT verification, or OAuth token introspection, the
gateway does this once, at the edge. On a successful check, the gateway
either:

- Forwards the original credential unchanged (backend re-validates), or
- Strips the original credential and replaces it with an internal signal —
  commonly a header like `X-Authenticated-User`, `X-User-Id`, or a
  gateway-signed internal JWT — that tells the backend "I already checked
  this, trust me."

**Why this matters.** The second pattern is extremely common because it is
faster (no redundant crypto operations at every microservice) and simpler to
implement across polyglot backends. It also means the backend has **no
independent way to verify** that a request was actually authenticated unless
it can independently verify the trust signal (e.g., a signed internal JWT
with a key the backend also holds). If the backend is reachable by any path
that does not go through the gateway, authentication offloading becomes a
complete authentication bypass, because the backend was never given the
ability to authenticate anything itself — it only knows how to trust a
header. This is the mechanism explored in file 02 and file 06.

### 2. Rate Limiting Enforcement

**Mechanism.** The gateway tracks request counts against a key — typically
API key, client IP, or authenticated user ID — over a sliding or fixed
window, using an in-memory store or a shared store like Redis for
multi-node gateway clusters. When the counter exceeds a configured
threshold, the gateway returns `429 Too Many Requests` and does not forward
the request to the backend.

**Why this matters.** Rate limiting is almost always configured **per
route**, matched against a route definition (a URL pattern, sometimes with
an HTTP method). If the gateway's route-matching logic and the backend's
own routing logic disagree about what counts as "the same route" — due to
trailing slashes, case sensitivity, or URL-encoding normalization
differences — a request can be counted against one rate-limit bucket at the
gateway while being served by a completely different (unprotected) backend
endpoint alias. The backend itself typically has no rate limiting at all,
because "the gateway handles that" is the standard architectural
assumption. This is the mechanism explored in file 03.

### 3. Request Routing

**Mechanism.** The gateway maps incoming paths to backend services using
route definitions — path prefixes, path templates, or virtual host rules.
A request to `gateway.example.com/api/v2/users/123` might be rewritten and
forwarded to `internal-users-svc.local:8080/users/123`, with the gateway
stripping or rewriting the `/api/v2` prefix.

**Why this matters.** Routing rules encode assumptions about what paths
*should* reach the backend. They do not remove other paths from actually
being reachable if the backend is exposed directly. Path rewriting also
creates room for confusion: a path that is blocked or transformed by the
gateway's routing table may be interpreted completely differently if it
reaches the backend unrewritten, because the backend was never designed to
receive the raw, un-rewritten path. This is explored further in file 02.

### 4. Response Caching

**Mechanism.** To reduce backend load, gateways can cache responses to GET
(and sometimes other idempotent) requests, keyed by a subset of the
request — typically the path and a small set of query parameters or
headers explicitly configured as part of the cache key. Everything not
included in the key is invisible to the cache: two requests that differ
only in an unkeyed input are treated as identical and served the same
cached response.

**Why this matters.** If the backend uses an input that the gateway does
not include in its cache key to generate different response content (a
header used for localization, a cookie used for personalization, an
`X-Forwarded-Host` used to build absolute URLs), an attacker can poison the
gateway's cache with backend output generated under attacker-controlled
conditions, and every subsequent consumer hitting that cached route
receives the poisoned response. This is the same root cause as web cache
poisoning, applied at the gateway layer rather than a CDN or reverse-proxy
cache in front of a monolith. See file 04.

---

## Why a Misconfigured Gateway Creates a False Sense of Security

This is the central theme of the entire series and worth stating explicitly
before diving into individual techniques.

Modern API security guidance (OWASP API Security Top 10, this series' own
backend-focused notes) largely assumes the backend is the thing under test.
Organizations that have deployed a gateway often treat that deployment as
having *already solved* authentication, rate limiting, and abuse
prevention — because the gateway vendor markets it that way, and because
from the outside (testing only through the gateway) it may appear to work
correctly.

The false sense of security comes from three independent trust
assumptions, each of which this series tests directly:

1. **"The backend isn't reachable directly."** True only if network
   controls (security groups, firewall rules, service mesh policy) actually
   enforce it. This is an infrastructure assumption, not a gateway feature,
   and it is routinely wrong — especially in cloud deployments where a
   backend service is given a public IP or load balancer for operational
   convenience (health checks, internal tooling access from a VPN) and the
   assumption "internal-only" was never actually enforced by a security
   group rule.

2. **"The gateway and backend agree on what a request means."** True only
   if both components normalize paths, methods, and encoding identically.
   Gateways and backends are frequently different technology stacks (e.g.,
   Kong/Nginx in front of a Spring Boot or Express backend) with different
   default normalization behavior. Divergence here breaks rate limiting,
   routing security, and any gateway-level input validation.

3. **"A signal set by the gateway can be trusted by the backend."** True
   only if the backend can distinguish a gateway-set header from a
   client-set header — normally by only trusting that header on
   connections it can prove come from the gateway (mTLS, network
   segmentation, a shared secret). Where this proof is missing, any header
   the gateway adds after authentication is exploitable exactly like a
   forged authentication token, because functionally that is what it is.

Every technique in this series is really a variation on: **find a place
where the gateway's enforcement and the backend's assumptions do not line
up, and stand in that gap.**

---

## Real-World Notes

- Gateway misconfiguration bug bounty reports (multiple public disclosures
  across Bugcrowd/HackerOne programs, generalized) repeatedly show the same
  root cause: a backend service originally deployed "temporarily" with a
  public listener for debugging or CI/CD access, which was never removed,
  sitting behind a gateway that everyone assumed was the only entry point.
- Kong, AWS API Gateway, and Azure APIM all default to *not* rate-limiting
  unless a plugin/policy is explicitly attached to a route — meaning newly
  added routes are frequently unprotected by default until someone
  remembers to configure the policy. This is a process gap, not a bug, but
  it is one of the highest-yield things to check first on any engagement.
- Multiple documented cloud misconfiguration incidents involve S3-fronting
  or Lambda-backed AWS API Gateway deployments where a resource policy
  intended to restrict access to a VPC endpoint was written with a
  condition that silently evaluated to allow-all due to a policy syntax
  error — a class of bug covered in file 05.

---

## How to Use This Series

Read files in order for a first pass; each technique file assumes the
mechanism explanation from this file. File 07 is a standalone cheatsheet
for use during an active engagement once you're familiar with the
material, plus the full PortSwigger lab mapping in Apprentice →
Practitioner → Expert order for the sub-topics where PortSwigger labs
apply, and vendor-lab setup notes for the sub-topics where they don't.
