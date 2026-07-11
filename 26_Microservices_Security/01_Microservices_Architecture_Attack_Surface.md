# Microservices Architecture and Attack Surface for Pentesters

## 1. Overview

Microservices architecture splits a single application into many small, independently
deployable services that communicate over a network instead of via in-process function
calls. From a security testing perspective, this is the single most important fact
about microservices: **internal function calls become network requests**, and network
requests can be intercepted, replayed, forged, and redirected.

This file covers:

- Why microservices have a larger internal API attack surface than monolithic apps
- How internal (service-to-service) communication differs from external-facing APIs
- What trust assumptions microservices commonly make about each other
- Why those trust assumptions are dangerous
- WAF/API Gateway relevance for this specific topic (explicitly addressed below)

Files 2–4 in this series build directly on the concepts introduced here. Read this
file first even if you are eager to jump into exploitation — every technique in the
later files exploits a trust assumption defined in this file.

---

## 2. Why Microservices Have a Larger Internal Attack Surface

### 2.1 The monolith baseline

In a monolith, a "checkout" function calling an "inventory" function is a local method
call. There is no network hop, no authentication check, no serialization boundary, and
no opportunity for an attacker to sit in the middle. The only attack surface is the
handful of externally exposed HTTP endpoints.

### 2.2 What changes with microservices

A typical microservices deployment might decompose that same checkout flow into:

- `api-gateway` (externally exposed)
- `auth-service`
- `user-service`
- `inventory-service`
- `pricing-service`
- `payment-service`
- `notification-service`
- `order-service`

Every one of these now exposes a network-reachable API — usually HTTP/REST or gRPC —
even though only `api-gateway` was ever intended to be reachable from the internet.
That is **seven additional network-facing APIs** that did not exist in the monolith,
each with its own:

- Authentication mechanism (or lack thereof)
- Authorization logic (or lack thereof)
- Input validation
- Dependency chain
- Deployment configuration

**The core pentesting insight:** the externally facing attack surface (the API
gateway) is usually well tested and well defended. The internal attack surface —
eight or more services each with their own listening ports — is frequently untested,
because the team's mental model is "attackers can't reach it anyway." That mental
model is the trust assumption this entire series exists to break.

### 2.3 Attack surface multiplication, not addition

The internal attack surface does not grow linearly with service count — it grows
closer to combinatorially, because:

- Every service-to-service call is a potential injection point (SSRF, deserialization,
  parameter pollution) independent of the others
- Every service typically has its own datastore, meaning a single compromised service
  can pivot to a database that has nothing to do with the original entry point
- Service mesh sidecars (Envoy, Linkerd-proxy) and service discovery components
  (Consul, etcd, Kubernetes DNS) become attack surface in their own right
- Message queues and event buses (Kafka, RabbitMQ, SNS/SQS) used for async
  service-to-service communication add yet another layer with its own trust model

**Real-world note:** In whitebox and internal pentest engagements, it is common to
find that a single externally exploitable vulnerability (e.g., an SSRF in an
image-fetching microservice) provides a pivot point into a flat internal network
where 15–40 internal services are reachable with no additional authentication. The
external attack surface might be hardened to a high standard while the internal
surface has effectively zero authentication between services — this asymmetry is the
single most common finding in microservices security assessments.

---

## 3. How Internal Service Communication Differs From External APIs

| Aspect | External-Facing API | Internal Service-to-Service API |
|---|---|---|
| Assumed caller | Untrusted, unauthenticated public | Trusted, "internal" service |
| Authentication | Almost always required (API key, OAuth, session) | Frequently absent or minimal |
| Input validation | Usually rigorous | Frequently relaxed — "the gateway already validated this" |
| Rate limiting | Standard practice | Rarely implemented |
| Logging/monitoring | Comprehensive | Sparse — internal traffic is often excluded from WAF/IDS coverage |
| Transport security | TLS mandatory | Often plaintext HTTP within the cluster/VPC, relying on network isolation |
| Network exposure | Internet-facing, load balancer | Internal DNS/service discovery, ClusterIP, private subnet |
| Protocol | REST/HTTP is dominant | REST, gRPC, GraphQL federation, or message queues — mixed protocols |

The critical row is **network exposure**: internal service communication typically
relies on the network boundary itself (VPC, Kubernetes namespace, security group) as
the *only* control. There is frequently no application-layer authentication because
the network layer was assumed to already do that job. This is exactly the assumption
that SSRF, container escapes, and misconfigured network policies defeat (see Files 3
and 4).

### 3.1 Protocol diversity as an attack surface issue

Unlike a monolith with one clear entry point, microservices commonly mix:

- Synchronous REST/JSON between some services
- Synchronous gRPC (binary, Protocol Buffers) between performance-sensitive services
- Asynchronous messaging (Kafka/RabbitMQ/SQS) for event-driven flows
- GraphQL federation gateways aggregating multiple backend services

Each protocol has different tooling maturity for security testing. Burp Suite handles
REST/JSON natively; gRPC requires proxy configuration (see the gRPC series for
details); message queues frequently have no HTTP interception path at all and require
direct broker access to test. **A pentester who only tests the REST endpoints in a
mixed-protocol environment is systematically missing a large fraction of the internal
attack surface.**

---

## 4. Trust Assumptions Microservices Commonly Make

These are the specific assumptions you are testing *for the presence of* in Files 2–4.
Understanding *why* each assumption exists is what lets you explain findings credibly
in a report — "missing authentication" is a weak finding; "the service assumes network
membership implies authorization, and here is the request that disproves that" is a
strong one.

### 4.1 Assumption: "Only internal services can reach this endpoint"

**Why it exists:** The service was deployed on an internal network segment (private
subnet, Kubernetes ClusterIP, internal load balancer) and the developer reasoned that
network placement is sufficient access control.

**Why it's dangerous:** Network boundaries are frequently crossed by means the
developer didn't anticipate: SSRF from an adjacent service, a compromised container,
a misconfigured ingress rule, a debug port left open, or — very commonly — the
service being reachable directly because the API gateway is not actually the only
ingress path (this is the entire subject of File 4).

### 4.2 Assumption: "The gateway already authenticated this request"

**Why it exists:** The API gateway performs authentication once at the edge (validates
a JWT, checks an API key), and downstream services trust that any request reaching
them has already passed that check.

**Why it's dangerous:** This assumption is only valid if it is *architecturally
enforced* — i.e., the downstream service is genuinely unreachable except through the
gateway. In practice this is rarely true (again, File 4). Even when it is true, this
pattern means a single gateway bypass compromises authentication for the entire
service mesh at once — there's no defense in depth.

### 4.3 Assumption: "The gateway already validated/sanitized this input"

**Why it exists:** Similar to 4.2 — input validation is centralized at the edge to
avoid duplicating validation logic across every service.

**Why it's dangerous:** Downstream services often accept additional parameters, headers,
or fields that the gateway's schema doesn't cover (over-posting, mass assignment via
internal-only fields), and internal services frequently trust internal callers to send
well-formed data, skipping validation entirely. An attacker who reaches a downstream
service directly bypasses every input check the gateway would have applied.

### 4.4 Assumption: "Service identity equals authorization"

**Why it exists:** If service A can prove *it is service A* (via mTLS client cert, a
service token, or simply its source IP/namespace), many architectures conclude that
service A is authorized to perform *any* action the target service exposes.

**Why it's dangerous:** This conflates authentication (who are you) with authorization
(what are you allowed to do). A compromised or SSRF-abused low-privilege service (e.g.,
`notification-service`) that can reach `payment-service` at the network layer often
finds it has no additional authorization checks to defeat — proving network membership
was the only gate.

### 4.5 Assumption: "Internal traffic doesn't need encryption"

**Why it exists:** TLS termination happens at the load balancer/gateway; traffic
"inside" the VPC or cluster is assumed safe because an external attacker supposedly
cannot observe it.

**Why it's dangerous:** This assumption fails the moment an attacker gains a foothold
inside the network boundary (compromised pod, SSRF pivot, malicious/compromised
third-party sidecar container). Plaintext internal HTTP means that foothold instantly
grants credential and data interception across every service that traverses it.

### 4.6 Assumption: "Internal APIs don't need the same rigor as public APIs"

**Why it exists:** Internal APIs are seen as an implementation detail, not a product
surface, so they receive less design review, less documentation, and less security
testing budget.

**Why it's dangerous:** This is a process failure that compounds all the assumptions
above — nobody is explicitly deciding "we accept this risk," it simply never gets
evaluated.

---

## 5. WAF / API Gateway Relevance for This Topic

**This file (architecture/attack surface) has no dedicated WAF/Gateway detection or
bypass section, and that is intentional — here is why:**

This file is conceptual and architectural; it does not describe a specific exploit
technique that a WAF or gateway would have a detection signature for. WAF/Gateway
detection and bypass content is genuinely relevant to the *specific* attack
techniques described later in this series, and is covered where it applies:

- **File 3 (Service Impersonation & Lateral Movement)** — SSRF-based internal service
  access is a well-known WAF/gateway detection category (SSRF payload patterns,
  outbound request anomaly detection). Covered in full there.
- **File 4 (API Gateway Bypass)** — this is inherently a gateway-defense topic: the
  entire technique is about reaching services the gateway is supposed to be the sole
  path to. Covered in full there, including detection and bypass considerations.

File 2 (mTLS/service auth) also has a brief WAF/gateway relevance note, since gateway
policies are sometimes (incorrectly) relied upon as a substitute for mTLS.

---

## 6. PortSwigger Web Security Academy Mapping

PortSwigger Web Security Academy has **no labs that directly simulate a multi-service
internal microservices architecture** — its labs are single-application, single-origin
by design. This is expected and stated up front rather than forced: microservices
internal-communication testing is fundamentally a **whitebox/internal network pentest
discipline**, not a blackbox web app discipline, and PortSwigger's lab format doesn't
model multi-service trust boundaries.

That said, several PortSwigger labs teach the *exact underlying primitive* that
enables microservices attacks (SSRF reaching internal-only endpoints), and are the
correct preparation before attempting real microservices assessments:

**Apprentice:**
- *Basic SSRF against the local server* — teaches the fundamental "reach a service
  that assumes it's unreachable" primitive used throughout File 3.
- *Basic SSRF against another back-end system* — directly models pivoting from one
  reachable component to an internal-only one, which is the microservices lateral
  movement pattern in miniature.

**Practitioner:**
- *SSRF with blacklist-based input filter* and *SSRF with whitelist-based input
  filter* — relevant because internal microservices deployments frequently attempt
  exactly these weak filtering strategies to "protect" internal-only endpoints.
- *SSRF with filter bypass via open redirection vulnerability* — models chaining
  through an intermediate service, analogous to multi-hop lateral movement.

**Expert:**
- PortSwigger does not currently have an Expert-tier SSRF/internal-pivot lab beyond
  the Practitioner set above. Gap is disclosed honestly here rather than papered over.

---

## 7. Supplementary Practice: HackTheBox and TryHackMe

Because PortSwigger coverage is minimal for this topic by design, supplementary
practice against real multi-host, multi-service environments is essential.

### HackTheBox Pro Labs

- **HTB Pro Labs — "RastaLabs" / "Offshore" / "Cybernetics"** — these are full
  enterprise-style internal networks with multiple internal services, Active
  Directory integration, and internal API endpoints that assume network-level trust.
  They are the closest available simulation of "you've landed inside the perimeter,
  now enumerate and pivot across internal services."
- **HTB Pro Labs — "APTLabs"** — includes internal service chains and lateral
  movement scenarios reflecting real breach patterns, useful for practicing
  enumeration methodology across many internal hosts/services rather than a single
  target.

Note: HTB Pro Labs are primarily Active Directory/Windows-domain focused rather than
container/Kubernetes-microservices focused — treat them as lateral-movement and
internal-enumeration methodology practice, not literal microservices practice.

### TryHackMe (internal-network-focused rooms)

- **"Internal"** — a room explicitly built around pivoting from an external foothold
  into an internal network with multiple internal-only services, directly modeling
  the trust-boundary-crossing pattern this series covers.
- **"Wreath"** — a network pivoting and lateral movement network, good for practicing
  multi-hop enumeration methodology (proxychains, port forwarding) that's identical
  in spirit to hopping between internal microservices.
- **Kubernetes-specific rooms (search current TryHackMe catalog for "Kubernetes" and
  "Container Security")** — TryHackMe's Kubernetes-focused rooms are the most direct
  simulation of container/service-mesh misconfiguration relevant to File 4
  specifically; check current room availability as TryHackMe's catalog changes
  frequently.

### crAPI (supplementary, cross-referenced from the API series)

crAPI (Completely Ridiculous API) has a genuine microservices backend (multiple
Docker containers: identity, community, workshop services) and is worth revisiting
specifically for this series — inspect its docker-compose.yml to see real internal
service-to-service calls and test whether internal endpoints enforce authorization
independently of the gateway.

---

## 8. Cross-References

- See **File 2** for mTLS and JWT-based service authentication testing.
- See **File 3** for the full SSRF-to-service-impersonation walkthrough and lateral
  movement methodology referenced in Section 6 above.
- See **File 4** for API gateway bypass testing (Kubernetes/ECS/Docker).
- See the existing **SSRF series** for foundational SSRF technique and payload detail
  — this series assumes that knowledge and builds the microservices-specific context
  on top of it rather than repeating it.
- See the existing **API Gateway Security series** for gateway configuration hardening
  content that complements the offensive testing methodology in File 4.

---

## 9. Key Takeaway

Every technique in this series is fundamentally about disproving one sentence:
**"this service doesn't need its own security controls because something else already
handles it."** Your job as a tester is to find the gap between what the architecture
diagram claims and what the network actually permits.
