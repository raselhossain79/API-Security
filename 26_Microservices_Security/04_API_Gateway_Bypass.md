# API Gateway Bypass

## 1. Overview

Every technique in Files 2 and 3 assumes an attacker who has *already* gained some
form of internal network access (via SSRF, a compromised container, or whitebox
access). This file covers a different and often simpler path: **reaching internal
services directly from outside, without ever passing through the API gateway at
all**, because the underlying infrastructure doesn't actually enforce the gateway as
the sole entry point.

This is a deployment/infrastructure misconfiguration category, most common in
Kubernetes, ECS, and Docker environments, and it directly disproves Trust Assumption
4.2/4.3 from File 1 ("the gateway already authenticated/validated this") — if the
gateway can be bypassed entirely, every downstream assumption that depends on the
gateway having done its job is void.

---

## 2. Why Gateway Bypass Happens

The API gateway is *meant* to be the single ingress point, with all other services
reachable only from within the internal network. This requires the surrounding
infrastructure (Kubernetes Ingress/Service config, ECS security groups, Docker port
mappings, cloud load balancer rules) to *enforce* that exclusivity. In practice, this
enforcement frequently has gaps because it spans multiple teams and tools
(networking, platform, and application teams often own different pieces), and because
the default behavior of the underlying platforms is often more permissive than
intended.

---

## 3. Kubernetes: Common Misconfiguration Patterns

### 3.1 Service type `LoadBalancer` or `NodePort` applied to internal services

Kubernetes `Service` objects have several types:

- `ClusterIP` (default) — only reachable from within the cluster
- `NodePort` — exposes the service on a static port on every node's IP, reachable
  from outside the cluster if the node's network allows it
- `LoadBalancer` — provisions an external cloud load balancer, directly
  internet-facing

**The misconfiguration:** a service that should be `ClusterIP`-only (internal-only)
gets deployed as `NodePort` or `LoadBalancer` — often as a leftover from local
development/debugging convenience, or because a developer copy-pasted a working
manifest without changing the type field.

**Testing methodology:**

```bash
# If you have any cluster visibility (whitebox) or discover node IPs (blackbox recon)
kubectl get services --all-namespaces -o wide
# Look for internal-sounding service names (inventory-service, payment-internal, etc.)
# with type NodePort or LoadBalancer instead of ClusterIP
```

Without `kubectl` access (external blackbox test), the equivalent is broad port
scanning of discovered node/infrastructure IPs (from ASN/cloud-range recon,
certificate transparency logs revealing internal hostnames with public DNS records,
or cloud metadata leaked via an unrelated SSRF per File 3) for high, non-standard
ports characteristic of NodePort's default range (30000–32767):

```bash
nmap -p 30000-32767 <discovered-node-ip>
```

A response from an internal-only-intended service on one of these ports, reachable
without going through the gateway/ingress, confirms the bypass.

### 3.2 Ingress rules with overly broad path matching

Kubernetes Ingress controllers route external traffic based on host/path rules. A
common flaw:

```yaml
- path: /api/
  pathType: Prefix
  backend:
    service:
      name: api-gateway
- path: /internal/
  pathType: Prefix
  backend:
    service:
      name: inventory-service   # should never be externally routable
```

If a second Ingress rule (sometimes added later, by a different team, for internal
debugging/monitoring convenience — e.g., exposing Prometheus metrics or an admin
health page) routes directly to an internal service, that service becomes reachable
from the internet despite never being intended as a gateway-fronted API.

**Testing methodology:** systematically probe for internal-sounding paths against the
public-facing hostname, not just the documented API paths:

```
https://shop.example.com/internal/
https://shop.example.com/admin/
https://shop.example.com/actuator/
https://shop.example.com/inventory-service/
https://shop.example.com/metrics
```

Combine with subdomain enumeration (cross-reference the existing subdomain
takeover/recon series) — internal services are sometimes given their own subdomain
(`inventory-internal.example.com`) that was meant for internal DNS resolution only,
but the DNS record and/or Ingress rule is public.

### 3.3 Missing or misconfigured NetworkPolicy

Even when Ingress/Service configuration correctly restricts *external* ingress,
Kubernetes' default behavior *without* a NetworkPolicy applied is **fully permissive
pod-to-pod communication within the cluster** — any pod can reach any other pod's
ClusterIP-exposed ports by default. This isn't strictly "gateway bypass" from
outside, but it means that once *any* pod is compromised (including a low-value
one, or one reached via SSRF per File 3), the "gateway is the only path to internal
services" assumption is false from that internal vantage point too, because no
policy is actually restricting east-west traffic.

**Testing methodology (from any pod-level foothold):**

```bash
# From inside a compromised/accessible pod
curl http://inventory-service.default.svc.cluster.local/internal/adjust-stock
# If this succeeds despite no NetworkPolicy explicitly permitting this specific
# pod-to-service relationship, segmentation is absent
```

Cross-reference File 3, Section 4.4, which covers this same test from the
lateral-movement angle.

### 3.4 Direct pod IP access bypassing Service abstraction entirely

Kubernetes pods each get their own cluster-internal IP address, independent of any
`Service` object. If an attacker (from an internal foothold) can enumerate pod IPs
directly (via DNS, via a compromised component with cluster API read access, or via
IP range sweeping), they can sometimes reach a pod's application port directly,
bypassing not just the API gateway but also any `Service`-level restrictions
(a `Service` can have restrictive `selector`/port config, but the underlying pod's
container port is usually still open to any traffic that reaches it directly, since
Kubernetes doesn't firewall a pod from its own exposed ports by default — that's what
NetworkPolicy is for, per 3.3).

---

## 4. ECS (Elastic Container Service): Common Misconfiguration Patterns

### 4.1 Security groups scoped too broadly

ECS tasks run within security groups that should restrict inbound traffic to only the
load balancer/gateway's security group. A common flaw: the task's security group
allows inbound traffic from `0.0.0.0/0` or from an overly broad internal CIDR (e.g.,
"allow from anywhere in the VPC") rather than specifically from the gateway/ALB's
security group.

**Testing methodology (from any position within the VPC, including a pivot per
File 3):**

```bash
# Enumerate ECS task private IPs (via cloud metadata if you have any foothold with
# IAM read permissions, or via internal DNS/service discovery if AWS Cloud Map is in use)
curl http://<task-private-ip>:<container-port>/internal/endpoint
```

If reachable without traversing the ALB, the security group is over-permissive.

### 4.2 Application Load Balancer with multiple target groups and inconsistent rules

A single ALB is sometimes configured with multiple listener rules routing to
different target groups (one for the public gateway, others for internal services
added for convenience — e.g., a debug dashboard). Each listener rule is independently
configured, and it's common for one to be added without the same authentication
requirements as the primary API path.

**Testing methodology:** enumerate ALB listener rules if you have AWS console/API
visibility (whitebox), or externally probe the ALB's public DNS name / associated
hostnames for unexpected paths, similar to Section 3.2's Ingress path enumeration.

### 4.3 AWS Cloud Map / service discovery misconfiguration

ECS Service Discovery (AWS Cloud Map) creates internal DNS records for services,
analogous to Kubernetes' `svc.cluster.local` names. If these DNS zones are
inadvertently made resolvable or the underlying records/security groups are
over-permissive, the same internal-hostname-enumeration technique from File 3,
Section 3.2 applies directly.

---

## 5. Docker (Non-Orchestrated / Docker Compose) Misconfiguration Patterns

### 5.1 Published ports beyond what's needed

`docker-compose.yml` files commonly use the `ports:` directive to publish a
container's port to the host, making it reachable from outside the Docker network
entirely — including from the internet if the host itself has a public IP and no
host-level firewall restricts it:

```yaml
inventory-service:
  ports:
    - "8080:8080"   # published to the HOST, not just the internal Docker network
```

versus the correct approach for internal-only services:

```yaml
inventory-service:
  expose:
    - "8080"   # only reachable by other containers on the same Docker network
```

**Why this happens:** `ports:` is frequently left over from local development, where
developers want to `curl localhost:8080` directly to debug a specific service, and
the same compose file (or a copy-pasted pattern from it) makes it to a production-like
deployment without removing the publish directive.

**Testing methodology:** straightforward port scanning of the host:

```bash
nmap -p- <host-ip>
```

Any internal-service port responding directly (especially alongside the expected
gateway port) is a finding. Cross-reference the existing **Linux server hardening**
portfolio project methodology for host-level port audit technique.

### 5.2 Docker's default bridge network and inter-container reachability

Similar to Kubernetes' default-permissive pod-to-pod communication (Section 3.3),
containers on the same Docker bridge network can reach each other's exposed ports by
default with no additional authentication required at the network layer — this
mirrors File 1's "network membership implies trust" assumption exactly, and becomes
exploitable the moment any single container is compromised.

---

## 6. General Methodology Regardless of Platform

1. **Map the intended architecture first** (from documentation, API specs, or
   architecture diagrams if available in a whitebox engagement) — know what *should*
   be internal-only before testing what actually is.
2. **Enumerate all listening infrastructure**, not just the documented gateway
   entry point — full port scans of any discovered infrastructure IPs, subdomain
   enumeration for internal-sounding hostnames, and (if any internal foothold exists)
   internal DNS/service discovery enumeration.
3. **For every internal-sounding service/port found, test reachability from outside
   the intended trust boundary** — externally for platform-level bypass (Sections 3.1,
   3.2, 4.1, 4.2, 5.1), or from a lower-privilege internal foothold for segmentation
   bypass (Sections 3.3, 3.4, 4.3, 5.2).
4. **Confirm the service actually processes the request** (not just that the port is
   open) — an open port with a connection-refused-at-application-layer response is a
   lower-severity finding (information disclosure of internal architecture) than an
   open port that fully processes internal-only operations (critical finding,
   converges with File 3's impersonation testing once you're through).
5. **Chain with File 3** — a successful gateway bypass often lands you in exactly the
   same position as a successful SSRF pivot: internal network access to test for
   service impersonation and lateral movement. The two files' techniques are meant to
   be used together in a real engagement.

---

## 7. WAF / API Gateway Relevance for This Topic

This file is, definitionally, about gateway-defense bypass — the entire topic is
whether the gateway (and the WAF that often sits alongside or in front of it) can be
circumvented rather than defeated head-on.

### 7.1 Common detection methods

- **Gateway-only ingress enforcement via infrastructure, not application logic** —
  the strongest defense is architectural: NetworkPolicies (Kubernetes), security
  groups scoped exclusively to the gateway/ALB (ECS), and `expose` instead of
  `ports` (Docker Compose) that make bypass *impossible* rather than merely
  detected. This is a prevention control, not a detection one, and is the correct
  primary defense — WAF/detection controls below are compensating, not primary.
- **Traffic source anomaly detection** — API gateways and cloud WAFs can flag
  requests to backend services that didn't originate from the gateway's own IP/service
  identity (e.g., AWS WAF associated with an ALB won't see traffic that reaches a
  target group directly, bypassing the ALB — but VPC Flow Logs or GuardDuty can
  separately flag unusual direct-to-task traffic patterns).
- **Certificate/mTLS enforcement at the mesh level** (cross-reference File 2) — if
  every internal service requires mTLS regardless of how a request reaches it, a
  gateway bypass alone doesn't grant access; the attacker still needs a valid service
  certificate. This is the most robust compensating control against everything in
  this file, because it doesn't depend on network topology being correctly configured
  at all.
- **Kubernetes admission controllers / policy engines** (e.g., OPA Gatekeeper, Kyverno)
  can be configured to reject `Service` manifests of type `NodePort`/`LoadBalancer`
  for namespaces/services tagged as internal-only, catching Section 3.1's
  misconfiguration at deploy time rather than relying on runtime detection.

### 7.2 Realistic bypass considerations

- **Detection controls listed above are almost entirely infrastructure-visibility
  dependent** — a WAF sitting in front of the API gateway has zero visibility into
  traffic that never transits the gateway in the first place. This is the fundamental
  reason gateway bypass is such a high-value technique: most organizations' entire
  detection stack (WAF, gateway-level rate limiting, gateway-level logging) is
  positioned at a chokepoint that this technique routes around entirely.
  **This is the single most important realistic bypass consideration in this whole
  file: bypass isn't about evading detection signatures, it's about the detection
  apparatus never seeing the traffic at all.**
- **VPC Flow Logs / GuardDuty-style anomaly detection can still catch this**, but
  these are typically *investigative* (post-hoc, SOC-reviewed) rather than
  *preventive* (blocking in real time) in most environments, meaning a bypass is
  frequently successful for the duration of a pentest engagement even where
  detection tooling technically exists.
- **mTLS as compensating control (Section 7.1) is bypassable in exactly the ways
  described in File 2** — if the bypassed service also has weak/missing mTLS
  enforcement (a common *combination* finding, since both gaps stem from the same
  underlying "internal = trusted" mindset), gateway bypass plus mTLS bypass compounds
  into full unauthenticated access with no remaining architectural control at all.
  When you find one of these gaps, always explicitly test for the other.

---

## 8. PortSwigger Web Security Academy Mapping

PortSwigger has **no labs modeling container orchestration, cloud infrastructure, or
gateway/ingress misconfiguration** — this is entirely outside its single-web-app lab
model, and there is no meaningful partial mapping to force here (stated explicitly
rather than reaching for a loosely-related lab). The closest conceptually adjacent
labs are the HTTP request smuggling category, since request smuggling against a
gateway/reverse-proxy setup shares the theme of "the front-end and back-end disagree
about what's being requested," which is worth revisiting from that angle:

**Practitioner/Expert (cross-reference only, not a direct mapping):**
- The HTTP request smuggling lab series (already covered in your existing HTTP/2 and
  request smuggling note packages) — revisit specifically for the scenario where
  smuggling is used to reach a back-end path the front-end/gateway would normally
  block, which is a *protocol-level* analog to this file's *infrastructure-level*
  gateway bypass theme.

---

## 9. Supplementary Practice

- **Local Kubernetes lab (`kind`/`minikube`)** — by far the highest-value practice
  for this file specifically. Deliberately misconfigure a `Service` as `NodePort`,
  omit a `NetworkPolicy`, and practice Sections 3.1/3.3 end-to-end against
  infrastructure you built yourself, since no CTF platform currently models this
  precisely.
- **HTB Pro Labs / TryHackMe Kubernetes-specific rooms** — check the current TryHackMe
  catalog for Kubernetes and container security rooms (availability changes
  frequently); these are the most direct third-party simulation of Sections 3–5.
- **TryHackMe "Internal"** — again relevant here for the general internal-network
  reachability testing mindset, even though it doesn't model Kubernetes/ECS
  specifically.
- **AWS/cloud-specific practice** — HTB's cloud-focused content and platforms like
  "flAWS" (a well-known free AWS misconfiguration wargame, unaffiliated with
  PortSwigger/HTB) are useful supplements specifically for Section 4's ECS/security
  group misconfiguration patterns, since AWS-specific infrastructure misconfiguration
  has essentially no coverage on PortSwigger or standard HTB machines.

---

## 10. Real-World Notes

- Gateway bypass findings are disproportionately common in **whitebox and internal
  pentest engagements specifically** (as flagged in the overview requirements for
  this series) because blackbox external testers often never discover the
  bypassable infrastructure exists at all — it requires either internal network
  visibility or unusually thorough external recon (full port sweeps of discovered
  IP ranges, which many time-boxed blackbox engagements don't budget for).
- The `ports:` vs `expose:` Docker Compose distinction (Section 5.1) is an extremely
  common finding specifically in smaller organizations and MVP/early-stage products —
  worth prioritizing early in any assessment of a company you know is running a
  simpler Docker Compose deployment rather than full Kubernetes.
- Always test the *combination* of gateway bypass and weak mTLS/service auth
  together (Section 7.2) — reporting them as separate findings understates the real
  risk when both are present, since together they represent a complete absence of
  defense-in-depth rather than two independent weaknesses.

---

## 11. Cross-References

- See **File 1, Section 4.1–4.3** for the trust assumptions this file directly
  disproves.
- See **File 2** for the mTLS compensating control discussed in Section 7.1/7.2 above.
- See **File 3** for what to do once a gateway bypass lands you with internal network
  access — the two files are designed to be chained together.
- See the existing **API Gateway Security series** for the defensive/configuration
  side of this same infrastructure.
- See the existing **Linux server hardening** portfolio project for host-level port
  audit methodology referenced in Section 5.1.
