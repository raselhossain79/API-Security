# Gateway Authentication Bypass & Backend Direct-Access Testing

## Trust Assumption Being Exploited

The gateway performs authentication once at the edge. The backend is
built on the assumption that **every request it receives has already been
authenticated by the gateway**, because in the intended architecture, the
backend is not reachable any other way. This assumption is an
infrastructure/network claim, not something the gateway itself can
enforce — the gateway has no control over whether the backend also has a
public listener. When that network assumption is false, the backend's
"authentication happens upstream" design becomes "authentication does not
happen at all" for anyone who can reach it directly.

This is the single highest-impact class of gateway vulnerability because it
does not require finding a flaw in the gateway's logic at all — it requires
finding that the gateway is *optional*.

---

## Part 1: Testing Whether the Backend Is Directly Reachable

### Step 1 — Identify the Backend's Real Address

The gateway hostname is not the backend's address; it is a public-facing
name that terminates at the gateway. To find what's behind it:

1. **DNS and certificate transparency.** Query `crt.sh` or similar CT log
   search for the target domain and its subdomains. Backend services are
   frequently given their own subdomain (`api-internal.example.com`,
   `users-svc.example.com`) even when not intended for public use, because
   internal DNS and public DNS are often the same zone in smaller
   organizations.
   ```
   crt.sh?q=%.example.com
   ```
2. **Cloud provider metadata leakage.** Error pages, redirect chains, or
   `Server`/`Via` response headers sometimes reveal internal hostnames or
   load balancer DNS names (e.g., AWS ELB default DNS
   `internal-xxx.us-east-1.elb.amazonaws.com` occasionally leaks in
   misconfigured CORS or redirect responses).
3. **Response header fingerprinting through the gateway.** Compare response
   headers on gateway-routed requests versus what the gateway itself is
   known to emit (Kong emits `Via: kong/x.x.x`, AWS API Gateway emits
   `x-amz-apigw-id` and `X-Amzn-Trace-Id`). If a request that should pass
   through the gateway is missing these headers, or a different route
   returns different backend fingerprints (e.g., different `Server` header
   values across routes), it can indicate direct-to-backend paths or
   inconsistent gateway coverage.
4. **Subdomain and port brute-forcing.** Standard recon (`subfinder`,
   `amass`, then `httpx` for live-host confirmation) against the apex
   domain, followed by a targeted port scan of any IPs discovered, looking
   for the same API surface exposed on non-standard ports without the
   gateway in front.
5. **Shodan/Censys search for the organization's known ASN or cloud
   account fingerprints.** Backend services with public IPs often get
   indexed even if never linked from anywhere public-facing.

### Step 2 — Confirm Direct Reachability

Once a candidate backend address is found:

1. Send the same authenticated request you'd normally send through the
   gateway, but target the backend address directly, **with the
   Authorization header removed entirely**.
2. Compare the response to what an unauthenticated request through the
   gateway returns (which should be a 401/403).
3. If the direct request to the backend succeeds (200 with real data)
   despite having no credential at all, the backend has no independent
   authentication — the gateway was the *only* authentication control, and
   it has just been bypassed entirely.

```
# Through gateway (expected: 401)
curl -i https://api.example.com/v2/users/123

# Direct to backend, no credential (if this returns 200, auth is fully bypassed)
curl -i https://users-svc-internal.example.com:8080/users/123
```

4. Even if the backend does perform some validation, test whether it
   trusts an internal header instead of real credentials (see file 06) —
   in many deployments the "authentication" the backend performs is
   actually just checking for the presence of a gateway-set header, which
   is trivially forgeable once you're talking to the backend directly.

### Step 3 — Cloud-Specific Checks

- **AWS API Gateway backed by an ALB/EC2/ECS backend**: check whether the
  target group's security group allows inbound traffic from anywhere
  (`0.0.0.0/0`) rather than being scoped to the API Gateway's VPC Link or a
  specific security group. This is directly inspectable if you have any
  read access to the AWS account (e.g., via a separate low-privilege
  compromise) and is a very common finding in cloud security assessments.
- **Kubernetes Ingress + Kong/Nginx Ingress Controller**: check whether the
  backend `Service` is only reachable via `ClusterIP` (correct — no direct
  external path) or has been given a `LoadBalancer` or `NodePort` type
  (incorrect — creates a second, unprotected entry point), and whether
  `NetworkPolicy` resources actually restrict ingress to the gateway pod's
  labels.
- **Apigee backed by on-prem or hybrid targets**: check whether the target
  endpoint is reachable from outside the intended network path — Apigee's
  own edge enforcement does nothing to protect a target server that is
  independently internet-facing.

---

## Part 2: Path-Based Routing Confusion Between Gateway and Backend

### Trust Assumption Being Exploited

The gateway's routing table encodes a mapping from public paths to backend
paths, and the gateway operator assumes the backend will *only* be reached
via paths that passed through this mapping. But the backend's own router
(Express routes, Spring `@RequestMapping`, Django URL patterns) doesn't
know or care about the gateway's mapping — it just matches whatever path
arrives at it. If the two routers disagree about path structure, a path
that the gateway considers "blocked," "not routed," or "routed to service
A" may resolve to a completely different, unintended backend resource once
it reaches the actual application router — especially when the backend is
directly reachable per Part 1.

### Step-by-Step Testing

1. **Enumerate the gateway's route table indirectly.** Send requests to
   likely internal-only paths through the gateway (`/internal/*`,
   `/admin/*`, `/debug/*`, `/actuator/*` for Spring backends,
   `/_status`, `/metrics`) and note which return a gateway-level 404
   (typically a generic gateway error page) versus a backend-level 404
   (typically an application-specific error format) — the latter indicates
   the gateway *did* forward the request, meaning that path isn't actually
   blocked, just unhandled by the backend.

2. **Test path normalization mismatches directly against the backend**
   (once direct access is confirmed per Part 1), by comparing how the
   gateway's routing decision would have differed:
   - Double slashes: `/api//admin/users` — some gateways normalize
     `//` to `/` before route matching; the backend framework may or may
     not, so a path the gateway would map to route A can be interpreted by
     the backend's router as an entirely different route.
   - Path traversal-style segments that survive gateway normalization but
     get resolved by the backend: `/api/v2/users/../admin/config`.
   - Trailing path segments used to smuggle past prefix-match rules:
     `/api/v2/public/../admin`.

3. **Test prefix-stripping assumptions.** If the gateway is configured to
   strip a prefix (e.g., `/api/v2` → forwarded as `/`), and the backend
   also has its own routes that don't expect the prefix to ever be
   present, sending the *unstripped* path directly to the backend (Part 1
   direct access) may hit a backend route that was never meant to be
   reachable under that path shape, because in the gateway-mediated world
   it would never arrive with the prefix intact.

4. **Test HTTP method discrepancies in routing.** Some gateways route
   based on path only and forward all methods to the same backend handler,
   while the backend's router differentiates by method. Conversely, some
   gateways enforce method-based route rules (e.g., only GET is proxied
   for a given path) while the backend accepts other methods on the same
   route. Confirm using direct-to-backend `OPTIONS`/`TRACE` probing to
   enumerate accepted methods the gateway never intended to expose.

---

## PortSwigger Lab Relevance

PortSwigger does not have dedicated API-gateway-product labs (no Kong/AWS
API Gateway sandbox). The closest conceptually relevant labs, useful for
practicing the *underlying* routing/trust-boundary reasoning even though
they're framed as web app labs, are cross-referenced from the Host Header
Injection and Broken Access Control notes in the web application series —
work through those first if you haven't:

- **Broken Access Control > Apprentice**: "Unprotected admin functionality"
  and "Unprotected admin functionality with unpredictable URL" — directly
  transferable to the "is the backend reachable at all" reasoning in Part 1.
- **Broken Access Control > Practitioner**: "URL-based access control can
  be circumvented" — this lab's core mechanic (a front-end control
  trusting a URL structure that the back-end interprets differently) is
  functionally identical to gateway/backend path routing confusion in
  Part 2, just implemented as a single application with a front controller
  instead of a separate gateway process. Map the lab's "front-end" to
  "gateway" and "back-end" to "backend service" mentally when working
  through it.

## Supplementary Practice (Vendor-Based, No PortSwigger Equivalent)

Since dedicated gateway-product labs don't exist on PortSwigger, build a
local lab:

1. **Kong OSS locally via Docker Compose** (official Kong quickstart) with
   a deliberately weak config: run a simple backend (e.g., a minimal
   Express or Flask app) *without* any auth of its own, put Kong in front
   with a `key-auth` or `jwt` plugin on select routes, then expose the
   backend's port directly in `docker-compose.yml` alongside Kong's port to
   simulate the "backend also has a public path" misconfiguration. Practice
   Part 1 and Part 2 against this.
2. **AWS API Gateway (HTTP API) backed by a Lambda or ALB target** in a
   sandbox AWS account, deliberately misconfigured with an overly permissive
   security group on the target, to practice Part 1's cloud-specific
   checks safely.

---

## Real-World Notes

- A recurring pattern in bug bounty reports against companies using AWS
  API Gateway with an ALB target: the ALB was provisioned with a public
  subnet and a security group allowing `0.0.0.0/0` on the listener port,
  because the team following a tutorial copied a security group meant for
  a public-facing resource without narrowing it to the API Gateway's VPC
  Link/NAT IP range.
- Kubernetes-based deployments frequently leak direct backend access
  through debug/staging Ingress resources that were added later by a
  different team and never routed through the same authentication gateway
  as the production Ingress, despite pointing at the same backend Service.
- Path normalization mismatches between Nginx-based gateways (which
  normalize `//` and `.` segments by default in most configurations) and
  Java/Spring backends (which historically had CVEs around path matching
  differences, e.g., matrix parameters and encoded slashes affecting
  Spring's `AntPathMatcher` vs the raw servlet path) have produced real
  CVEs in the Spring ecosystem — worth searching current CVE databases for
  the specific backend framework version in scope during an engagement.
