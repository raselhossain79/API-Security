# Microservices Security Testing — Final Checklist

## 1. How to Use This Checklist

This checklist consolidates every testable item from Files 1–4 into a single working
document for use during an actual engagement. It is organized by testing phase, not
by file, since a real assessment moves fluidly between these categories rather than
working through them in strict document order. Each item references the file/section
where the full methodology is explained.

Use this as your engagement tracking sheet — check items off as tested, and record
findings with the specific trust assumption exploited (per the reporting guidance
repeated throughout Files 1–4), not just a generic vulnerability label.

---

## 2. Phase 1 — Reconnaissance and Architecture Mapping

- [ ] Identify all externally-facing entry points (API gateway, public load balancers,
      public DNS records for any subdomain) — *File 1, Section 2*
- [ ] Enumerate subdomains for internal-sounding hostnames that may be unintentionally
      public — *File 4, Section 3.2*
- [ ] Check certificate transparency logs for internal hostnames leaked via TLS
      certificates issued for internal services — *File 4, Section 3.2*
- [ ] If whitebox/internal access is available, map the intended architecture from
      documentation/diagrams before testing — *File 4, Section 6*
- [ ] Identify which protocols are in use (REST, gRPC, GraphQL federation, message
      queues) — don't assume REST-only — *File 1, Section 3.1*
- [ ] Note whether the engagement is scoped as external/blackbox (gateway bypass and
      SSRF-pivot techniques are primary) or internal/whitebox (full internal API
      testing is in scope from the start) — *File 1, Section 2.3*

## 3. Phase 2 — API Gateway Bypass Testing

- [ ] Port scan any discovered infrastructure IPs for NodePort-range
      (30000–32767) or unexpected open ports — *File 4, Section 3.1*
- [ ] Enumerate Kubernetes `Service` objects for type `NodePort`/`LoadBalancer`
      applied to internal-sounding services (whitebox) — *File 4, Section 3.1*
- [ ] Probe the public-facing hostname for internal-sounding paths
      (`/internal/`, `/admin/`, `/actuator/`, `/metrics`) — *File 4, Section 3.2*
- [ ] Check for a `NetworkPolicy` (Kubernetes) restricting pod-to-pod traffic;
      confirm default-permissive behavior if absent — *File 4, Section 3.3*
- [ ] Enumerate ECS task security groups for overly broad inbound rules
      (`0.0.0.0/0` or broad VPC CIDR instead of gateway-only) — *File 4, Section 4.1*
- [ ] Check ALB listener rules for inconsistent auth requirements across target
      groups — *File 4, Section 4.2*
- [ ] Full port sweep (`nmap -p-`) of any Docker host IPs for services published via
      `ports:` that should only use `expose:` — *File 4, Section 5.1*
- [ ] Confirm whether Docker default bridge network allows unrestricted
      inter-container reachability — *File 4, Section 5.2*
- [ ] For every open/reachable internal port found: confirm it actually processes
      requests (not just TCP-open) before rating severity — *File 4, Section 6*

## 4. Phase 3 — SSRF-to-Internal-Pivot Testing

- [ ] Identify any functionality that fetches a user-supplied URL server-side
      (avatar import, link preview, webhook test, PDF/image generation from URL) —
      *File 3, Section 3, Step 1*
- [ ] Confirm SSRF with cloud metadata endpoint (`169.254.169.254`) or loopback probe
      — *File 3, Section 3, Step 1*
- [ ] Enumerate internal service DNS names via the SSRF
      (`<service>.<namespace>.svc.cluster.local`, `.internal`) —
      *File 3, Section 3, Step 2*
- [ ] Probe for exposed internal API documentation (`/swagger.json`, `/openapi.json`)
      and Spring Boot Actuator endpoints (`/actuator/mappings`, `/actuator/env`) via
      the SSRF — *File 3, Section 3, Step 3*
- [ ] Test discovered internal endpoints for unauthenticated state-changing actions —
      *File 3, Section 3, Step 4*
- [ ] Confirm actual impersonation (state change observed), not just reachability —
      *File 3, Section 3, Step 5*
- [ ] Test SSRF filter bypass techniques if a blacklist/whitelist filter is present:
      alternate IP encodings, DNS rebinding, open-redirect chaining —
      *File 3, Section 5.2*

## 5. Phase 4 — Lateral Movement (from any internal foothold)

- [ ] Build a full internal service inventory by sweeping common service names and
      namespace variations — *File 3, Section 4.1*
- [ ] Prioritize targets: payment/billing → auth/identity → admin →
      config-service → user-service → logging/notification —
      *File 3, Section 4.2*
- [ ] Check `config-service`/Spring Cloud Config-style services for leaked
      credentials/API keys usable against higher-value services —
      *File 3, Section 4.3*
- [ ] Check `logging-service` for leaked tokens or internal API details in
      request/response logs — *File 3, Section 4.3*
- [ ] Confirm whether network segmentation actually restricts your pivot point's
      reach, or whether it's flat/default-allow — *File 3, Section 4.4*

## 6. Phase 5 — mTLS Testing (requires internal network position)

- [ ] Attempt plain TLS connection without a client certificate — is mTLS enforced
      at all? — *File 2, Section 3.1*
- [ ] Attempt connection with a self-signed cert not issued by the trusted internal
      CA — is chain validation genuinely enforced? — *File 2, Section 3.2*
- [ ] If you can obtain a validly-signed low-privilege service cert, test it against
      a high-privilege service — is identity/SAN checked, or just chain validity? —
      *File 2, Section 3.3*
- [ ] Test expired and (if determinable) revoked certificates for proper rejection —
      *File 2, Section 3.4*
- [ ] Check for Istio `PeerAuthentication` (or equivalent) left in `PERMISSIVE` mode
      — *File 2, Section 8*

## 7. Phase 6 — Service Token (JWT) Testing

- [ ] Apply standard JWT attack technique (cross-reference JWT series):
      `alg:none`, weak secret, `jwk`/`jku`/`kid` header injection, algorithm confusion
- [ ] Test whether the `aud` claim is validated — replay a token issued for one
      service against a different service — *File 2, Section 4.2.1*
- [ ] Check whether a single static/shared service token is used across all services
      (test by reading env vars/mounted secrets from any compromised container) —
      *File 2, Section 4.2.2*
- [ ] Decode any obtained service token and check `exp` — is it absent or
      excessively long-lived? — *File 2, Section 4.2.3*
- [ ] If user JWTs are forwarded downstream, test whether internal services perform
      their own signature verification or blindly trust forwarded claims —
      *File 2, Section 4.2.4*

## 8. Phase 7 — Service Impersonation / Authorization Testing

For every internal endpoint reached (via any of the above phases), check in order:

- [ ] Is there any authentication check at all? — *File 3, Section 2.1(1)*
- [ ] If a token/header check exists, does it validate a real credential or just
      presence/non-emptiness? — *File 3, Section 2.1(2)*
- [ ] If identity is validated, is there a *separate* authorization check for the
      specific action, or does valid identity alone grant the action? —
      *File 3, Section 2.1(3)*
- [ ] Is trust based only on source IP/CIDR allowlisting? —
      *File 3, Section 2.1(4)*

## 9. Phase 8 — WAF/Gateway-Specific Considerations

- [ ] Confirm whether traffic reaching internal services via gateway bypass (Phase 2)
      is visible to any WAF/detection tooling at all, or bypasses it entirely —
      *File 4, Section 7.1–7.2*
- [ ] Test SSRF payloads against WAF detection: literal internal IPs (likely
      blocked) vs. internal service hostnames (likely not signature-matched) —
      *File 3, Section 5.1–5.2*
- [ ] If mTLS is present, explicitly test it as a compensating control after a
      successful gateway bypass — does bypass alone grant access, or is mTLS still
      enforced independently? — *File 4, Section 7.2*

## 10. Reporting Guidance

For every finding, state explicitly:

1. **What was reached** (specific endpoint/service)
2. **What trust assumption was relied upon** by the vulnerable component (reference
   the specific File 1, Section 4.x assumption)
3. **What request/technique disproved that assumption** (exact request, not just a
   description)
4. **What the realistic blast radius is** — for microservices findings specifically,
   this often means naming which *other* services become reachable/compromisable as
   a result, since containment (or lack thereof) is usually the core of the finding's
   severity, not the initial access point alone.
5. **Which File 2 (mTLS/service auth) or Section 7 (WAF/gateway) compensating
   controls were absent** that would have limited the impact even if the initial
   entry point couldn't be fully remediated.

---

## 11. Engagement-Type Notes

- **External/blackbox engagements:** Phases 1–3 (recon, gateway bypass via public
  probing, SSRF pivot) are your primary path in. Phases 4–7 become available only
  after Phase 3 succeeds.
- **Internal/whitebox engagements:** all phases are in scope from the start; skip
  directly to Phases 4–7 once architecture mapping (Phase 1) is complete, and treat
  Phase 2/3 as supplementary rather than the primary path.
- As emphasized throughout this series: **microservices internal-communication
  testing is primarily an internal/whitebox pentest discipline.** If you're doing
  external/blackbox work only, expect Phases 4–7 to be reachable only via a
  successful Phase 2 or 3 pivot, not directly testable — plan engagement time
  accordingly and set client expectations if scoped as blackbox-only.
