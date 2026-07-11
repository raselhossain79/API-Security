# Microservices Security Testing

A focused note series on **service-to-service communication security** within
microservices architectures — internal API attack surface, service authentication
(mTLS and JWT service tokens), service impersonation, lateral movement, and API
gateway bypass.

This series is written for penetration testers and security researchers, and follows
the same conventions as the rest of this note library: mechanism-first explanations,
step-by-step technique breakdowns with the underlying trust assumption named
explicitly, PortSwigger Web Security Academy lab mappings in
Apprentice → Practitioner → Expert order with honest coverage-gap disclosure, and
supplementary practice environments (crAPI, HackTheBox, TryHackMe) referenced where
PortSwigger coverage is insufficient.

## Scope Note

Microservices internal-communication security testing is primarily an **internal and
whitebox pentest discipline**, not a blackbox web application testing discipline.
PortSwigger Web Security Academy has minimal direct coverage of this topic because its
lab format is single-application/single-origin by design and doesn't model
multi-service trust boundaries. Each file states explicitly where PortSwigger mapping
applies, where it's only conceptually adjacent, and where there is a genuine coverage
gap — rather than forcing a loose mapping. HackTheBox Pro Labs and internal-network-
focused TryHackMe rooms are used throughout as the primary supplementary practice,
since they model real multi-host/multi-service environments that PortSwigger doesn't.

## Files in This Series

| # | File | Covers |
|---|------|--------|
| 1 | [01_Microservices_Architecture_Attack_Surface.md](01_Microservices_Architecture_Attack_Surface.md) | Why microservices expand internal API attack surface, external vs. internal communication differences, the six trust assumptions microservices commonly make and why each is dangerous |
| 2 | [02_mTLS_Service_Authentication_Testing.md](02_mTLS_Service_Authentication_Testing.md) | mTLS mechanics and testing methodology (enforcement, chain validation, identity/SAN checking, expiry/revocation), JWT-based service tokens and service-to-service-specific weaknesses (audience confusion, static shared tokens, missing expiry, user/service token confusion) |
| 3 | [03_Service_Impersonation_Lateral_Movement.md](03_Service_Impersonation_Lateral_Movement.md) | Testing internal endpoints for missing authorization, a full step-by-step SSRF-to-internal-service-impersonation walkthrough, systematic internal service enumeration and lateral movement methodology |
| 4 | [04_API_Gateway_Bypass.md](04_API_Gateway_Bypass.md) | Reaching internal services without transiting the API gateway — Kubernetes (NodePort/LoadBalancer misuse, Ingress path misconfiguration, missing NetworkPolicy, direct pod access), ECS (security group scoping, ALB listener rules, Cloud Map), and Docker Compose (`ports:` vs `expose:`, default bridge network) misconfiguration patterns |
| 5 | [05_Final_Checklist.md](05_Final_Checklist.md) | Consolidated, phase-organized testing checklist across all four files, with reporting guidance and engagement-type (external/blackbox vs. internal/whitebox) planning notes |

## WAF / API Gateway Relevance

Per the requirements of this series, WAF/API Gateway-level detection and bypass
considerations are addressed **specifically where they are meaningfully relevant**,
rather than added uniformly to every file:

- **File 1** — explicitly states why WAF/gateway defenses are not directly relevant
  to the architectural/conceptual content of that file, and points to Files 3 and 4
  where they are.
- **File 2** — brief note on why mTLS/service tokens operate largely outside typical
  WAF visibility (transport layer / internal application layer), with the one
  relevant intersection (gateway policy substituting for mTLS) flagged.
- **File 3** — full dedicated section: SSRF detection methods (payload pattern
  matching, DNS rebinding protection, egress anomaly detection, outbound
  allowlisting) and realistic bypass considerations (alternate IP encodings, DNS
  rebinding, redirect chaining, and the inherent difficulty of signature-matching
  internal service hostnames).
- **File 4** — full dedicated section: this file's entire subject is gateway-defense
  bypass, covering infrastructure-level prevention controls, traffic-source anomaly
  detection, mTLS as a compensating control, and the central realistic-bypass point
  that gateway-bypass traffic is often invisible to the detection stack entirely,
  since it never transits the gateway.

## Suggested Reading Order

Read in file order (1 → 5). File 1 establishes the trust-assumption vocabulary used
throughout Files 2–4; File 3's SSRF walkthrough and File 4's gateway bypass content
are designed to be chained together in a real engagement (a successful gateway bypass
or SSRF pivot in either file typically hands you the internal network position needed
to apply File 2 and File 3's remaining tests). File 5 is a working reference to use
during an actual engagement rather than a first-read document.

## Cross-References to Other Series in This Library

This series assumes familiarity with, and cross-references rather than duplicates:

- **SSRF series** — full payload technique and filter-bypass detail underlying
  File 3's walkthrough
- **JWT series** — foundational JWT attack mechanics underlying File 2's
  service-token section
- **API Gateway Security series** — defensive/configuration-side content
  complementing File 4's offensive testing methodology
- **HTTP/2 and HTTP Request Smuggling note packages** — conceptually adjacent to
  File 4's gateway bypass theme from a protocol-level angle
- **Subdomain takeover/recon series** — reconnaissance methodology underlying
  File 4's public-hostname enumeration steps
- **Linux server hardening portfolio project** — host-level port audit methodology
  referenced in File 4's Docker section
- **gRPC security series** — relevant where internal service-to-service
  communication uses gRPC rather than REST (noted in File 1, Section 3.1)

## Author

Rasel Hossain — 4xpl0it Security
GitHub: [raselhossain79](https://github.com/raselhossain79)
