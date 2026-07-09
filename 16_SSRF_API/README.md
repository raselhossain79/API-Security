# API SSRF (Server-Side Request Forgery) — Security Notes

Part of the API Security note series. This series covers SSRF specifically in the
context of APIs — how it is delivered, where it appears, and how it chains with other
API vulnerabilities. General SSRF technique and bypass methods (blacklist bypass,
whitelist bypass, DNS rebinding, IP obfuscation encodings, redirect-based filter
bypass, protocol smuggling) are covered in the separate **Web Application Security —
SSRF** series and are cross-referenced from here rather than duplicated.

## File Index

| # | File | Covers |
|---|------|--------|
| 1 | `01-overview-api-ssrf-context.md` | What makes API SSRF distinct from web app SSRF; delivery surface; WAF/API gateway applicability statement for this series |
| 2 | `02-webhook-callback-url-ssrf.md` | URL-accepting API parameters (webhooks, avatars, document fetch, import, callbacks); recon methodology; third-party integration SSRF |
| 3 | `03-cloud-metadata-exploitation.md` | AWS IMDSv1/IMDSv2, GCP, Azure metadata endpoint exploitation via API-originated SSRF |
| 4 | `04-blind-ssrf-api-context.md` | Burp Collaborator workflow for API-triggered OOB SSRF, piece-by-piece; post-confirmation actions |
| 5 | `05-internal-service-pivot.md` | Using API SSRF to reach internal APIs, databases, admin interfaces |
| 6 | `06-cheatsheet-lab-mapping.md` | Consolidated cheatsheet and full PortSwigger lab sequence (Apprentice → Practitioner → Expert) |

## Conventions Used in This Series

- Mechanism-first explanation before technique.
- Every payload and every Collaborator workflow step is broken down piece by piece —
  what each URL component is, and what the server-side request actually retrieves.
- WAF / API Gateway relevance is addressed explicitly in every file, including an
  explicit statement in the overview on where it does and does not meaningfully apply
  to this specific vulnerability class.
- PortSwigger Web Security Academy labs are mapped in strict Apprentice →
  Practitioner → Expert order, with honest disclosure of any coverage gaps for the
  API-specific angle.
- crAPI is noted as supplementary practice where it fills API-specific gaps that
  PortSwigger labs (which are web-app framed) do not cover.
- Cross-references point to sibling series (general SSRF, BOLA, BFLA, SSRF-adjacent
  API series) instead of repeating their content.
- Full English only, no exceptions.

## Prerequisite / Related Series

- **Web Application Security — SSRF** (general technique, bypass methods, protocol
  handlers) — read first if unfamiliar with core SSRF mechanics.
- **API Reconnaissance** — for endpoint/parameter discovery methodology referenced in
  file 2.
- **API6: Unrestricted Access to Sensitive Business Flows** — for business-flow abuse
  patterns that sometimes co-occur with import/webhook SSRF.
- **API4: Unrestricted Resource Consumption** — relevant when SSRF is used to trigger
  repeated outbound fetches as a resource-exhaustion vector.
