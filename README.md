# API Security — Complete Reference Notes

This directory covers API penetration testing from scratch — OWASP API Security Top 10
(2023) as the backbone, expanded with protocol-specific, auth-specific, and
methodology topics cross-checked against real-world pentest/bug-bounty practice.

**Scope note:** This is web/API security only. Mobile API testing (certificate pinning
bypass, APK reverse engineering) is out of scope here — that belongs in a dedicated
mobile security track.

---

## Why API Security is a Separate Directory

APIs are not just "web app with JSON." The attack surface is fundamentally different:
- Authorization flaws (BOLA/BFLA) dominate — not injection
- Authentication is token-based (JWT/OAuth/API keys), not session-cookie-based
- Protocol diversity: REST, GraphQL, gRPC, SOAP, WebSocket all need different
  testing approaches
- Rate limiting and business flow abuse are first-class findings, not afterthoughts
- Shadow/zombie endpoints and improper inventory are API-specific risks

The web app notes already cover injection (SQLi, XSS, SSTI, XXE etc) — those
techniques apply through API parameters too, but the testing methodology differs
enough that API security deserves its own structured track.

---

## ⭐ Learning Sequence, Priority & Depth Guidance

**Priority legend:**
- 🔴 **High** — extremely common finding in real engagements/bug bounty, non-negotiable
- 🟡 **Medium** — important, worth thorough coverage, may not appear on every target
- ⚪ **Low** — niche or protocol-specific, know it exists, don't over-invest early

**Depth legend:**
- 🔬 **Deep** — drill extensively, lab practice essential, high ROI
- 📖 **Thorough** — read fully, understand mechanism, some practice
- 👁 **Awareness** — know the concept and pattern, revisit when target specifically needs it

**Bug bounty vs pentest note:** For client pentest engagements you test everything in
scope regardless of priority — the client defines scope, you cover it. For bug bounty,
focus your active hunting time on 🔴 High topics; 🟡 and ⚪ topics are still worth
knowing but don't need the same repetition.

| # | Topic | Folder | Status | Pentest | Bug Bounty | Depth | Why |
|---|---|---|---|---|---|---|---|
| 1 | **API Recon & Endpoint Discovery** | `01_API_Recon_Endpoint_Discovery/` | ⬜ | 🔴 | 🔴 | 🔬 | Everything else starts here — you can't test what you can't find. Swagger leakage, JS mining, shadow endpoints. |
| 2 | **BOLA — Broken Object Level Authorization** | `02_BOLA_IDOR/` | ⬜ | 🔴 | 🔴 | 🔬 | #1 most common API finding globally (40%+ of API attacks). Every API endpoint with an ID is a candidate. |
| 3 | **Broken Authentication** | `03_Broken_Authentication/` | ⬜ | 🔴 | 🔴 | 🔬 | Token misuse, credential stuffing, missing MFA on sensitive endpoints. Foundation for almost every other finding. |
| 4 | **JWT Attacks (deep dive)** | `04_JWT_Attacks/` | ⬜ | 🔴 | 🔴 | 🔬 | alg:none, RS256→HS256 confusion, JWK injection, kid injection. Increasingly common, high payout. |
| 5 | **OAuth 2.0 Attack Techniques** | `05_OAuth2_Attacks/` | ⬜ | 🔴 | 🔴 | 🔬 | Authorization code interception, redirect_uri manipulation, state bypass, token leakage. Ubiquitous in modern APIs. |
| 6 | **BFLA — Broken Function Level Authorization** | `06_BFLA/` | ⬜ | 🔴 | 🔴 | 🔬 | Admin endpoints accessible by regular users. Missed by scanners. Direct privilege escalation. |
| 7 | **BOPLA — Broken Object Property Level Authorization** | `07_BOPLA/` | ⬜ | 🔴 | 🟡 | 🔬 | Covers Excessive Data Exposure + Mass Assignment combined. Overly verbose responses, hidden writable fields. |
| 8 | **REST API-Specific Testing Methodology** | `08_REST_API_Testing/` | ⬜ | 🔴 | 🟡 | 📖 | HTTP method abuse, versioning attacks (/v1/ vs /v2/), parameter fuzzing methodology, response differential analysis. Core methodology file. |
| 9 | **API Injection Testing** | `09_API_Injection/` | ⬜ | 🔴 | 🟡 | 📖 | SQLi/NoSQL/Command injection via JSON bodies, GraphQL fields, different content types. Different delivery from web app but same underlying vulns. |
| 10 | **Unrestricted Resource Consumption** | `10_Unrestricted_Resource_Consumption/` | ⬜ | 🔴 | 🟡 | 📖 | Rate limiting absence, resource exhaustion, no pagination limits. Enabler for brute force, DoS, scraping abuse. |
| 11 | **API Rate Limit & Bot Protection Bypass** | `11_Rate_Limit_Bypass/` | ⬜ | 🔴 | 🟡 | 📖 | X-Forwarded-For rotation, header-based IP spoofing, distributed request techniques. Goes deeper than basic rate limit absence testing. |
| 12 | **GraphQL-Specific Attacks** | `12_GraphQL_Attacks/` | ⬜ | 🔴 | 🟡 | 🔬 | Introspection abuse, query batching/alias rate-limit bypass, depth attacks, field suggestion leakage, resolver authorization. Completely different from REST — needs its own methodology. |
| 13 | **Unrestricted Access to Sensitive Business Flows** | `13_Business_Flow_Abuse/` | ⬜ | 🔴 | 🟡 | 📖 | Automation abuse of business logic — ticket scalping, coupon stacking, referral farming, account enumeration at scale. |
| 14 | **SSRF (API-specific)** | `14_SSRF_API/` | ⬜ | 🔴 | 🟡 | 📖 | SSRF via API URL parameters, webhook URL abuse, cloud metadata via API-originated requests. Cross-reference with web app SSRF notes for bypass techniques. |
| 15 | **Webhook Security** | `15_Webhook_Security/` | ⬜ | 🟡 | 🟡 | 📖 | SSRF via webhook registration, signature validation bypass, replay attacks, parameter tampering via webhook payload. Increasingly common in SaaS/integration-heavy targets. |
| 16 | **API Key Security** | `16_API_Key_Security/` | ⬜ | 🟡 | 🟡 | 📖 | Key leakage in JS/git repos/responses, entropy testing, key scope/permission testing, rotation gap testing. |
| 17 | **Security Misconfiguration (API-specific)** | `17_Security_Misconfiguration_API/` | ⬜ | 🟡 | 🟡 | 📖 | Exposed Swagger/OpenAPI docs, debug endpoints, CORS wide-open, unnecessary HTTP methods, verbose error messages leaking internals. |
| 18 | **Improper Inventory Management** | `18_Improper_Inventory_Management/` | ⬜ | 🟡 | 🟡 | 📖 | Shadow APIs, zombie/deprecated endpoints (/v1/ still live when /v3/ is current), undocumented endpoints. Overlaps with recon but deeper focus on version/lifecycle exploitation. |
| 19 | **WebSocket API Security** | `19_WebSocket_API_Security/` | ⬜ | 🟡 | 🟡 | 📖 | WebSocket message manipulation, injection via WebSocket, auth bypass via handshake, cross-site WebSocket hijacking in API context. Different from CSWSH in web app notes — API-specific testing methodology. |
| 20 | **Unsafe Consumption of APIs** | `20_Unsafe_API_Consumption/` | ⬜ | 🟡 | ⚪ | 👁 | Trusting third-party API responses blindly — supply chain risk via API. Less common as a standalone bounty finding. |
| 21 | **SOAP/XML API Attacks** | `21_SOAP_XML_Attacks/` | ⬜ | 🟡 | ⚪ | 👁 | XXE via SOAP, WS-Security bypass. Relevant for legacy/enterprise engagements. Rare in modern public bug bounty programs. |
| 22 | **gRPC & Protocol-Level Attacks** | `22_gRPC_Attacks/` | ⬜ | 🟡 | ⚪ | 👁 | gRPC reflection, protobuf manipulation, service enumeration. Increasingly common in microservices but still niche in typical bug bounty scope. |
| 23 | **Microservices & Service-to-Service Security** | `23_Microservices_Security/` | ⬜ | 🟡 | ⚪ | 👁 | Internal service auth (mTLS, service mesh), service impersonation, lateral movement via internal APIs. Pentest-relevant when scope includes internal architecture. Rare in bug bounty. |
| 24 | **API Automation & Tooling** | `24_API_Automation_Tooling/` | ⬜ | 🔴 | 🔴 | 📖 | Postman/Newman, ffuf for API fuzzing, Arjun (parameter discovery), kiterunner (endpoint bruteforce), nuclei API templates, jwt_tool, Burp extensions for API testing. Read this in parallel with other notes as you build your workflow. |

---

## How To Read the Priority Columns in Practice

**For pentest client engagements:**
Everything in the table above is 🔴 for pentest scope — if a client says "test our
API," you cover all 24 topics relevant to their stack. The pentest column is only
🟡 for topics that are stack-specific (you don't test gRPC if there's no gRPC).

**For bug bounty:**
- 🔴 Bug bounty = actively hunt for this on every API target
- 🟡 Bug bounty = test if you encounter it naturally, don't specifically time-box here
- ⚪ Bug bounty = skip unless the target specifically uses this tech (SOAP endpoint,
  gRPC service, microservices internal scope)

**On depth:**
- 🔬 Deep = do dedicated lab practice (crAPI, DVAPI, HackTheBox API challenges) —
  not just read the notes
- 📖 Thorough = read fully, understand every mechanism, minimal lab time needed
- 👁 Awareness = one read-through is enough; you'll revisit this file when a target
  calls for it

---

## Recommended Practice Environments

| Platform | What it covers |
|---|---|
| **crAPI** (OWASP's deliberately vulnerable API) | BOLA, BFLA, BOPLA, rate limiting, business logic — best starting point |
| **DVAPI** (Damn Vulnerable API) | Similar to crAPI, slightly different vuln set |
| **HackTheBox API challenges** | Real-world-style black-box API testing |
| **PortSwigger Web Security Academy** | Has relevant labs for JWT attacks, OAuth, WebSocket, CORS — referenced in individual files |
| **Public bug bounty programs** (HackerOne, Bugcrowd) | Real-world practice once foundational topics are solid |

---

## Directory Structure

```
API_Security_Notes/
├── README.md                              ← you are here
├── 01_API_Recon_Endpoint_Discovery/
├── 02_BOLA_IDOR/
├── 03_Broken_Authentication/
├── 04_JWT_Attacks/
├── 05_OAuth2_Attacks/
├── 06_BFLA/
├── 07_BOPLA/
├── 08_REST_API_Testing/
├── 09_API_Injection/
├── 10_Unrestricted_Resource_Consumption/
├── 11_Rate_Limit_Bypass/
├── 12_GraphQL_Attacks/
├── 13_Business_Flow_Abuse/
├── 14_SSRF_API/
├── 15_Webhook_Security/
├── 16_API_Key_Security/
├── 17_Security_Misconfiguration_API/
├── 18_Improper_Inventory_Management/
├── 19_WebSocket_API_Security/
├── 20_Unsafe_API_Consumption/
├── 21_SOAP_XML_Attacks/
├── 22_gRPC_Attacks/
├── 23_Microservices_Security/
└── 24_API_Automation_Tooling/
```

---
