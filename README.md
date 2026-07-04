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
| 1 | **API Recon & Endpoint Discovery** | `01_API_Recon_Endpoint_Discovery/` | ⬜ | 🔴 | 🔴 | 🔬 | Everything else starts here — you can't test what you can't find. |
| 2 | **BOLA — Broken Object Level Authorization** | `02_BOLA_IDOR/` | ⬜ | 🔴 | 🔴 | 🔬 | #1 most common API finding globally. |
| 3 | **Broken Authentication** | `03_Broken_Authentication/` | ⬜ | 🔴 | 🔴 | 🔬 | Foundation for auth-related chains. |
| 4 | **JWT Attacks (deep dive)** | `04_JWT_Attacks/` | ⬜ | 🔴 | 🔴 | 🔬 | alg:none, RS256→HS256, JWK/kid injection. Increasingly common, high payout. |
| 5 | **OAuth 2.0 Attack Techniques** | `05_OAuth2_Attacks/` | ⬜ | 🔴 | 🔴 | 🔬 | Ubiquitous in modern APIs. |
| 6 | **BFLA** | `06_BFLA/` | ⬜ | 🔴 | 🔴 | 🔬 | Direct privilege escalation, pairs with BOLA for chaining. |
| 7 | **BOPLA (+ CSV/Formula Injection)** | `07_BOPLA/` | ⬜ | 🔴 | 🟡 | 🔬 | Mass assignment + excessive data exposure + CSV injection via data export. |
| 8 | **REST API Testing Methodology** | `08_REST_API_Testing/` | ⬜ | 🔴 | 🟡 | 📖 | Core methodology file, reference throughout. |
| 9 | **API Injection Testing** | `09_API_Injection/` | ⬜ | 🔴 | 🟡 | 📖 | SQLi/NoSQL/Command via JSON, includes WAF bypass section. |
| 10 | **HTTP/2 Attack Techniques** | `10_HTTP2_Attacks/` | ⬜ | 🔴 | 🟡 | 📖 | Rapid Reset, HTTP/2 downgrade smuggling, HPACK abuse — most gateways run HTTP/2. |
| 11 | **Unrestricted Resource Consumption** | `11_Unrestricted_Resource_Consumption/` | ⬜ | 🔴 | 🟡 | 📖 | Rate limiting absence, resource exhaustion. |
| 12 | **API Rate Limit & Bot Protection Bypass** | `12_Rate_Limit_Bypass/` | ⬜ | 🔴 | 🟡 | 📖 | Bypassing limits that DO exist. |
| 13 | **Race Conditions (API-specific)** | `13_Race_Conditions_API/` | ⬜ | 🔴 | 🔴 | 🔬 | High payout, trending heavily. Multi-step chain races, GraphQL batching races. |
| 14 | **GraphQL-Specific Attacks** | `14_GraphQL_Attacks/` | ⬜ | 🔴 | 🟡 | 🔬 | Completely separate methodology from REST. |
| 15 | **Business Flow Abuse** | `15_Business_Flow_Abuse/` | ⬜ | 🔴 | 🟡 | 📖 | Scalping, coupon stacking, referral farming at scale. |
| 16 | **SSRF (API-specific)** | `16_SSRF_API/` | ⬜ | 🔴 | 🟡 | 📖 | Via webhooks, cloud metadata via API-originated requests. |
| 17 | **Webhook Security** | `17_Webhook_Security/` | ⬜ | 🟡 | 🟡 | 📖 | SSRF via registration, signature bypass, replay attacks. |
| 18 | **API Key Security** | `18_API_Key_Security/` | ⬜ | 🟡 | 🟡 | 📖 | Leakage in git/JS, entropy, scope testing. |
| 19 | **Security Misconfiguration (API)** | `19_Security_Misconfiguration_API/` | ⬜ | 🟡 | 🟡 | 📖 | Exposed docs, CORS, verbose errors. |
| 20 | **API Gateway Security** | `20_API_Gateway_Security/` | ⬜ | 🔴 | 🟡 | 📖 | Gateway auth bypass, gateway rate limit bypass, gateway cache poisoning. |
| 21 | **Improper Inventory Management** | `21_Improper_Inventory_Management/` | ⬜ | 🟡 | 🟡 | 📖 | Shadow APIs, zombie endpoints, old versions. |
| 22 | **WebSocket API Security (+ SSE)** | `22_WebSocket_API_Security/` | ⬜ | 🟡 | 🟡 | 📖 | Message manipulation, auth bypass, plus Server-Sent Events. |
| 23 | **Unsafe Consumption of APIs** | `23_Unsafe_API_Consumption/` | ⬜ | 🟡 | ⚪ | 👁 | Trusting third-party API responses blindly. |
| 24 | **SOAP/XML API Attacks** | `24_SOAP_XML_Attacks/` | ⬜ | 🟡 | ⚪ | 👁 | XXE via SOAP, WS-Security bypass. Legacy/enterprise. |
| 25 | **gRPC & Protocol-Level Attacks** | `25_gRPC_Attacks/` | ⬜ | 🟡 | ⚪ | 👁 | Reflection, protobuf manipulation. Microservices-focused. |
| 26 | **Microservices & Service-to-Service Security** | `26_Microservices_Security/` | ⬜ | 🟡 | ⚪ | 👁 | mTLS, service impersonation, lateral movement. Internal engagements. |
| 27 | **API Automation & Tooling (+ httpx, katana, jq)** | `27_API_Automation_Tooling/` | ⬜ | 🔴 | 🔴 | 📖 | Read in parallel with all other topics. |
| 28 | **Real-World API Exploitation & Chaining (capstone)** | `28_Real_World_API_Chaining/` | ⬜ | 🔴 | 🔴 | 🔬 | Build LAST. All chain patterns, multi-role testing, Postman documentation, reporting. |

---

## How To Read the Priority Columns in Practice

**For pentest client engagements:**
Everything in the table above is 🔴 for pentest scope — if a client says "test our
API," you cover all 27 topics relevant to their stack. The pentest column is only
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
├── API_Fundamentals_Notes/                ← START HERE (prerequisite folder)
├── 01_API_Recon_Endpoint_Discovery/
├── 02_BOLA_IDOR/
├── 03_Broken_Authentication/
├── 04_JWT_Attacks/
├── 05_OAuth2_Attacks/
├── 06_BFLA/
├── 07_BOPLA/
├── 08_REST_API_Testing/
├── 09_API_Injection/
├── 10_HTTP2_Attacks/
├── 11_Unrestricted_Resource_Consumption/
├── 12_Rate_Limit_Bypass/
├── 13_Race_Conditions_API/
├── 14_GraphQL_Attacks/
├── 15_Business_Flow_Abuse/
├── 16_SSRF_API/
├── 17_Webhook_Security/
├── 18_API_Key_Security/
├── 19_Security_Misconfiguration_API/
├── 20_API_Gateway_Security/
├── 21_Improper_Inventory_Management/
├── 22_WebSocket_API_Security/
├── 23_Unsafe_API_Consumption/
├── 24_SOAP_XML_Attacks/
├── 25_gRPC_Attacks/
├── 26_Microservices_Security/
├── 27_API_Automation_Tooling/
└── 28_Real_World_API_Chaining/            ← capstone, build LAST
```
