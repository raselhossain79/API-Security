# API Security Practice Roadmap

This file tells you **where to practice** each topic in the API notes repo and **in what order** to follow.

## Rules

1. Read the topic notes first, then do the labs, then write a writeup using `Practice_Methodology_Notes/01_Writeup_Template.md`.
2. Finish the web SQLi, access control, auth, JWT, and SSRF topics before starting the matching API topics. The API notes build on them.
3. Use Postman for mapping the API, Burp Suite for attacking it.
4. Keep every lab as a Postman collection or Burp project so you can reuse it.
5. Update the progress table at the bottom after each topic.

## Platforms

| Short name | Platform | Best for |
|---|---|---|
| crAPI | OWASP crAPI (local, Docker) | BOLA, BFLA, BOPLA, auth, mass assignment, SSRF, rate limit, chaining |
| VAmPI | Vulnerable REST API (local) | SQLi, BOLA, mass assignment, JWT, unauthenticated access |
| vAPI | vAPI by Roni Lugasi (local) | OWASP API Top 10 scenarios |
| JS | OWASP Juice Shop (local) | REST API issues, JWT, NoSQL, broken access control |
| DVGA | Damn Vulnerable GraphQL Application (local) | GraphQL attacks |
| PS | PortSwigger Web Security Academy | API testing, GraphQL, JWT, OAuth, WebSockets, SSRF, race conditions |
| Local | Build your own small service | SOAP, gRPC, webhooks, gateway, microservices |
| GH | Vulnerable lab repos on GitHub | SOAP, gRPC, microservices |

Setup first: install Docker, run crAPI, VAmPI, vAPI and DVGA, import their Postman collections.

---

## Phase 0: Foundation

| Order | Repo folder | Where to practice |
|---|---|---|
| 0.1 | `00_API_Fundamentals_Notes` | PS: API testing intro, set up Postman and Burp together on crAPI |
| 0.2 | `Practice_Methodology_Notes` | Read fully |
| 0.3 | `27_API_Automation_Tooling` (read the setup parts) | Install tools: ffuf, Kiterunner, Arjun, Autorize, jwt_tool, Nuclei |

## Phase 1: Recon and core authorization (most important)

| Order | Topic | Primary platform | Extra practice |
|---|---|---|---|
| 1 | 01 API Recon and Endpoint Discovery | crAPI, VAmPI, PS: API testing (documentation, hidden endpoints) | vAPI |
| 2 | 02 BOLA / IDOR | crAPI, vAPI | VAmPI, JS, PS: access control |
| 3 | 06 BFLA | crAPI, vAPI | JS |
| 4 | 07 BOPLA (excessive data exposure, mass assignment) | crAPI, VAmPI | PS: API testing mass assignment lab |
| 5 | 03 Broken Authentication | crAPI, VAmPI | PS: Authentication |
| 6 | 04 JWT Attacks | PS: JWT labs | VAmPI, JS, crAPI |
| 7 | 05 OAuth 2 Attacks | PS: OAuth labs | local OAuth test app |

## Phase 2: Core API testing techniques

| Order | Topic | Primary platform | Extra practice |
|---|---|---|---|
| 8 | 08 REST API Testing | crAPI, VAmPI | PS: API testing |
| 9 | 09 API Injection | VAmPI (SQLi), JS (NoSQL), crAPI | PS: SQLi, NoSQL, SSTI, XXE, command injection |
| 10 | 16 SSRF in APIs | crAPI | PS: SSRF |
| 11 | 17 Webhook Security | Build a small local webhook receiver and sender | crAPI webhook-like features |
| 12 | 18 API Key Security | Search your own test repos with TruffleHog and Gitleaks | GitHub public repos for educational recon only |

## Phase 3: Abuse, limits, and logic

| Order | Topic | Primary platform | Extra practice |
|---|---|---|---|
| 13 | 11 Unrestricted Resource Consumption | crAPI, vAPI | local test API |
| 14 | 12 Rate Limit Bypass | crAPI, vAPI | PS: Authentication brute-force protection labs |
| 15 | 13 Race Conditions in APIs | PS: Race conditions | crAPI (coupon and transaction flows) |
| 16 | 15 Business Flow Abuse | crAPI | PS: Business logic vulnerabilities |
| 17 | 21 Improper Inventory Management | crAPI, vAPI | PS: API testing (versions, hidden endpoints) |
| 18 | 19 Security Misconfiguration in APIs | crAPI, VAmPI, JS | PS: Information disclosure |
| 19 | 23 Unsafe API Consumption | Build a small app that consumes a third-party API you control | none |

## Phase 4: Protocols and architecture

| Order | Topic | Primary platform | Extra practice |
|---|---|---|---|
| 20 | 14 GraphQL Attacks | DVGA | PS: GraphQL API vulnerabilities |
| 21 | 22 WebSocket API Security | PS: WebSockets | JS |
| 22 | 10 HTTP/2 Attacks | PS: Request smuggling (HTTP/2 labs) | local h2 test server |
| 23 | 24 SOAP / XML Attacks | GH vulnerable SOAP labs | local SOAP service |
| 24 | 25 gRPC Attacks | GH vulnerable gRPC labs | local gRPC service with reflection on |
| 25 | 20 API Gateway Security | Local gateway (Kong or NGINX) with a test backend | none |
| 26 | 26 Microservices Security | Local docker-compose microservices lab | GH repos |

## Phase 5: Tooling and chaining

| Order | Topic | Where to practice |
|---|---|---|
| 27 | 27 API Automation Tooling (full) | Re-run the tools against crAPI, vAPI, VAmPI |
| 28 | 28 Real World API Chaining | Full crAPI takeover chains, multi-role testing, Postman chain documentation, one complete API report |

---

## Suggested pairing with web practice

| Web topic done | Then do API topic |
|---|---|
| SQLi, NoSQL, SSTI, XXE, command injection | 09 API Injection |
| Access control | 02 BOLA, 06 BFLA |
| Auth, JWT, OAuth | 03, 04, 05 |
| SSRF | 16 SSRF in APIs |
| Race conditions | 13 Race Conditions in APIs |
| Mass assignment | 07 BOPLA |

## Legal reminder

Only test local labs, your own services, or targets explicitly in scope of an authorized program or engagement.

## Progress tracker

| Topic | Notes read | Labs done | Writeups done | Postman collection saved | Date finished |
|---|---|---|---|---|---|
| 01 Recon | [ ] | [ ] | [ ] | [ ] | |
| 02 BOLA | [ ] | [ ] | [ ] | [ ] | |
| 06 BFLA | [ ] | [ ] | [ ] | [ ] | |
| 07 BOPLA | [ ] | [ ] | [ ] | [ ] | |
| 03 Broken Auth | [ ] | [ ] | [ ] | [ ] | |
| 04 JWT | [ ] | [ ] | [ ] | [ ] | |
| 05 OAuth2 | [ ] | [ ] | [ ] | [ ] | |
| 08 REST Testing | [ ] | [ ] | [ ] | [ ] | |
| 09 API Injection | [ ] | [ ] | [ ] | [ ] | |
| 16 SSRF | [ ] | [ ] | [ ] | [ ] | |
| 17 Webhook | [ ] | [ ] | [ ] | [ ] | |
| 18 API Keys | [ ] | [ ] | [ ] | [ ] | |
| 11 Resource Consumption | [ ] | [ ] | [ ] | [ ] | |
| 12 Rate Limit Bypass | [ ] | [ ] | [ ] | [ ] | |
| 13 Race Conditions | [ ] | [ ] | [ ] | [ ] | |
| 15 Business Flow Abuse | [ ] | [ ] | [ ] | [ ] | |
| 21 Inventory Management | [ ] | [ ] | [ ] | [ ] | |
| 19 Misconfiguration | [ ] | [ ] | [ ] | [ ] | |
| 23 Unsafe Consumption | [ ] | [ ] | [ ] | [ ] | |
| 14 GraphQL | [ ] | [ ] | [ ] | [ ] | |
| 22 WebSocket | [ ] | [ ] | [ ] | [ ] | |
| 10 HTTP/2 | [ ] | [ ] | [ ] | [ ] | |
| 24 SOAP | [ ] | [ ] | [ ] | [ ] | |
| 25 gRPC | [ ] | [ ] | [ ] | [ ] | |
| 20 API Gateway | [ ] | [ ] | [ ] | [ ] | |
| 26 Microservices | [ ] | [ ] | [ ] | [ ] | |
| 27 Tooling | [ ] | [ ] | [ ] | [ ] | |
| 28 Chaining | [ ] | [ ] | [ ] | [ ] | |
