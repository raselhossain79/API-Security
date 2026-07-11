# API Security Testing — Automation and Tooling: Overview & Tool Selection Guide

## Purpose of This Series

This series is a tooling reference that sits underneath the 23 other API security
topic series in this note library (OWASP API Top 10, GraphQL, JWT, OAuth, SOAP/XML,
WebSocket/SSE, SSRF, webhooks, API keys, race conditions, API gateways, gRPC, etc.).
Those series explain *vulnerability classes* and *methodology*. This series explains
the *tools* used to find, fuzz, exploit, and automate discovery of those
vulnerabilities, with every command broken down flag by flag — the same depth as the
sqlmap file in the SQL injection notes.

Read this file first. It tells you which tool to reach for at each stage of an API
engagement, and links to the dedicated file where that tool is broken down in full.

## A Note on WAF/API Gateway Bypass Relevance

Every other series in this library includes a WAF/API gateway bypass relevance
section, because each of those series documents a vulnerability class that a WAF or
gateway might filter, rate-limit, or block. **This series does not**, because it is a
pure tooling reference rather than a vulnerability class — the tools themselves are
attacker/tester workflow, not an attack technique that a WAF signature is written
against. Where a specific tool has WAF-evasion-relevant behavior (e.g., ffuf's
`-rate` and header randomization, or Burp's rate limiting for Autorize scans), that
is covered inline in the relevant tool section instead of as a standalone gateway
bypass discussion.

## A Note on PortSwigger Lab Mapping

Every other series in this library maps its techniques to PortSwigger Web Security
Academy labs in Apprentice → Practitioner → Expert order. **This series has no
PortSwigger lab mapping**, because PortSwigger labs test vulnerability
identification and exploitation, not tool usage. There is no lab that specifically
teaches "run ffuf with these sixteen flags." Instead, **crAPI (Completely Ridiculous
API)** is the primary practice environment for this series — it is a real,
deliberately vulnerable API you run locally with Docker, against which every tool in
this series can be pointed for hands-on practice. crAPI setup and its vulnerability-
to-topic mapping is covered in file 08.

## Tool Selection by Engagement Phase

### Phase 1: Reconnaissance and Endpoint Discovery
| Goal | Tool | File |
|---|---|---|
| Crawl an app/API to discover endpoints organically | katana | 07 |
| Brute-force guess API paths from a wordlist | ffuf, kiterunner | 03 |
| Discover undocumented HTTP parameters on a known endpoint | Arjun | 03 |
| Validate which discovered URLs are actually live, and fingerprint them | httpx | 07 |
| Find leaked API keys/secrets in a target's git history | truffleHog, gitleaks | 04 |

katana and ffuf are often confused because both "find endpoints," but they operate
on opposite principles: katana **crawls** (follows links, JS files, sitemap, robots.txt
— it only finds what is reachable by following references), while ffuf and
kiterunner **brute-force** (they guess paths from a wordlist — they can find
endpoints with zero inbound references, but only if the guess is in the wordlist).
Use both; they find different things. See file 07 for the full comparison.

### Phase 2: Manual Testing and Traffic Manipulation
| Goal | Tool | File |
|---|---|---|
| Intercept, repeat, and manipulate individual API requests | Burp Suite (core) | 02 |
| Test JSON and GraphQL bodies specifically | Burp Suite + InQL | 02 |
| Automated authorization/BOLA testing across many endpoints | Burp Suite + Autorize | 02 |
| Forge, crack, and manipulate JWTs during manual testing | Burp Suite + JWT Editor, or jwt_tool | 02, 04 |
| Detect HTTP request smuggling and hidden/unkeyed parameters | Burp Suite + HTTP Request Smuggler, Param Miner | 02 |

### Phase 3: Automated Fuzzing
| Goal | Tool | File |
|---|---|---|
| Fuzz URL paths, headers, or JSON body fields at high speed | ffuf | 03 |
| Brute-force realistic API routes (versioned, RESTful patterns) | kiterunner | 03 |
| Discover hidden/undocumented parameters at scale | Arjun | 03 |
| Stateful fuzzing that learns dependencies from an OpenAPI spec | RESTler | 05 |

### Phase 4: Scanning and Template-Based Detection
| Goal | Tool | File |
|---|---|---|
| Run known CVE/misconfiguration templates against API endpoints | nuclei | 05 |
| Scan specifically for GraphQL misconfigurations | graphql-cop | 05 |
| Interact with and test gRPC services | grpcurl | 06 |

### Phase 5: Team Collaboration and Reporting Workflow
| Goal | Tool | File |
|---|---|---|
| Build a shared, versioned collection of API requests for a team | Postman | 06 |
| Run that collection headlessly in CI or from the CLI | Newman | 06 |
| Parse and filter JSON API responses in scripts/pipelines | jq | 07 |

## Recommended Default Workflow

1. **Recon**: katana (crawl) + ffuf/kiterunner (brute-force) → httpx (validate/
   fingerprint what was found) → feed live endpoints into Postman/Burp.
2. **Secrets check**: run truffleHog and gitleaks against any git repos or JS bundles
   associated with the target early — leaked keys change the rest of the engagement.
3. **Parameter discovery**: Arjun against confirmed live endpoints from step 1.
4. **Manual triage in Burp**: import discovered endpoints, configure JSON/GraphQL
   handling, enable Autorize for authorization testing, use InQL if GraphQL is
   present.
5. **Scale up with automated scanning**: nuclei with API templates across the full
   endpoint list; graphql-cop if GraphQL; RESTler if a full OpenAPI/Swagger spec is
   available and stateful fuzzing is in scope.
6. **Protocol-specific**: grpcurl if gRPC services are present (cross-reference the
   gRPC series for protocol mechanics).
7. **Document and automate for retesting**: convert the manual Burp workflow into a
   Postman collection with pre-request/test scripts, run headlessly via Newman for
   regression checks on retest.

## Practice Environment

**crAPI** (Docker-based) is the primary hands-on target for this entire series. Full
setup instructions and a vulnerability-to-topic mapping table are in file 08. Where
individual tool sections below reference "practice against crAPI's `/identity/api/...`
endpoints," that mapping is defined there.

## File Index

See `00_README.md` for the full file index and how the files cross-reference each
other and the rest of the note library.
