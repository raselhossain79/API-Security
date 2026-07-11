# API Security Testing — Automation & Tooling

A tooling reference for API security testing, companion to the 23 other API
security topic series in this note library (OWASP API Top 10, GraphQL, JWT, OAuth,
SOAP/XML, WebSocket/SSE, SSRF, webhooks, API keys, race conditions, API gateways,
gRPC, and the underlying web application vulnerability series). Where those series
document *vulnerability classes and methodology*, this series documents the *tools*
used to find, fuzz, exploit, and automate discovery of those vulnerabilities — every
command broken down flag by flag.

## How This Series Differs From the Others

- **No WAF/API gateway bypass section**: this is a pure tooling reference, not a
  vulnerability class, so there's no standalone bypass discussion. Tool-specific
  rate-limit/evasion flags are covered inline within each tool's section instead.
  See file 01 for the explicit reasoning.
- **No PortSwigger lab mapping**: PortSwigger labs teach vulnerability
  identification, not tool usage. **crAPI** (Docker-based) is this series' primary
  hands-on practice environment instead — see file 08 for setup and a
  vulnerability-to-topic mapping table.

## File Index

| File | Contents |
|---|---|
| `01_overview_tool_selection.md` | Tool selection by engagement phase, recommended workflow, WAF/lab-mapping notes |
| `02_burp_suite_api.md` | Burp config for JSON/GraphQL; Autorize, InQL, JWT Editor, HTTP Request Smuggler, Param Miner |
| `03_fuzzing_tools.md` | ffuf, kiterunner, Arjun — full flag breakdowns |
| `04_auth_secret_tools.md` | jwt_tool, truffleHog, gitleaks — full flag breakdowns |
| `05_scanning_tools.md` | nuclei (API templates + custom template authoring), graphql-cop, RESTler |
| `06_protocol_tools.md` | grpcurl, Postman (collections/env vars/pre-request & test scripts), Newman |
| `07_endpoint_probing_json.md` | httpx, katana (crawling vs brute-forcing), jq |
| `08_wordlists_crapi.md` | SecLists & Assetnote API wordlists, crAPI Docker setup and vulnerability map |
| `09_quick_reference_cheatsheet.md` | Condensed command reference across every tool |

## Cross-References to the Rest of the Library

This series intentionally avoids re-explaining vulnerability mechanics already
covered elsewhere:

- **JWT attack theory** (alg confusion, `none` alg, kid injection) → JWT series.
  This series covers only jwt_tool and JWT Editor *usage*.
- **GraphQL vulnerability classes** (introspection abuse, batching DoS, injection
  in resolvers) → GraphQL series. This series covers InQL and graphql-cop *usage*.
- **BOLA/BFLA/mass assignment theory** → their respective series. This series
  covers Autorize, Arjun, and ffuf JSON-field fuzzing *usage* for finding them.
- **gRPC protocol mechanics** (Protocol Buffers, HTTP/2 framing) → gRPC series.
  This series covers grpcurl *usage* only.
- **HTTP request smuggling theory** → HTTP request smuggling / HTTP2 series. This
  series covers the Burp extension *usage* only.

## Conventions Used Throughout This Series

- Every command is broken down flag by flag — no command appears without full
  explanation of every flag/argument/option used.
- Each file includes a **Real-World Notes** section with practical
  engagement-level guidance beyond the raw flag reference.
- crAPI is referenced as the practice target wherever a hands-on example is useful.
- Written in full English only, consistent with the rest of this note library.
