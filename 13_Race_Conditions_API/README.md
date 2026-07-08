# API Race Conditions — Note Series

This series covers race condition (TOCTOU) exploitation as it specifically applies to
API contexts: REST APIs, GraphQL APIs, and API gateways. It assumes familiarity with
the core race condition mechanism (TOCTOU, sub-states, the single-packet attack, and
basic Turbo Intruder usage), which is covered in the general **Race Conditions** series
in the web application security note library. That series is not duplicated here —
every file in this series cross-references it for foundational concepts and builds
only on what is unique to API-based exploitation.

## Why a separate series for APIs

Traditional web race condition testing targets a browser-driven, form-based, session-
cookie-authenticated flow. API race condition testing targets a fundamentally
different surface: stateless bearer-token auth, JSON payloads that can batch multiple
operations into one request, GraphQL resolvers that can multiply write operations
inside a single HTTP call, distributed microservice state that doesn't live in one
database, and payment-grade idempotency controls that are supposed to prevent races
but are frequently implemented incorrectly. These require distinct methodology,
distinct tooling configuration, and distinct real-world exploitation patterns — that
is the entire scope of this series.

## File index

| # | File | Covers |
|---|------|--------|
| 1 | `01-overview-why-apis-race-conditions.md` | Why APIs are especially prone to race conditions: statelessness, microservice distributed state, JSON batch/array operations |
| 2 | `02-multistep-api-chain-races.md` | Race windows spanning multiple sequential API calls (e.g. check-balance → withdraw as separate requests) |
| 3 | `03-graphql-batching-race-exploitation.md` | Using GraphQL aliased batched mutations to fire many state-changing operations in one HTTP request |
| 4 | `04-idempotency-key-abuse.md` | Testing idempotency key enforcement in payment and other transactional APIs |
| 5 | `05-real-world-scenarios.md` | Double-spending, coupon/discount races, balance races, limited-resource claim races |
| 6 | `06-turbo-intruder-api-races.md` | Turbo Intruder single-packet attack applied to API endpoints, full script breakdowns |
| 7 | `07-cheatsheet-lab-mapping.md` | Final cheatsheet + PortSwigger lab mapping (Apprentice → Practitioner → Expert) + crAPI mapping |

## Cross-references

- **General Race Conditions series** (web application security notes) — core TOCTOU
  concept, sub-states, methodology (predict/probe/prove), Turbo Intruder basics,
  connection warming, session-based locking mechanisms, partial construction attacks.
  Read that series first if the terms above are unfamiliar.
- **GraphQL notes** — schema introspection, batched query/mutation syntax, aliasing,
  resolver-level authorization gaps. File 3 in this series assumes that background.
- **Broken Access Control / IDOR notes** — object-level authorization gaps that often
  compound with race conditions in the resource-claim scenarios in File 5.
- **API Fundamentals / API Reconnaissance series** — endpoint discovery and API
  documentation review, useful for the "predict potential collisions" phase applied
  to API surfaces specifically.

## Conventions used throughout this series

- Mechanism-first: every technique opens with what creates the race window before any
  tooling instructions.
- Flag-by-flag breakdowns for every command and every Turbo Intruder script.
- PortSwigger lab mapping in Apprentice → Practitioner → Expert order, with honest
  disclosure of which labs do and do not translate directly to API testing.
- crAPI referenced as supplementary practice where relevant.
- A WAF / API gateway defense-awareness section in every file — or an explicit note
  on why it doesn't apply to that specific sub-technique.
- Full English only, GitHub-ready Markdown, no Bangla/Banglish text anywhere.
