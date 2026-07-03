# Injection Testing via APIs

A focused note series on how injection vulnerability classes (SQLi, NoSQL
injection, OS command injection, SSTI, XXE) manifest and are tested **specifically
through API endpoints** — JSON request bodies, nested object parameters,
array-based fields, GraphQL field arguments, and content-type confusion — as
distinct from traditional HTML-form-based delivery.

This series is a **companion to**, not a replacement for, the standalone
vulnerability-class series covering each injection type's core mechanics in depth.
Read the relevant standalone file first if you need the underlying mechanics
refreshed; this series assumes that foundation and focuses entirely on the
API-specific delivery, encoding, and testing-methodology differences.

## Why This Series Exists

APIs deliver user input through structured formats (primarily JSON, sometimes XML)
rather than flat form encoding. This changes:

- How payloads must be structured to survive the transport format without breaking
  the request's own syntax
- Where injection points can hide (nested objects, array elements, deeply buried
  fields with no visible UI equivalent)
- What tooling configuration is required to even locate injection points
- How responses must be interpreted, since APIs rarely render HTML back to the tester

## Files in This Series

| File | Contents |
|---|---|
| [`01-api-injection-context-overview.md`](./01-api-injection-context-overview.md) | Why API injection testing differs from web app testing: JSON delivery, nested parameters, array injection, GraphQL field injection, encoding requirements, tooling adjustments, industry framing |
| [`02-sqli-via-api.md`](./02-sqli-via-api.md) | SQL injection through JSON request bodies — UNION, boolean-blind, and time-blind techniques adapted to JSON delivery, with full payload/encoding breakdowns |
| [`03-nosql-injection-via-api.md`](./03-nosql-injection-via-api.md) | MongoDB operator injection (`$ne`, `$gt`, `$regex`, `$where`) — the most common API-native injection variant, including nested-field and query-string delivery |
| [`04-command-injection-via-api.md`](./04-command-injection-via-api.md) | OS command injection through API body parameters — in-band, time-based blind, and out-of-band confirmation techniques |
| [`05-ssti-via-api.md`](./05-ssti-via-api.md) | Server-side template injection through API string fields — engine fingerprinting and escalation to RCE via JSON-delivered payloads |
| [`06-xxe-via-api.md`](./06-xxe-via-api.md) | XXE via content-type confusion — exploiting XML parsing on endpoints documented as JSON-only |
| [`07-methodology-and-cheatsheet.md`](./07-methodology-and-cheatsheet.md) | Unified testing methodology across all classes, quick-reference payload cheatsheet, JSON escaping reference, consolidated PortSwigger lab progression |

## Recommended Reading Order

1. Start with the overview file — it establishes the core concepts (JSON escaping,
   nested/array injection, tooling setup) referenced throughout every other file.
2. Read the injection-class files in any order based on what's relevant to your
   current target — each is self-contained given the overview's foundation.
3. Use the methodology/cheatsheet file as a live-reference during actual testing.

## Related Series

- Standalone web application injection series (SQLi, NoSQL Injection, OS Command
  Injection, SSTI, XXE, and other OWASP Top 10 classes) — covers core vulnerability
  mechanics this series assumes as background.
- OWASP API Security Top 10 series (API Reconnaissance/Endpoint Discovery, API2
  Broken Authentication, API1 BOLA) — covers API-specific vulnerability classes
  outside the injection category.
- JWT Attacks series and OAuth 2.0 Attacks series — cover authentication/
  authorization-layer API vulnerabilities, complementary to this series' focus on
  data-layer injection.

## Standing Conventions

- Every payload is broken down piece by piece: what the injected fragment does, and
  exactly how it breaks out of (or exploits type confusion within) its intended
  context.
- PortSwigger Web Security Academy labs are mapped in correct difficulty-progression
  order where applicable, with honest disclosure of gaps where no current lab covers
  the JSON-delivery-specific technique.
- Real-world industry framing is included in every file — why the technique matters
  in actual bug bounty/pentest engagements, not just lab environments.
- Full English only, throughout.
