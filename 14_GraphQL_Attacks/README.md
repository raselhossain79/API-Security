# GraphQL Security Testing

A comprehensive, GitHub-ready note series on GraphQL Security Testing — a
distinct attack surface from REST APIs, requiring its own recon,
exploitation, and authorization-testing methodology. Companion series to
the REST/OWASP API Security Top 10 note library.

All content is written in full English. Every query, mutation, and tool
command is broken down field-by-field/flag-by-flag: what it does, why it's
structured that way, and exactly what the attack achieves.

## File index

| # | File | Covers |
|---|---|---|
| 1 | [01-graphql-fundamentals-for-pentesters.md](01-graphql-fundamentals-for-pentesters.md) | Queries, mutations, subscriptions, types, schema, resolvers, variables, aliases, fragments — mechanism-first, no attacks |
| 2 | [02-introspection-and-schema-extraction.md](02-introspection-and-schema-extraction.md) | `__schema`/`__type` introspection, finding privileged mutations, introspection-disabled bypasses including field-suggestion leakage |
| 3 | [03-batching-and-alias-attacks.md](03-batching-and-alias-attacks.md) | Query batching and alias attacks for rate-limit bypass, full OTP brute-force walkthrough |
| 4 | [04-depth-complexity-and-dos-attacks.md](04-depth-complexity-and-dos-attacks.md) | Nested-query depth and complexity attacks causing server resource exhaustion |
| 5 | [05-authorization-testing-bola-bfla.md](05-authorization-testing-bola-bfla.md) | BOLA/BFLA testing at the resolver level, not just the endpoint |
| 6 | [06-injection-testing.md](06-injection-testing.md) | SQL/NoSQL/OS command injection via GraphQL variables and inline arguments |
| 7 | [07-waf-bypass-for-graphql.md](07-waf-bypass-for-graphql.md) | WAF/gateway detection methods and evasion: query obfuscation, fragment abuse, alias obfuscation |
| 8 | [08-tooling-inql-and-graphql-cop.md](08-tooling-inql-and-graphql-cop.md) | Full setup and flag-by-flag usage of InQL (Burp extension) and graphql-cop |
| 9 | [09-final-cheatsheet-and-lab-mapping.md](09-final-cheatsheet-and-lab-mapping.md) | Quick-reference cheatsheet + full PortSwigger GraphQL lab mapping in difficulty order |

## Recommended reading order

Sequential, 1 → 9. Files 2–6 each build directly on mechanics introduced in
file 1; file 7 consolidates WAF material referenced throughout files 2–6;
file 8 covers the tools referenced throughout the series; file 9 closes
with a cheatsheet and lab mapping.

## Lab practice

Every technique maps to a PortSwigger Web Security Academy GraphQL lab —
see file 9 for the full table. **Note:** PortSwigger's GraphQL lab set is
smaller than other topics (5 labs: 1 Apprentice, 4 Practitioner, no Expert
tier currently published) — this is disclosed honestly in file 9 rather
than padded out. Damn Vulnerable GraphQL Application (DVGA) is noted as
supplementary practice for deeper hands-on repetition beyond the five
PortSwigger labs; crAPI is noted as supplementary but is REST-focused with
thin GraphQL-specific coverage.

## WAF / API gateway coverage

Every file that has a meaningful WAF/gateway bypass angle includes a
dedicated section covering detection methods and evasion. File 5
(authorization testing) explicitly states that BOLA/BFLA is a
business-logic category not meaningfully addressable at the WAF layer,
rather than inventing a bypass section for completeness. File 7
consolidates all WAF material into one cross-referenced dictionary.
