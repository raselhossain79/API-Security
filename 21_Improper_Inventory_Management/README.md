# API9:2023 — Improper Inventory Management

Notes series for OWASP API Security Top 10 2023 #9 (Improper Inventory
Management). Follows the same conventions as the rest of this note library:
mechanism-first explanations, step-by-step technique breakdowns, PortSwigger Web
Security Academy lab mapping in Apprentice → Practitioner → Expert order with
honest gap disclosure, crAPI as supplementary practice, and full English
throughout.

## Files

| File | Contents |
|---|---|
| [`00-overview-and-concept.md`](./00-overview-and-concept.md) | Core concept, why unmonitored endpoints have weaker controls, the four inventory problem categories, WAF/Gateway applicability scoping for this vulnerability class |
| [`01-api-version-exploitation.md`](./01-api-version-exploitation.md) | Why deprecated versions have fewer controls, step-by-step discovery methodology, worked example of finding and exploiting a deprecated endpoint with missing authentication |
| [`02-shadow-zombie-endpoint-discovery.md`](./02-shadow-zombie-endpoint-discovery.md) | JS file mining, response inference, brute-forcing, error message analysis; zombie endpoint-specific signals; dedicated WAF/Gateway detection and bypass section |
| [`03-documentation-gap-testing.md`](./03-documentation-gap-testing.md) | Systematic methodology for testing documented behavior against actual implementation behavior across parameters, response fields, methods, rate limits, auth, and input validation |
| [`04-cheatsheet.md`](./04-cheatsheet.md) | Condensed checklist, command reference, consolidated lab and crAPI mapping, reporting checklist |

## Suggested Reading Order

1. Start with `00-overview-and-concept.md` for the mechanism underlying the
   entire vulnerability class — everything else builds on it.
2. Read `01` and `02` in either order; they cover parallel but distinct
   discovery problems (known-but-abandoned vs. never-documented endpoints).
3. Read `03` last among the technique files — it assumes you've already found
   the endpoint and are now testing what it actually does.
4. Use `04-cheatsheet.md` as your working reference during live engagements.

## Cross-References to Other Series

This series frequently serves as an entry point into other vulnerability
classes rather than standing alone. Findings here commonly chain into:

- **BOLA (API1)** — unauthenticated or under-authorized legacy/shadow endpoints
  returning object data by ID
- **Broken Authentication (API2)** — deprecated versions with weaker auth
  enforcement
- **Mass Assignment** — undocumented parameters silently accepted
- **BFLA (API5)** — undocumented methods or scopes granting unintended
  function-level access
- **API4 Unrestricted Resource Consumption** — documented rate limits not
  actually enforced
- **GraphQL security notes** — if shadow discovery surfaces a GraphQL endpoint,
  discovery technique diverges from REST and should switch to that series

## Scope Note on WAF/API Gateway Coverage

This vulnerability class has uneven WAF/Gateway relevance across its
sub-techniques — it is not treated uniformly the way it is in other series in
this library. See `00-overview-and-concept.md` Section 4 for the full scoping
rationale, and the dedicated section in `02-shadow-zombie-endpoint-discovery.md`
for the one sub-technique (active brute-forcing) where it's genuinely central.
