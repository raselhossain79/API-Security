# REST API-Specific Testing Methodology

A procedural framework for systematically testing any REST API — independent of specific vulnerability classes. This series answers: *"Given an arbitrary REST API, in what order do I work, and what do I check at each stage?"*

For vulnerability-class-specific deep dives (BOLA, JWT attacks, OAuth attacks, injection classes, etc.), see the companion series: **OWASP API Security Top 10**, **JWT Attacks**, **OAuth 2.0 Attacks**, and the web application vulnerability series. This series focuses purely on methodology and sequencing — it is the procedural backbone those other series plug into.

---

## How to Use This Series

Read the files in order on a first pass — each file builds on baseline data and matrices established in Part 1. On subsequent engagements, use **Part 7 (Consolidated Methodology Checklist)** as your working document and refer back to Parts 1–6 for the full technical reasoning behind any checklist item.

---

## Files in This Series

| # | File | Covers |
|---|---|---|
| 1 | [`01-overview-and-setup-methodology.md`](01-overview-and-setup-methodology.md) | Reading API specs, building the endpoint matrix, traffic-based mapping, establishing behavioral baselines, configuring Burp Suite and Postman for API-specific work |
| 2 | [`02-http-method-testing.md`](02-http-method-testing.md) | Systematic testing of GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD against every endpoint, method override headers, interpreting results correctly |
| 3 | [`03-api-versioning-attacks.md`](03-api-versioning-attacks.md) | Enumerating version schemes, confirming old versions are live, testing for authorization/rate-limit/validation regression on older versions |
| 4 | [`04-content-type-manipulation.md`](04-content-type-manipulation.md) | Switching between JSON/XML/text-plain/form-encoded/multipart, validation-consistency checks, CSRF and XXE escalation triggers |
| 5 | [`05-response-differential-analysis.md`](05-response-differential-analysis.md) | Systematic comparison across role, object ownership, parameter value, and timing — the core BOLA/BFLA detection technique |
| 6 | [`06-parameter-fuzzing-methodology.md`](06-parameter-fuzzing-methodology.md) | JSON-specific fuzzing: type confusion, nested object injection, array/scalar substitution, bulk-endpoint validation gaps |
| 7 | [`07-methodology-checklist.md`](07-methodology-checklist.md) | Consolidated, engagement-ready checklist tying all phases together, plus cross-series escalation triggers and report-writing discipline |

---

## Series Conventions

- **Mechanism-first:** every technique is explained by what it actually tests and why, before any command or payload is shown.
- **Command/payload breakdown:** every request example is broken down piece by piece — what changed, and what that specific change is designed to reveal.
- **PortSwigger Web Security Academy mapping:** each file maps to relevant labs in correct difficulty-progression order where labs exist. Coverage gaps are disclosed honestly rather than papered over — several techniques in this series (full-matrix versioning sweeps, timing-based blind differentials, deep JSON structural fuzzing) are not currently modeled by any PortSwigger lab and are instead recommended for practice against **crAPI** and **VAmPI**.
- **Real-world framing:** every file includes notes on how and why each technique surfaces in actual bug bounty and pentest engagements, not just lab environments.
- **Full English throughout.**

---

## Prerequisites

- Working familiarity with Burp Suite (Proxy, Repeater, Intruder, Comparer) and Postman
- Basic understanding of REST conventions and JSON structure
- Test credentials across every role the target API defines, ideally including multi-tenant test accounts if the target is multi-tenant

## Recommended Practice Targets

- **crAPI** — the most consistently useful target across this entire series; referenced repeatedly for versioning, content-type, differential, and fuzzing practice
- **VAmPI** — particularly useful for versioning-regression practice (Part 3)
- **PortSwigger Web Security Academy** — API testing, Access control, and NoSQL injection topics, mapped per-file above
