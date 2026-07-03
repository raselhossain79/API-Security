# Broken Function Level Authorization (BFLA) — Note Series

**OWASP API Security Top 10 2023 — API5:2023**

A complete, GitHub-ready reference on BFLA discovery and exploitation, written to the same depth and conventions as this repository's other vulnerability-class series (mechanism-first explanations, full request/response breakdowns, PortSwigger lab mapping with honest gap disclosure, and real-world framing).

---

## Files

| # | File | Covers |
|---|---|---|
| 01 | [BFLA-Overview-and-Concept.md](01-BFLA-Overview-and-Concept.md) | BOLA vs BFLA distinction, root-cause mechanism, impact, vertical/lateral preview |
| 02 | [BFLA-Discovery-Methodology.md](02-BFLA-Discovery-Methodology.md) | Path guessing, JS source mining, API doc/GraphQL mining, response field inference, OPTIONS enumeration, non-admin credential testing |
| 03 | [BFLA-Common-Patterns.md](03-BFLA-Common-Patterns.md) | HTTP method switching, endpoint path manipulation, parameter-based role manipulation — each with full request breakdowns |
| 04 | [BFLA-Vertical-and-Lateral-Escalation.md](04-BFLA-Vertical-and-Lateral-Escalation.md) | Vertical escalation, lateral cross-tenant/cross-role escalation, chaining BFLA with BOLA |
| 05 | [BFLA-Testing-With-Burp.md](05-BFLA-Testing-With-Burp.md) | Manual Burp workflow, Autorize/AuthMatrix, PortSwigger lab mapping, crAPI practice |
| 06 | [BFLA-Cheatsheet.md](06-BFLA-Cheatsheet.md) | Condensed checklists, curl one-liners, severity guidance |

---

## Reading Order

Read 01 → 06 in sequence for first-pass learning. During live engagements, 06 (cheatsheet) is the fast-reference entry point, linking back to the relevant deep-dive file as needed.

## Prerequisites

Familiarity with basic API authentication concepts and this repository's BOLA series is recommended before starting, since BFLA is defined largely by contrast with BOLA (file 01, section 2).

## Practice Environments

- **crAPI** — primary hands-on environment for BFLA-specific role/function scenarios (mechanic vs. regular user, admin functions).
- **PortSwigger Web Security Academy** — Access Control category labs, mapped in function-level-relevant order in file 05, section 3.

## Conventions Used Throughout

- Every request/response example states what's being tested and precisely why the authorization check fails — not just "this works."
- PortSwigger labs are listed in difficulty-progression order, with an explicit note where PortSwigger's category structure doesn't cleanly separate BOLA from BFLA.
- Written entirely in English.
