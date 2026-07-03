# BOPLA — Broken Object Property Level Authorization
### OWASP API Security Top 10 2023 — API3

A complete testing and reference series on **Broken Object Property Level Authorization (BOPLA)**,
the API3:2023 category that merges two vulnerability classes from the 2019 list:

- **API3:2019 — Excessive Data Exposure**
- **API6:2019 — Mass Assignment**

This series follows the same depth and structure as the rest of the OWASP API Security Top 10
note set (API Recon, API2 Broken Authentication, API1 BOLA) and the web application security
track. Every payload is broken down field by field. Every claim is mapped to a real testing
technique, not just theory.

---

## Files in this series

| # | File | Covers |
|---|------|--------|
| 1 | `01-bopla-overview-and-concepts.md` | What BOPLA is, why OWASP merged EDE + Mass Assignment into one category, root-cause mechanics, BOLA vs BFLA vs BOPLA decision logic, real-world impact |
| 2 | `02-excessive-data-exposure-testing.md` | Full testing methodology for Excessive Data Exposure: response-vs-UI diffing, cross-role response comparison, field-by-field breakdown of dangerous responses |
| 3 | `03-mass-assignment-testing.md` | Auto-binding mechanics per framework, hidden-parameter discovery, differential testing methodology, filter bypass techniques |
| 4 | `04-bopla-cheatsheet.md` | Quick-reference wordlist, bypass matrix, Burp Suite workflow, PortSwigger lab index, crAPI endpoint list |

Read them in order. Each file assumes the previous one.

---

## Prerequisites

- Comfortable intercepting and modifying requests in Burp Suite (Repeater, Intruder, Comparer)
- Basic understanding of REST APIs and JSON request/response structure
- Familiarity with the API Recon and API2 Broken Authentication notes in this repository —
  BOPLA testing assumes you already know how to enumerate endpoints and obtain tokens for
  multiple roles

## Practice environments

- **PortSwigger Web Security Academy** — API testing topic (`portswigger.net/web-security/api-testing`).
  Lab mapping and honest gap disclosure are provided in each file — PortSwigger has one lab that
  directly targets Mass Assignment; Excessive Data Exposure is not covered by a dedicated named
  lab, so this series draws on adjacent API recon and access control labs to fill that gap.
- **crAPI (Completely Ridiculous API)** — the only free practice target with BOPLA-specific
  scenarios baked in by design (vehicle location exposure, mechanic report mass assignment,
  coupon/credit manipulation). Referenced throughout.
- **OWASP crAPI GitHub**: `github.com/OWASP/crAPI`

## Related files in this repository

- OWASP API Security Top 10 series: API Recon, API2 Broken Authentication, API1 BOLA
- JWT Attacks series (8 files)
- OAuth 2.0 Attacks series
- Web Application Security track (Mass Assignment overlaps with Insecure Design / A04 and
  Broken Access Control notes from that track — cross-referenced where relevant)

---

*All notes written in full English. No Bangla or Banglish text.*
