# BOPLA — Broken Object Property Level Authorization
## OWASP API Security Top 10 2023 — API3

A comprehensive, mechanism-first note series on BOPLA, the 2023 merge of API3:2019
(Excessive Data Exposure) and API6:2019 (Mass Assignment) into a single property-level
authorization category, plus its related data-export failure mode (CSV/Formula Injection).

Built to the same depth and conventions as this repository's other OWASP API Security
Top 10 and web application vulnerability note series: mechanism-first explanations,
flag-by-flag/field-by-field request breakdowns, PortSwigger lab mappings in strict
Apprentice → Practitioner → Expert order with honest gap disclosure where Academy has no
matching lab, explicit WAF/API gateway relevance for every sub-type (including explicit
statements where it is *not* relevant, rather than silent omission), crAPI mapping as
supplementary practice, and real-world framing throughout.

---

## File Index

| # | File | Covers |
|---|---|---|
| 1 | [`01-bopla-overview-and-concepts.md`](01-bopla-overview-and-concepts.md) | What BOPLA is, the 2019→2023 merge, both sub-types explained, ORM/framework root-cause analysis, WAF/gateway relevance overview, real-world framing, crAPI mapping |
| 2 | [`02-excessive-data-exposure-testing-methodology.md`](02-excessive-data-exposure-testing-methodology.md) | Response vs UI field comparison, sensitive-field identification, cross-role response comparison, nested/list endpoint pitfalls, PortSwigger gap disclosure |
| 3 | [`03-mass-assignment-testing-methodology.md`](03-mass-assignment-testing-methodology.md) | Systematic per-endpoint field injection, candidate field-list building, server-side impact verification, cross-role write comparison, PortSwigger lab mapping |
| 4 | [`04-mass-assignment-filter-bypass-techniques.md`](04-mass-assignment-filter-bypass-techniques.md) | Alternate field names/casing, nested object injection, content-type switching, JSON key duplication, dedicated WAF/API gateway detection & bypass section |
| 5 | [`05-csv-formula-injection-data-export.md`](05-csv-formula-injection-data-export.md) | Formula-trigger mechanism, safe testing method, 2025 CVEs (Axosoft, Bagisto, UnoPim), mitigation guidance, WAF relevance, PortSwigger/crAPI gap disclosure |
| 6 | [`06-final-cheatsheet.md`](06-final-cheatsheet.md) | Consolidated quick-reference: checklists, bypass technique table, lab map, report-writing reminders |

---

## Recommended Reading Order

Read sequentially, 1 → 6. Files 2–5 build on the field-identification and injection
methodology established in file 1, and file 4 assumes file 3's baseline methodology.
File 6 is a standalone quick-reference for use during live engagements once files 1–5
have been studied.

## Practice Environments Referenced

- **PortSwigger Web Security Academy** — primary lab environment. Exact lab mapping and
  progression order given per-file; gaps (no lab for Excessive Data Exposure or
  CSV/Formula Injection) are disclosed explicitly rather than force-fit to unrelated labs.
- **[crAPI](https://github.com/OWASP/crAPI)** — supplementary practice for Excessive Data
  Exposure and Mass Assignment, where PortSwigger's coverage is thin or absent. Confirm
  exact endpoint paths against your locally deployed version.

## Scope Note

This series is intended for authorized security testing (bug bounty programs, contracted
penetration tests, or your own lab/training environments) only. File 5 in particular
includes explicit guidance on safe, non-destructive testing boundaries for CSV/Formula
Injection given its client-side execution nature.
