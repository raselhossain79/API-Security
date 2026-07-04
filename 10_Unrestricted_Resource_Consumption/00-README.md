# Unrestricted Resource Consumption — API4:2023

**OWASP API Security Top 10 2023 — API4:2023**
*(Previously named "Lack of Resources and Rate Limiting" in the 2019 edition)*

A comprehensive, GitHub-ready note series covering detection and exploitation of
missing/weak rate limiting, resource exhaustion attacks, and third-party spending
abuse in APIs — written for penetration testing and bug bounty research.

---

## Series Structure

| # | File | Description |
|---|---|---|
| 1 | [`01-overview-concept.md`](./01-overview-concept.md) | What Unrestricted Resource Consumption is, why OWASP renamed and broadened this category in 2023, the resource types at risk, and real-world industry framing |
| 2 | [`02-detection-methodology.md`](./02-detection-methodology.md) | Response-based detection, `X-RateLimit-*` header analysis, timing-based detection, and enumeration/brute-force enabled by absent rate limiting |
| 3 | [`03-resource-exhaustion-techniques.md`](./03-resource-exhaustion-techniques.md) | Pagination limit abuse, file upload size abuse, regex complexity (ReDoS) attacks, expensive computation endpoint abuse |
| 4 | [`04-third-party-spending-abuse.md`](./04-third-party-spending-abuse.md) | SMS, email, and payment API cost amplification — "Denial of Wallet" attacks against paid third-party integrations |
| 5 | [`05-cheatsheet.md`](./05-cheatsheet.md) | Quick-reference commands, payloads, header table, lab map, and report-writing checklist |

---

## Recommended Reading Order

Read in numeric order. Files build on each other: file 01 establishes the concept,
file 02 establishes how to *detect* the absence of controls, files 03–04 cover
*exploitation* once absence is confirmed, and file 05 is a condensed reference for
active testing once you're familiar with the full material.

---

## Series Conventions

- **Mechanism-first:** every attack is explained by *why* it works before *how* to run
  it — the underlying resource being exhausted is always named explicitly.
- **Command/payload breakdowns:** every request, script, or payload is broken down
  piece by piece (flag by flag, parameter by parameter).
- **PortSwigger lab mapping:** relevant labs are mapped in PortSwigger's own
  difficulty-progression order, with **honest gap disclosure** where PortSwigger has no
  applicable lab (this is common for this OWASP category — see individual files).
- **crAPI reference:** used throughout as the primary hands-on target for API-specific
  techniques not covered by PortSwigger.
- **Real-world industry framing:** every file includes documented real-world context —
  bug bounty patterns, vendor guidance, and named industry concepts (e.g. "Denial of
  Wallet").
- **Full English only.**

---

## Cross-References to Other Series

- **API1:2023 — BOLA:** pagination abuse chains directly with BOLA to mass-exfiltrate
  data (see file 03, section 1.4).
- **API2:2023 — Broken Authentication:** enumeration and brute-force techniques in file
  02 are covered here from the resource-consumption angle only; full authentication
  mechanism detail lives in the Broken Authentication series.
- **API5:2023 — Broken Function Level Authorization:** expensive admin-only endpoints
  become resource exhaustion vectors if reachable by low-privilege users.

---

## Legal / Ethical Note

Techniques in files 03 and 04, particularly third-party spending abuse (SMS/email/
payment triggering), must only be tested against authorized targets and using your own
or explicitly designated test recipients. File 04 includes specific warnings on this at
each relevant technique. Never run high-volume tests against real third-party phone
numbers, email addresses, or payment instruments outside of an authorized scope.
