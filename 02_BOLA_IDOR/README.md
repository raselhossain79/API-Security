# BOLA (Broken Object Level Authorization) — Note Series

**OWASP API Security Top 10 2023 — API1:2023**

Part of the API security note series, built to the same depth and conventions as the web application security series (34+ vulnerability series covering SQL injection, XSS, SSTI, XXE, Broken Access Control, and others).

---

## File Index

| # | File | Covers |
|---|---|---|
| 1 | [`01_Overview_and_Concept.md`](./01_Overview_and_Concept.md) | What BOLA is, the precise BOLA vs IDOR distinction, horizontal vs cross-tenant preview, dedicated WAF/API Gateway relevance section (why signature-based detection doesn't apply, what actually does), real-world notes |
| 2 | [`02_Testing_Methodology.md`](./02_Testing_Methodology.md) | Manual, step-by-step testing: baseline API mapping, horizontal privilege escalation, cross-tenant BOLA in multi-tenant SaaS, non-obvious locations (request bodies, response-disclosed references, HTTP method coverage gaps, nested resources) |
| 3 | [`03_ID_Type_Bypass_Techniques.md`](./03_ID_Type_Bypass_Techniques.md) | Sequential integers, UUIDs (v1 vs v4, disclosure-based discovery), hashed IDs (hash identification, rainbow tables, reproducing the hash function), GUIDs, base64-encoded IDs — every technique broken down command-by-command |
| 4 | [`04_Autorize_Extension_Guide.md`](./04_Autorize_Extension_Guide.md) | Complete Burp Suite Autorize setup: Jython/installation, low-privilege credential capture, configuration of header replacement and enforcement detection rules, workflow, reading the results table, false-positive handling |
| 5 | [`05_Cheatsheet.md`](./05_Cheatsheet.md) | Condensed reference tables for all of the above, plus PortSwigger Web Security Academy lab mapping (Apprentice → Practitioner, with honest gap disclosure) and crAPI Challenges 1–3 breakdown |

---

## Recommended Reading Order

1. Start with **file 1** to lock in the BOLA/IDOR distinction — this changes how you scope testing versus a pure web-app IDOR assessment.
2. Work through **file 2** methodically; it is the operational core of the series.
3. Reference **file 3** as needed once you encounter a specific ID format during testing — it's written to be looked up per-ID-type, not necessarily read linearly.
4. Set up **file 4** (Autorize) early in any real engagement with a large API surface, so it's collecting data throughout your manual walkthrough rather than as an afterthought.
5. Keep **file 5** open during live testing/lab work as the fast-recall reference.

## Practice Mapping

- **PortSwigger Web Security Academy** — Access Control topic labs, full Apprentice → Practitioner progression mapped to specific file 2/3 techniques in file 5 §7.
- **OWASP crAPI** — Challenges 1–3 (BOLA-focused), mapped to specific techniques in file 5 §8; recommended as the primary supplementary practice since it exercises genuine API-shaped (JSON, GUID-based) scenarios that PortSwigger's web-app-shaped labs don't fully cover, particularly cross-tenant and GUID-disclosure patterns.
