# API4:2023 — Unrestricted Resource Consumption

Comprehensive note series on OWASP API Security Top 10 2023 — API4:
Unrestricted Resource Consumption. Part of the broader API Security Top 10
note library.

## Reading Order

| # | File | Covers |
|---|---|---|
| 1 | `00_Overview_and_Concept.md` | Definition, mechanism, impact categories, relationship to other series in the library, why WAF/Gateway bypass is meaningfully relevant to this specific vulnerability |
| 2 | `01_Detection_Methodology.md` | Response-header detection, timing-based detection, behavioral difference detection (rate-limited vs. unlimited endpoints) |
| 3 | `02_Resource_Exhaustion_Techniques.md` | Pagination limit abuse, file upload size abuse, ReDoS via API, expensive computation endpoint abuse — each broken down piece by piece |
| 4 | `03_Third_Party_Spending_Abuse.md` | SMS/OTP, transactional email, and payment processing spend abuse (Denial of Wallet) |
| 5 | `04_Burp_Turbo_Intruder_Resource_Testing.md` | Full flag-by-flag Burp Intruder and Turbo Intruder configuration for resource testing |
| 6 | `05_Final_Cheatsheet.md` | Condensed quick-reference for active testing |

## Cross-References to Other Series in the Library

This series intentionally does not repeat content already covered
elsewhere:

- **Broken Authentication (API2) series** — credential stuffing mechanics
- **BOLA (API1) series** — object ID enumeration mechanics
- **Rate Limit / Bot Protection Bypass series** — generic bypass techniques
  (IP rotation, header spoofing, distributed sources)
- **API Reconnaissance and Endpoint Discovery series** — finding endpoints
  before testing them for resource limits

Read those series alongside this one for full context; this series covers
only the resource-consumption-specific angle of each.

## Practice Environments

- **PortSwigger Web Security Academy** — used where labs exist; honest gap
  disclosure provided in each file where no dedicated lab is available
  (this vulnerability class has significant Academy coverage gaps —
  see `05_Final_Cheatsheet.md` section 5 for the full summary)
- **crAPI (Completely Ridiculous API)** — supplementary practice,
  particularly strong for pagination abuse and third-party spend (OTP)
  simulation

## Conventions Used

- Mechanism-first explanations before technique walkthroughs
- Every request/script example broken down piece by piece: what resource
  is exhausted, why the API lacks protection
- Flag-by-flag command/configuration breakdowns for tooling
- Dedicated WAF/API Gateway section in every technical file (detection
  methods + realistic bypass considerations specific to this vulnerability
  class)
- PortSwigger lab mappings in Apprentice → Practitioner → Expert order,
  with honest disclosure where no lab exists
- Real-world notes in every file
- Full English only — no Bangla or Banglish text anywhere in this library
