# API10:2023 — Unsafe Consumption of APIs

Notes on the tenth category of the OWASP API Security Top 10 (2023): applications
that act as **clients** of third-party APIs and unsafely trust the data those
APIs return.

This series is a companion to the existing API Security Top 10 note set. Where
API1–API9 mostly deal with protecting your API from inbound abuse, API10 flips
the direction: your application is the caller, and the untrusted party is
whatever service you integrate with.

## Files in this series

| # | File | Covers |
|---|------|--------|
| 1 | `01-overview-and-concept.md` | Core concept, trust boundary reversal, attack surface, why WAF/gateway signature detection mostly does not apply here |
| 2 | `02-injection-via-third-party-response.md` | SQLi, SSTI, command injection, log injection via unsanitized third-party response fields |
| 3 | `03-ssrf-via-third-party-response.md` | SSRF triggered by URLs embedded in third-party API responses (webhooks, callbacks, pagination links, redirects) |
| 4 | `04-data-integrity-issues.md` | Missing schema/type validation — type confusion, null dereference, fail-open logic bypass |
| 5 | `05-testing-methodology.md` | Black-box vs grey-box vs white-box approach, honest discussion of detection difficulty, PortSwigger lab mapping, supplementary practice |
| 6 | `06-final-checklist.md` | Design, code review, and testing checklist |

## How this fits with other series

- **SSRF (general/API-focused series)** — the SSRF sub-case in file 03 reuses
  the exact same exploitation mechanics (cloud metadata endpoints, DNS
  rebinding, blacklist/whitelist bypass). Read that series first if you
  haven't; this series does not re-explain baseline SSRF theory.
- **SQL Injection / SSTI / OS Command Injection series** — file 02 assumes you
  already understand these injection classes. It focuses only on what's
  different when the *source* of the malicious payload is a third-party API
  response instead of direct user input.
- **Webhook Security series** — heavy overlap, since webhooks are one of the
  most common real-world instances of "unsafe consumption." File 03
  cross-references it directly.
- **API Gateway Security series** — referenced wherever gateway-level
  mitigation is actually applicable (mostly file 03; explicitly *not*
  applicable in most of files 02 and 04).
- **Prototype Pollution series** — referenced in file 04 where merging an
  untyped third-party response into an application object can create
  pollution paths.

## A note on scope and honesty

API10 is the least "lab-friendly" category in the entire Top 10. It is a
design/trust problem more than a payload-crafting problem, and PortSwigger's
Web Security Academy has no dedicated lab track for it. File 05 addresses
this directly rather than pretending otherwise — it explains which existing
lab tracks are mechanically relevant, and where you actually need grey-box
access or your own test infrastructure to find this class of bug at all.

All notes are written in full English. Every attack scenario is broken down
step by step: what the third party returns, how the consuming application
processes it, and why that specific processing step is unsafe.
