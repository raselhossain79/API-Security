# API Reconnaissance and Endpoint Discovery

A structured note series covering the mandatory first phase of any API penetration test:
finding out what actually exists before attacking any of it. This series sits upstream
of the API Security Top 10 (2023) track — every vulnerability class in that track
(BOLA, broken auth, mass assignment, etc.) is only exploitable against an endpoint you
have first discovered. Weak recon means an incomplete attack surface, which means a
penetration test report that misses real vulnerabilities.

This series follows the same conventions as the web application security note series:
mechanism-first explanations, every command broken down flag by flag, honest disclosure
of PortSwigger Academy coverage gaps, and real-world industry framing throughout.

## Why This Series Exists

Most API security content jumps straight into "here is BOLA, here is how to exploit it"
and assumes you already have a full list of endpoints, parameters, and methods to test.
In practice, that list rarely exists. Modern APIs are sprawling, versioned, partially
documented, and frequently have entire sections that were never meant to be public.
Recon is the phase where a tester converts "I have one Swagger URL" into "I have 340
endpoints across 4 API versions, 60 of which are undocumented." Everything after that is
just applying the API Security Top 10 methodically against a complete map.

## Learning Sequence

Read in this order. Each file assumes the concepts from the ones before it.

| # | File | Covers |
|---|------|--------|
| 1 | `01-overview-and-methodology.md` | The full recon methodology, why order of operations matters, passive-before-active reasoning |
| 2 | `02-passive-reconnaissance.md` | Swagger/OpenAPI spec exposure, JS file mining, Google dorking, Wayback Machine, certificate transparency |
| 3 | `03-active-discovery.md` | Directory/endpoint brute-forcing, HTTP method enumeration, parameter discovery, content-type fuzzing, response-based inference |
| 4 | `04-shadow-and-zombie-apis.md` | Deprecated `/v1/` endpoints still live, undocumented admin endpoints, forgotten test/debug routes |
| 5 | `05-api-documentation-analysis.md` | Reading OpenAPI/Swagger specs, Postman collections, and GraphQL schemas to map the attack surface before testing |
| 6 | `06-cheatsheet.md` | Condensed command reference and pre-engagement checklist |

## Tooling Files

Deep-dive, flag-by-flag references for the four tools this methodology leans on most.
Read these alongside the technique files above, not in isolation — the technique files
explain *when* and *why*, these explain *exactly how*.

| Tool | File | Role |
|------|------|------|
| kiterunner | `tools/kiterunner.md` | Wordlist- and spec-based API endpoint brute-forcing |
| Arjun | `tools/arjun.md` | Automated HTTP parameter discovery |
| ffuf | `tools/ffuf-api-fuzzing.md` | General-purpose fuzzing adapted for API paths, headers, and content negotiation |
| Amass / Subfinder | `tools/amass-subfinder.md` | Subdomain enumeration for `api.*`, `api-*.*`, versioned API subdomains |

## Practice Environment Disclosure

Read this before starting. PortSwigger Web Security Academy has **no dedicated lab
category for API recon and endpoint discovery** as of this writing. It has strong
coverage of individual API vulnerability classes (BOLA-equivalent access control labs,
mass assignment labs, GraphQL labs) but does not teach the discovery phase itself —
Academy labs generally hand you the endpoint list. Where an Academy lab is genuinely
useful for practicing a recon-adjacent skill (e.g., a lab that requires you to find a
hidden API endpoint via JS mining before exploiting it), it is mapped explicitly in the
relevant file with the label **"Recon-adjacent, not recon-dedicated."**

Because of this gap, three alternative platforms carry most of the hands-on practice
weight for this series:

- **crAPI (Completely Ridiculous API)** — OWASP's intentionally vulnerable API, closest
  thing to a realistic microservice architecture with genuine shadow endpoints and
  version sprawl to discover.
- **DVAPI (Damn Vulnerable API)** — lighter weight, good for isolated technique practice
  (single endpoint, single flaw) before moving to crAPI's fuller scope.
- **HackTheBox** — select boxes and the dedicated API-focused tracks provide real
  discovery scenarios (undocumented admin panels, forgotten debug routes) inside a
  broader host-level engagement, closer to real client work than either crAPI or DVAPI.

Each technique file states plainly, per technique, whether Academy has anything to offer
or whether you should go straight to crAPI/DVAPI/HTB.

## Standing Conventions (same as the web app series)

- Every command, flag, and payload is broken down piece by piece — no "just run this."
- PortSwigger lab mappings are listed in official difficulty-progression order, with
  gaps disclosed honestly rather than papered over.
- Real-world industry notes are included in every file — this is not just lab theory.
- Full English only, no Bangla or Banglish, throughout every file in this repository.

## Prerequisites

This series assumes familiarity with core HTTP concepts (methods, headers, status
codes), basic command-line tooling, and — ideally — the SSRF, Broken Access Control, and
Security Misconfiguration files from the web application security series, since shadow
API discovery draws directly on those concepts.
