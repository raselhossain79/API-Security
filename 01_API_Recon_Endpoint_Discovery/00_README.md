# API Reconnaissance and Endpoint Discovery — Note Series

This series covers the mandatory first phase of any API penetration test: finding
out what actually exists before attempting to break anything. It follows the same
structure and conventions as the companion web application security note series
(SQLi, XSS, SSRF, etc.).

## Why This Phase Matters

You cannot test an endpoint you don't know exists. In API pentesting, the attack
surface is frequently larger than what is documented — deprecated versions,
undocumented admin routes, debug endpoints, and internal-only paths accidentally
exposed all live outside the "official" API surface. Recon determines whether a
test is thorough or whether it only covers the 20% of the API that the client
handed you in a Postman collection.

## File Index

| # | File | Covers |
|---|------|--------|
| 1 | `01_Overview_and_Methodology.md` | What API recon is, methodology flow, scoping, WAF/Gateway relevance statement, practice environment overview |
| 2 | `02_Passive_Recon.md` | Swagger/OpenAPI exposure, JS file mining, Google dorking, Wayback Machine, certificate transparency logs |
| 3 | `03_Active_Discovery.md` | Directory/endpoint brute-forcing, HTTP method enumeration, parameter discovery, content-type fuzzing, response-based inference, shadow/zombie API identification, spec analysis |
| 4 | `04_Tooling.md` | kiterunner, Arjun, ffuf, Amass, Subfinder — full flag-by-flag breakdowns |
| 5 | `05_Cheatsheet.md` | Condensed command reference for live engagements |

## How to Use This Series

1. Read the Overview file first — it sets the methodology and explains why some
   sections (like WAF bypass) apply differently here than in exploitation-focused
   series.
2. Work through Passive Recon before Active Discovery. Passive recon is silent,
   free, and often reveals more than brute-forcing ever will. Never skip straight
   to brute-forcing.
3. Use the Tooling file as a reference while executing — every flag is explained
   so you're not copy-pasting commands you don't understand.
4. Use the Cheatsheet during live engagements once you already understand the
   underlying mechanics from the other files.

## Conventions Used Throughout

- **Mechanism-first**: every technique explains *why* it works before showing
  *how* to run it.
- **Flag-by-flag breakdowns**: no command is ever presented as "just run this."
- **PortSwigger lab mapping**: labs are listed in official Apprentice →
  Practitioner → Expert order where they exist. This topic has limited direct
  PortSwigger coverage (Academy focuses on exploitation, not recon), so gaps are
  disclosed honestly rather than papered over.
- **Alternative practice environments**: crAPI (OWASP) and HackTheBox API
  challenges are used to fill the practice gap, with an explanation of what each
  one actually covers.
- **Real-world notes**: every file distinguishes lab behavior from what you'll
  actually encounter on real, production targets.
- **Language**: written entirely in English, no exceptions.

## Prerequisites

Familiarity with basic HTTP (methods, status codes, headers), REST API concepts
(resources, versioning, JSON bodies), and comfort with a Linux terminal. If you
haven't yet built the API Fundamentals and Web Fundamentals prerequisite notes,
review those first — this series assumes that foundation.
