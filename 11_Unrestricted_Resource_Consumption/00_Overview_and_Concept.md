# API4:2023 — Unrestricted Resource Consumption

## Overview and Concept

### 1. What This Vulnerability Actually Is

Unrestricted Resource Consumption (API4:2023) occurs when an API does not properly
limit the number, size, or frequency of requests a client can make, nor the amount
of server-side resource (CPU, memory, disk, bandwidth, database connections, or
third-party spend) that a single request can consume.

This is fundamentally different from a single "vulnerability class" like SQL
injection. It is a **missing control** — the absence of throttling, quota
enforcement, or resource-usage limits — that turns normal API functionality
into a resource exhaustion vector. The API logic can be functionally correct
and still be exploitable purely because nothing stops a client from calling it
too often, requesting too much, or feeding it inputs that are disproportionately
expensive to process.

This replaces what was API4:2019 "Lack of Resources & Rate Limiting" in the
previous OWASP API Top 10 revision, broadened to explicitly include third-party
service cost abuse (Denial of Wallet) as a first-class concern, not just
server CPU/memory exhaustion.

### 2. Why APIs Are Especially Exposed to This

Traditional web applications often have implicit friction: page loads render
HTML, JavaScript executes client-side delays, and a human is usually driving
the browser. APIs remove that friction:

- Machine-to-machine calls can be fired in tight loops with no rendering delay.
- API responses are typically small and structured (JSON), so an attacker can
  send thousands of requests per second without waiting on page paint.
- Many APIs are designed for legitimate high-volume consumption (mobile apps
  polling, batch integrations), which makes it harder to distinguish abuse from
  normal load using volume alone.
- Backend logic is often abstracted behind a gateway that developers assume is
  "already handling" rate limiting, when in practice it is not configured or
  covers only a subset of routes.

### 3. Impact Categories Covered in This Series

This series treats "resource consumption" broadly, matching the four impact
categories most relevant in real engagements:

| Category | What Gets Exhausted | File Reference |
|---|---|---|
| Compute/Memory/Disk | CPU cycles, RAM, disk I/O, DB connections | `02_Resource_Exhaustion_Techniques.md` |
| Financial (Denial of Wallet) | Real money via third-party paid APIs | `03_Third_Party_Spending_Abuse.md` |
| Enumeration surface | Account/credential/object ID space | Cross-referenced to Broken Authentication + BOLA series |
| Availability | Uptime, response time, concurrent capacity | `02_Resource_Exhaustion_Techniques.md` |

### 4. Relationship to Existing Series (Cross-References, Not Repetition)

This series assumes you have already read the following from the note library
and will not re-explain their core mechanics:

- **Broken Authentication (API2) series** — for the mechanics of credential
  stuffing and brute-force attacks. This series covers only *why absent rate
  limiting is what makes those attacks feasible at scale*, not the attacks
  themselves.
- **BOLA (API1) series** — for the mechanics of object ID enumeration. This
  series covers only the rate-limiting angle that turns a slow manual BOLA
  check into an automatable mass-enumeration attack.
- **API Reconnaissance and Endpoint Discovery series** — for identifying
  which endpoints exist before you test them for resource limits.
- **Rate Limit / Bot Protection Bypass series** — this is the closest sibling
  series. That series focuses on *bypassing* rate limiting once you know it
  exists (IP rotation, header spoofing, distributed sources). This series
  focuses on *detecting whether limiting exists at all* and *what damage is
  possible once you confirm it doesn't*. Read that series after this one for
  the case where limiting exists but is poorly implemented.

### 5. Why WAF/API Gateway Bypass IS Meaningfully Relevant Here

Unlike some purely logic-based vulnerabilities (e.g., BOLA, mass assignment)
where a WAF has almost nothing to pattern-match against, resource consumption
attacks are frequently the **primary thing WAFs and API gateways are deployed
to stop**. Rate limiting, request throttling, and anomaly-based blocking are
core API gateway features (AWS API Gateway usage plans, Kong rate-limiting
plugin, Cloudflare rate limiting rules, Azure APIM throttling policies).

This means, unlike other series in this library where a WAF section might be
thin, this vulnerability class has a **dedicated, substantial WAF/Gateway
section in every technical file**, covering:

- How rate limiting is typically implemented at the gateway layer (fixed
  window, sliding window, token bucket, leaky bucket)
- What signals gateways use to detect abuse beyond simple request counts
  (behavioral/anomaly detection, device fingerprinting, JA3/TLS fingerprinting)
- Realistic bypass considerations specific to each attack technique (these are
  covered per-technique in files 2–4, not repeated generically)

Full generic bypass techniques (IP rotation, distributed botnets, header
manipulation) are intentionally **not re-explained here** — see the
**Rate Limit / Bot Protection Bypass series** for that content in depth. This
series covers only bypass considerations that are specific to *resource
exhaustion payload construction*, which the bypass series does not cover.

### 6. Testing Environments Used in This Series

- **PortSwigger Web Security Academy** — primary lab environment. Labs are
  mapped in Apprentice → Practitioner → Expert order in each technical file,
  with honest disclosure of coverage gaps where PortSwigger does not have a
  dedicated lab for a technique.
- **crAPI (Completely Ridiculous API)** — supplementary practice environment,
  referenced where it fills a gap PortSwigger does not cover (particularly
  around realistic third-party spend simulation and OTP/SMS-triggering
  endpoints, which PortSwigger's academy does not model).

### 7. Real-World Note

In bug bounty and pentest engagements, unrestricted resource consumption is
one of the most commonly *under-reported* API vulnerabilities — not because
it's rare, but because testers often stop at "I sent 50 requests and nothing
blocked me" without going further to demonstrate concrete impact (a dollar
figure for Denial of Wallet, a CPU-time delta for ReDoS, or a completed
enumeration of a user ID space). Programs increasingly require quantified
impact for this class to accept anything above a low/informational severity.
This series is built around producing that quantified evidence, not just
proving the absence of a header.

### 8. File Index

See `README.md` for the full file index and reading order.
