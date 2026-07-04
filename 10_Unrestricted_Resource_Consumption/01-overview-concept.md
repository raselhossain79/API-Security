# Unrestricted Resource Consumption — Overview & Core Concept

**OWASP API Security Top 10 2023 — API4:2023**
**Previously named (2019 edition):** "Lack of Resources and Rate Limiting"

---

## 1. What Changed Between 2019 and 2023

In the 2019 OWASP API Security Top 10, this category was named **API4:2019 — Lack of
Resources and Rate Limiting**, and it was framed almost entirely around *rate limiting*:
too many requests per minute, no throttling, no CAPTCHA.

In the 2023 revision, OWASP renamed it **API4:2023 — Unrestricted Resource Consumption**
and deliberately broadened the scope. The reasoning:

- Rate limiting (requests per second) is only **one** dimension of resource exhaustion.
- A single API call with no rate limiting violation at all can still exhaust CPU, memory,
  disk, database connections, or a third party's paid service, if that one call is
  allowed to request or process an unbounded amount of work.
- Cloud-based and serverless APIs introduced a new consequence that didn't exist for
  traditional on-premise apps: **resource consumption now has a direct, unbounded
  dollar cost** (auto-scaling compute, pay-per-use third-party APIs, bandwidth
  egress charges).

So the 2023 definition covers **any** API interaction where the client controls, directly
or indirectly, the amount of a finite resource that gets consumed per request — and the
server does not cap it.

This note series treats rate limiting as a *subset* of Unrestricted Resource Consumption,
not the whole topic, matching the OWASP 2023 framing.

---

## 2. Core Mechanism: Why This Vulnerability Exists

Every API request consumes some combination of finite resources on the server side:

| Resource | Consumed by |
|---|---|
| CPU cycles | Business logic, regex evaluation, image/PDF processing, cryptographic operations |
| Memory (RAM) | Loading large payloads, building large response objects, deserializing large files |
| Disk / storage | File uploads, log writes, temp file creation |
| Database connections / query time | Every DB-backed endpoint, especially unpaginated or unfiltered queries |
| Network bandwidth | Large responses, large uploads, file downloads |
| Third-party API quota / dollar cost | SMS gateways, email providers, payment processors, geocoding APIs, AI/LLM APIs |
| Application-level counters | Login attempts, OTP generation, password reset tokens |

**The vulnerability exists when the API assumes the client will behave "reasonably" and
does not enforce a server-side ceiling on any of the above.** Attackers do not behave
reasonably. If the client can request 10 records, they can request 10,000,000. If the
client can upload a 1 MB file, they can attempt a 10 GB file. If a computation is
triggered by a single API call, it can be triggered a thousand times in parallel.

This is fundamentally the same trust failure as **BOLA (API1)** and **Broken Function
Level Authorization (API5)** — the API trusts client-supplied intent instead of enforcing
server-side limits — but instead of trusting *authorization*, it trusts *scale*.

---

## 3. Categories of Unrestricted Resource Consumption

This series is organized around four practical attack categories, each covered in its
own file:

1. **Missing/weak rate limiting** — no cap on requests per time window
   (file 02: detection methodology)
2. **Resource exhaustion via a single request or small number of requests** — pagination
   abuse, oversized file uploads, algorithmic complexity attacks (ReDoS), expensive
   computation endpoints (file 03)
3. **Third-party spending abuse** — using the API as a proxy to trigger unlimited paid
   calls to SMS/email/payment providers (file 04)
4. **Enumeration and brute-force enabled by absent rate limiting** — user enumeration,
   credential stuffing, OTP brute-force (covered in file 02, cross-referenced with the
   Broken Authentication (API2) series)

---

## 4. Real-World Industry Framing

**Why this matters commercially, not just technically:**

- **Cloud cost attacks ("Denial of Wallet"):** Unlike classic on-prem DoS, cloud-native
  APIs auto-scale. An attacker sending a flood of expensive requests doesn't just slow
  the service down — they directly inflate the victim's AWS/GCP/Azure bill. Security
  researchers and incident responders now treat this as a financial attack vector, not
  purely an availability one.
- **Third-party billing abuse is a recurring bug bounty category.** SMS OTP endpoints
  with no rate limiting have repeatedly been reported (and paid out) on HackerOne and
  Bugcrowd as "SMS bombing" or "cost amplification via unauthenticated SMS trigger."
  Twilio and other SMS providers publish their own guidance to customers on preventing
  this exact abuse pattern, because it happens often enough to warrant vendor-level
  documentation.
- **GraphQL and modern API gateways made this worse, not better.** GraphQL's flexible
  query language lets a client request deeply nested, computationally expensive queries
  in a single POST to a single endpoint — traditional per-endpoint rate limiting doesn't
  see this as "many requests," it sees one request that happens to be enormous.
- **Regulatory and compliance angle:** Uncapped resource consumption is increasingly
  called out in API security frameworks referenced by PCI DSS and SOC 2 auditors,
  particularly for payment and messaging-adjacent APIs, because it's a direct path to
  financial loss for the business, not just the user.
- **Real breach/report pattern:** Multiple bug bounty writeups describe chaining
  unrestricted pagination (dumping entire user tables via `?limit=999999`) with BOLA to
  achieve mass data exfiltration in a handful of requests — this is why API4 is commonly
  chained with API1 in practice, and why this note series explicitly cross-references
  the BOLA notes.

---

## 5. Where the Server-Side Fix Belongs (for defensive/report-writing context)

When writing a vulnerability report or remediation section, resource consumption issues
are fixed by **enforcing limits server-side**, never client-side:

- Rate limiting at the API gateway or middleware layer (per-IP, per-user, per-API-key)
- Hard maximum on `limit`/`page_size` query parameters, enforced server-side regardless
  of what the client requests
- File upload size caps enforced before the file is fully read into memory
- Timeouts and complexity limits on regex evaluation (or switching to non-backtracking
  regex engines like RE2)
- Query cost analysis / depth limiting for GraphQL
- Server-side ceilings on third-party API triggers (e.g., max 3 SMS OTP requests per
  phone number per hour, enforced in the API layer, not the SMS provider's own limits)
- Queueing/throttling expensive computation jobs instead of executing synchronously
  on every request

This note series is written from the **offensive/testing** perspective — how to detect
and prove these issues exist — but understanding the fix is what makes a finding
credible and actionable in a report.

---

## 6. Series Cross-References

- **API1:2023 (BOLA)** — pagination abuse frequently combines with BOLA to mass-exfiltrate
  records the attacker shouldn't see at all, not just in bulk.
- **API2:2023 (Broken Authentication)** — brute force and credential stuffing, covered
  in file 02 of this series, are Broken Authentication issues that are *only exploitable
  at scale* because rate limiting is absent. Full authentication mechanics remain in the
  Broken Authentication series; this series covers the resource-consumption angle.
- **API5:2023 (Broken Function Level Authorization)** — expensive admin-only computation
  endpoints (e.g., "regenerate full report," "recalculate all balances") become resource
  exhaustion vectors if a low-privilege user can also reach them.

---

## 7. Files in This Series

| File | Covers |
|---|---|
| `01-overview-concept.md` | This file — concept, mechanism, real-world framing |
| `02-detection-methodology.md` | Response-based detection, header analysis, timing-based detection, enumeration/brute-force |
| `03-resource-exhaustion-techniques.md` | Pagination abuse, file upload abuse, regex complexity, expensive computation |
| `04-third-party-spending-abuse.md` | SMS/email/payment API cost amplification |
| `05-cheatsheet.md` | Quick reference — commands, payloads, headers, lab map |
