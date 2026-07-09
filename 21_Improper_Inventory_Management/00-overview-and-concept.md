# API9:2023 — Improper Inventory Management

## Overview and Core Concept

### 1. What This Vulnerability Actually Is

Improper Inventory Management is not a single injection point or a single broken
function. It is a **governance failure that produces attack surface the security
team does not know exists.** Every other item in the OWASP API Top 10 (BOLA, Broken
Auth, Mass Assignment, SSRF, etc.) assumes you know which endpoints exist and can
test them. API9 is what happens *before* that assumption is true — it is the study
of the endpoints nobody remembered to test, secure, decommission, or even list.

The vulnerability exists because APIs are not static artifacts. They are living
systems that go through:

- **Version churn** — `/v1/` ships, `/v2/` replaces it, `/v3/` replaces that, and
  `/v4/` is "current." Nobody tore down `/v1/` and `/v2/`.
- **Environment sprawl** — dev, staging, UAT, canary, and internal-only hosts get
  spun up for testing and never torn down, and some end up reachable from the
  public internet through misconfigured routing, forgotten DNS records, or a load
  balancer rule nobody audited.
- **Team/product sprawl** — in larger orgs, multiple teams ship APIs independently.
  A marketing team's growth-hacking microservice, a mobile team's undocumented
  "internal" endpoint used only by QA, a partner integration built for one client
  and forgotten — none of these go through the same security review as the
  flagship API.
- **Feature deprecation without endpoint removal** — a feature is turned off in the
  UI, but the backend route that powered it is still live, still routable, and
  still executes the same logic it always did.

### 2. Why This Produces Real Vulnerabilities (Not Just "Untidiness")

The reason API9 is exploitable — not just messy — is that **unmonitored endpoints
tend to have systematically weaker security posture than the endpoints your team
actively works on.** This isn't coincidence, it's a direct consequence of how
security controls get applied in real engineering organizations:

- Security fixes get applied where developers are *currently working*. A
  auth bypass fix that lands in `/v4/users` because that's the active codebase
  frequently never gets backported to `/v1/users`, because nobody thinks about
  `/v1/` anymore — it's not in anyone's sprint board.
- Rate limiting, WAF rules, and API gateway policies are usually configured
  against a known route table. If `/v1/` isn't in that route table (because it
  was never formally decommissioned but also never formally re-registered), it
  may sit *behind* the gateway or *outside* the gateway's policy scope entirely,
  meaning zero rate limiting, zero WAF inspection, zero centralized logging.
- Authentication and authorization middleware is often added incrementally.
  Middleware added to "all routes under `/api/v4/`" by convention does not
  retroactively apply to a legacy blueprint mounted separately in the codebase.
- Monitoring and alerting are built against expected traffic patterns for known
  endpoints. Traffic to a forgotten endpoint doesn't trigger anomaly detection
  because nobody defined a baseline for it — it's invisible by default, not
  because it's hidden, but because nobody is looking.

This is the mechanism you are exploiting throughout this series: **staleness of
security control coverage, not staleness of the endpoint itself.** The endpoint
still works fine. It's the *controls around it* that rotted.

### 3. The Four Inventory Problem Categories Covered in This Series

| Category | Definition | Covered In |
|---|---|---|
| **Deprecated/legacy versions** | Old API versions still live and reachable, lacking controls applied to current versions | File 01 |
| **Shadow endpoints** | Endpoints that exist and function but appear in no documentation, spec, or changelog | File 02 |
| **Zombie endpoints** | Test/debug/internal endpoints accidentally left in or exposed from production | File 02 |
| **Documentation-reality mismatch** | Documented behavior differs from actual behavior (extra params, extra verbs, extra data) | File 03 |

These categories overlap in practice — a shadow endpoint is very often also a
zombie endpoint, and a deprecated version is very often also undocumented — but
they require different discovery techniques, which is why they're separated into
distinct files with distinct methodologies.

### 4. Why WAF / API Gateway Bypass Is Only Partially Relevant Here

Per the standing convention of including a WAF/Gateway section in every series file,
here is the honest scoping for API9 specifically:

**WAF/Gateway bypass in the traditional sense (payload obfuscation to evade
signature matching) is largely NOT applicable to this vulnerability class.**
API9 exploitation usually doesn't involve sending a malicious payload that a WAF
would pattern-match against (no injection strings, no XSS vectors at the discovery
stage). The core exploit primitive is *reaching an endpoint that exists outside the
gateway's awareness in the first place* — you're not evading detection of a bad
payload, you're operating in a location the detection system was never configured
to watch.

However, WAF/Gateway relevance does exist in three concrete ways, and each is
covered where it belongs in this series:

1. **Detection of version/shadow-endpoint discovery activity** — brute-force
   enumeration of paths (`/v1/`, `/v2/`, `/internal/`, `/debug/`) can trigger
   rate-based or pattern-based WAF rules designed to catch directory brute-forcing.
   Covered in File 02 (Shadow and Zombie Endpoint Discovery) since that's where the
   enumeration techniques live.
2. **Gateway routing gaps as the root cause of the vulnerability** — this is
   covered throughout File 01, since it's the actual mechanism, not a bypass
   technique.
3. **Once found, exploiting a legacy/shadow endpoint may involve payloads that
   *do* trigger WAF signatures** (e.g., if the legacy endpoint is vulnerable to
   SQLi or BOLA once reached) — at that point, refer to the WAF bypass sections in
   the relevant sibling series (`sql-injection`, `bola-api1`, etc.) rather than
   duplicating that content here. This series' job is getting you *to* the
   vulnerable endpoint; exploiting what you find there is the job of the
   vulnerability-specific series.

So: no dedicated "WAF bypass payload obfuscation" section exists in this series
because it would be padding, not signal. Where gateway/WAF behavior is genuinely
part of the mechanism, it's folded into the relevant file instead of siloed off.

### 5. Real-World Notes

- The single most common real-world source of API9 findings in bug bounty and
  pentest work is **mobile application API version drift**. Mobile apps update on
  app-store release cycles, not server deploy cycles, so a backend team may keep
  `/v2/` alive for years just to support users who haven't updated their app —
  and that `/v2/` frequently never received the auth hardening that shipped to
  `/v4/` six months ago.
- The second most common source is **acquisitions and internal tooling**. Acquired
  companies bring their own API surface, often documented nowhere the parent
  company's security team has visibility into.
- API9 findings are disproportionately valuable in bug bounty programs because
  they frequently chain directly into API1 (BOLA) or API2 (Broken Authentication)
  findings — the deprecated endpoint doesn't need a *new* vulnerability, it just
  needs to lack a fix that was applied elsewhere. This series should be read
  alongside your BOLA and Broken Authentication notes; cross-references are
  called out inline.

### 6. Series Map

- `01-api-version-exploitation.md` — deprecated version discovery and exploitation
- `02-shadow-zombie-endpoint-discovery.md` — undocumented and leftover endpoint discovery
- `03-documentation-gap-testing.md` — systematic doc-vs-behavior testing
- `04-cheatsheet.md` — condensed reference for active engagements

### 7. PortSwigger Web Security Academy — Applicability Note

PortSwigger's Web Security Academy does not currently maintain a labeled topic
category specifically titled "Improper Inventory Management" or "API9" — this is
expected and disclosed honestly rather than papered over. The relevant labs live
under the **API testing** topic and under general **information disclosure** /
**reconnaissance**-adjacent labs, because the underlying skills (finding hidden
endpoints, exploiting version differences, testing docs against reality) are the
same skills, just not packaged under an API9 label. Full lab mapping with
Apprentice → Practitioner → Expert sequencing is in each individual file, and gaps
are called out explicitly rather than silently omitted. crAPI is used as the
primary hands-on supplement for this specific vulnerability class since it has
purpose-built inventory management challenges that PortSwigger does not.
