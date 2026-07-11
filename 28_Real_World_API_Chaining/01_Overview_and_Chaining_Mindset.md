# API Security — Real-World Exploitation and Vulnerability Chaining
## Part 1: Overview and Chaining Mindset

### Purpose of This Series

This is the capstone series for the API security note library. It assumes mastery
of all 27 individual API security topics already documented (BOLA, Broken
Authentication, BOPLA/Mass Assignment, API4 Unrestricted Resource Consumption,
API6 Unsafe Business Flows, API8 Security Misconfiguration, API9 Improper
Inventory Management, API10 Unsafe Consumption, GraphQL, JWT, OAuth 2.0, REST API
methodology, injection via API endpoints, API reconnaissance, BFLA, rate
limit/bot protection bypass, race conditions, webhook security, API key
security, API gateway security, SSRF in API contexts, WebSocket/SSE, SOAP/XML,
HTTP/2 attack techniques, and others).

This series does not re-teach any individual vulnerability class. It teaches the
skill that separates a checklist tester from a real-world API pentester: taking
individually "medium" or even "low" severity findings and combining them into a
chain whose cumulative impact is critical. A single BOLA finding on a read-only
endpoint might score Medium. The same BOLA finding, combined with a BFLA gap and
a mass assignment bug, can become a full account takeover with privilege
escalation — a Critical finding with a completely different business impact
narrative.

### Relationship to the Web Application Chaining Capstone

The existing `Real_World_Chaining_Notes/` series already covers general
chaining methodology and report writing structure that applies to any
target type: attack surface mapping mindset, the concept of a "kill chain,"
generic report structure, and generic CVSS scoring mechanics. This series does
not repeat that content. Cross-reference the web app capstone for:

- The general definition of a vulnerability chain and why chains matter more
  to real clients than isolated findings
- Generic report skeleton (executive summary → technical findings →
  remediation → appendix)
- CVSS v3.1 base metric definitions (Attack Vector, Attack Complexity,
  Privileges Required, User Interaction, Scope, C/I/A)

This series focuses only on what is unique to APIs: chains that only exist
because of how APIs are structured (multiple roles calling the same
endpoints, machine-to-machine trust, token-based session state, versioned
and shadow surfaces), and API-specific tooling (Postman as both a testing
and PoC-documentation tool, since API testing workflows lean on Postman far
more heavily than typical web app testing does).

### Why API Chains Are Structurally Different From Web App Chains

Web application chaining typically follows a single authenticated user
through a browser session, pivoting through pages and forms. API chaining
looks different for three structural reasons:

**1. Roles are explicit and comparable.** A REST or GraphQL API usually
exposes the same set of endpoints to multiple role types (anonymous, user,
premium user, admin, service account). This makes cross-role diffing — call
the same endpoint as two different roles and compare responses — the single
most productive discovery technique in API testing. Web apps often don't
expose this cleanly because different roles see entirely different pages,
not the same page with a hidden authorization check.

**2. The "session" is a token, not a cookie jar.** Web app chaining often
relies on the browser silently carrying session state. API chaining requires
explicitly capturing, storing, and re-injecting tokens (JWTs, API keys,
OAuth access/refresh tokens) at every step of a chain. This is why Postman's
variable and test-script system becomes central to API chain work in a way
it rarely is for web app work — see Part 5.

**3. The attack surface has versions and shadows.** APIs accumulate
deprecated versions (`/v1/`, `/v2/`, `/internal/`), staging endpoints, and
service-to-service routes that were never intended for direct external
access. These create chain opportunities that simply don't exist in a
typical server-rendered web app, where there is usually one canonical route
per page. See Part 3 for how to map and exploit this.

### The Core Mental Model: Output-to-Input Chaining

Every chain in this series follows one repeating pattern:

> **Vulnerability A produces something (a token, an ID, a role claim, a
> credential, an internal IP, a piece of PII) that Vulnerability B was not
> designed to receive from an untrusted source, but does anyway.**

When evaluating any individual finding during testing, stop asking only "is
this exploitable on its own?" and start asking two additional questions:

1. **What does this finding hand me?** (a valid session for another user, a
   list of internal object IDs, a role name accepted at face value, an
   internal-only URL, a decoded-but-unverified JWT claim)
2. **Which other endpoint or component would treat that thing as trusted
   input?**

If the answer to question 2 is "none," the finding stays an isolated,
lower-severity issue. If the answer is "yes, endpoint X trusts that value
without re-validating it," you have the first two links of a chain. Part 3
formalizes this into a repeatable methodology; Part 2 formalizes the
technique (cross-role testing) that surfaces most of these findings in the
first place.

### Severity Reframing: Why Chains Change CVSS Outcomes

Individually scored findings understate real risk because CVSS base scoring
evaluates each finding in isolation, using only what that single finding
grants an attacker. A chain should be scored based on the access the
attacker holds **after the full chain completes**, not by summing or
averaging the individual scores of each link. Part 6 of this series
(API-specific report writing) works through worked CVSS examples for
chained findings, including how to justify Scope: Changed when a chain
crosses from the API layer into cloud infrastructure (for example, the
webhook → SSRF → cloud metadata chain in Part 1).

### How to Use This Series While Testing

Recommended order of operation on a real engagement or lab environment:

1. Complete reconnaissance and attack surface mapping (Part 3) before
   attempting any chain — chains are discovered by pattern-matching across a
   mapped surface, not by getting lucky on one endpoint.
2. Run the systematic cross-role test loop (Part 2) across the mapped
   surface. This alone will surface the majority of BOLA/BFLA-based chain
   starting points.
3. For every individual finding logged, ask the two output-to-input
   questions above and log candidate chain links (Part 3).
4. Once a viable chain is identified, rebuild it as a Postman collection
   with chained test scripts before writing it up (Part 4) — this both
   validates reproducibility and produces ready-made PoC evidence.
5. Write the finding using the API-specific chain report structure (Part 5),
   not a generic template.
6. Sanity-check the chain against real-world conditions — WAF behavior,
   token expiry, rate limiting (Part 6) — since lab-clean chains frequently
   break on live targets for reasons that have nothing to do with the
   underlying vulnerability logic.

### Practice Environment Notes

This series references PortSwigger Web Security Academy labs wherever an
individual chain step maps to an existing lab, in Apprentice → Practitioner
→ Expert order, with honest gaps disclosed where PortSwigger has no
equivalent lab. Where PortSwigger has no API-specific coverage for a given
step (this is common for OAuth-to-cloud-metadata chains and for GraphQL
batching-based brute force), crAPI (Completely Ridiculous API) and
HackTheBox are noted as the supplementary environments, consistent with the
convention used across the rest of the note library.

### Real-World Notes

- On real engagements, the highest-impact chains are found by pentesters who
  spend disproportionate time on recon and cross-role mapping relative to
  active exploitation. Teams that jump straight to firing payloads
  consistently miss chains that were sitting in plain sight in the attack
  surface map.
- Bug bounty triagers on platforms like HackerOne and Bugcrowd routinely
  reward chained reports far above the sum of what the individual findings
  would earn separately, specifically because the chain demonstrates
  business impact rather than theoretical risk. A report that says "I could
  read another user's order history" is worth far less than one that says
  "I chained that read access into full account takeover on any account,
  including admin accounts, in under five requests."
- Client-side stakeholders (CISOs, engineering directors) remember chains,
  not CVSS numbers. The chain narrative in Part 5's executive summary
  guidance exists because this is frequently the only part of the report a
  non-technical stakeholder actually reads.

---
Next: `02_API_Exploit_Chain_Patterns.md` — the ten fully worked chain patterns.
