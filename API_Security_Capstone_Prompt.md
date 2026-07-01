# API Security Capstone — Real-World Exploitation & Chaining

> Build this LAST — after completing all 24 API Security note series topics. This is
> not about any single vulnerability type. It covers how to combine individual API
> vulnerabilities into high-impact chains, how to think like a real API attacker, and
> how to document and report chained findings professionally.
>
> The web application security repo has a similar capstone (Real_World_Chaining_Notes/)
> covering web app chains. This one is specifically for API chains — different attack
> patterns, different methodology, different reporting requirements. Cross-reference the
> web app capstone for any overlapping concepts rather than duplicating them here.

---

## Prompt (paste into a new chat)

```
I'm building a final, capstone note series called "API Security — Real-World
Exploitation & Chaining" — meant to be read AFTER completing all 24 individual API
security note series topics (BOLA, JWT attacks, OAuth, GraphQL, BFLA, BOPLA, Webhook
Security, etc). This is not about any single vulnerability type — it's about the
methodology and skills that bridge "I can find an individual API vulnerability" to
"I can chain multiple API findings into a critical-impact path and document it
professionally."

Cross-reference my web application security capstone (Real_World_Chaining_Notes/)
for overlapping concepts like general chaining mindset and report writing structure —
don't duplicate that content here. Focus entirely on what's unique to API security.

Requirements:

PART 1 — API-SPECIFIC CHAIN PATTERNS:
Cover vulnerability chaining specifically in API contexts — combining individually
low-severity API findings into critical-impact chains. Include all of the following
real-world API chain patterns, each broken down step by step (what bug A produces, how
bug B consumes it, why the combination is critical):
- BOLA + BFLA → full account takeover (access another user's object via BOLA,
  then use BFLA to execute an admin function on that object)
- JWT algorithm confusion → claim manipulation → BFLA → remote code execution
  (forge a token as admin, execute privileged function that triggers RCE)
- OAuth redirect_uri bypass → authorization code theft → account takeover
- GraphQL introspection → hidden admin mutations discovery → BFLA → privilege
  escalation (introspection reveals endpoints the UI doesn't show)
- Webhook URL registration → SSRF → cloud metadata endpoint → AWS credential theft
  → lateral movement into cloud environment
- Improper inventory management (old API version) + missing authentication on
  deprecated endpoint → authentication bypass → BOLA → mass data exfiltration
- API key leakage (exposed in git repo/JS bundle) → BOLA enumeration → full
  database scrape
- BOPLA (mass assignment) + BFLA → privilege escalation to admin role
- Rate limit bypass (X-Forwarded-For spoofing) + Broken Authentication → admin
  account brute force → full compromise
- GraphQL batching/alias attack → OTP/2FA brute force bypass → account takeover

PART 2 — MULTI-ROLE API TESTING METHODOLOGY:
Cover how to approach API testing when multiple user roles exist (regular user, premium
user, admin, service account, API partner). Include:
- How to set up multi-role testing in Burp Suite (multiple browser profiles, session
  tokens, switching between roles efficiently)
- How to use Postman environments for multi-role testing (separate environment
  variables per role, collection runner for systematic cross-role testing)
- The systematic process: test every endpoint as role A, then repeat as role B, diff
  the responses — this is the core BOLA/BFLA discovery loop
- How to identify role-specific endpoints that other roles shouldn't access

PART 3 — CHAIN BUILDING METHODOLOGY:
Cover how to think about building chains from individual findings:
- Mapping the API's full attack surface first (all endpoints, all roles, all data
  objects) before trying to chain
- Tracking "low severity" individual findings instead of discarding them — a BOLA
  that only returns non-sensitive data + a BFLA on a related endpoint may chain into
  something critical
- Finding where one bug's output (a leaked token, an object ID, a role field) becomes
  another bug's input
- API-specific chain building: how API versioning mismatches, shadow endpoints, and
  service-to-service trust create chain opportunities not present in traditional web apps

PART 4 — POSTMAN COLLECTION-BASED CHAIN DOCUMENTATION:
Cover how to use Postman to document and reproduce multi-step API exploit chains:
- Structuring a Postman collection as a step-by-step exploit chain (each request as
  a named step, variables passing data between steps automatically)
- Using Postman's test scripts to extract tokens/IDs from responses and pass them to
  subsequent requests in the chain
- Exporting a collection as evidence for a client report (so the client can reproduce
  the chain themselves)
- The difference between a Postman PoC collection (for the report) vs a testing
  collection (for your own workflow during the engagement)

PART 5 — API-SPECIFIC REPORT WRITING:
Cover how API pentest reporting differs from web app reporting:
- How to document BOLA/BFLA findings so the client understands the impact (not just
  "authorization check missing" — show the actual data accessed or function executed)
- CVSS v3.1 scoring for API-specific findings: how to score BOLA (often higher than
  traditional IDOR because API BOLA typically affects all objects, not just one)
- How to document a multi-step chain clearly: step-by-step reproduction, what each
  step requires as input, what it produces as output, cumulative impact statement
- Evidence requirements for API findings: raw HTTP requests/responses in Burp,
  Postman collection export, response diffs showing cross-role data access
- How to communicate API findings to non-technical stakeholders (the executive summary
  section of an API pentest report)

PART 6 — REAL-WORLD ADAPTATION:
Cover how real API targets differ from lab environments:
- WAF/gateway behavior on real API targets vs clean lab environments
- How to handle APIs with rate limiting during a chain that requires multiple requests
- Dealing with short-lived tokens mid-chain (token refresh automation)
- Identifying when a chain "should work" but doesn't due to environmental factors
  (caching, load balancing, eventual consistency)

FILE BREAKDOWN:
Break into multiple separate files:
1. Overview — API chaining mindset, why API chains differ from web app chains,
   how to use this capstone alongside the web app capstone
2. API-specific chain patterns (all 10 from Part 1, each fully documented)
3. Multi-role testing methodology (Part 2)
4. Chain building methodology (Part 3)
5. Postman collection-based chain documentation (Part 4)
6. API-specific report writing (Part 5)
7. Real-world adaptation (Part 6)
8. README.md indexing all files

Additional requirements:
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every chain example must be broken down step by step — explain exactly
  what each step does, what it produces, and how it feeds into the next step. Never
  describe a chain as just "A leads to B" without explaining the mechanism connecting
  them. Every Postman script and Burp workflow shown must be broken down piece by piece.

Please plan the file breakdown first, then build each file. When all files are complete, provide them as a single ZIP file for direct download.
```
