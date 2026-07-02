# API Reconnaissance and Endpoint Discovery — Overview and Methodology

## 1. Why Recon Comes First

Every API vulnerability class — broken object level authorization, mass assignment,
excessive data exposure, injection, whatever comes next in the API Security Top 10 —
requires an endpoint and a set of parameters to test against. A penetration test that
skips recon and works only from the client's provided documentation will, in almost
every real engagement, test a fraction of what is actually deployed. The gap between
"what the client told us exists" and "what actually exists" is where the most severe
findings tend to live, because that gap is exactly the part nobody has been watching.

Three concrete reasons recon is not optional:

1. **Documentation drift.** Swagger/OpenAPI specs are written once and rarely updated as
   the API evolves. Endpoints get added by developers who never touch the spec file.
   The documented API and the live API are two different things by the time you test.
2. **Version sprawl.** Mobile apps, internal tools, and partner integrations often pin to
   older API versions long after a "current" version is publicly documented. Those old
   versions are frequently still live, unmonitored, and less hardened.
3. **Shadow and forgotten endpoints.** Debug routes, admin panels, and test endpoints
   added during development are the single most common source of critical findings in
   API engagements, precisely because they were never meant to be tested by anyone.

## 2. The Methodology, in Order

Recon proceeds in a specific order for a reason: passive techniques generate zero
traffic to the target and cost nothing to run, so they always come first. Active
techniques generate traffic, can trip rate limiting or WAF rules, and should only be run
once passive recon has already narrowed the target list and given you real
endpoint/parameter names to seed your wordlists with — brute-forcing blind is far less
effective than brute-forcing with informed wordlists.

```
Phase 1 — Passive Recon (zero footprint)
  ├─ Swagger/OpenAPI spec exposure hunting
  ├─ JavaScript file mining for embedded API calls
  ├─ Google/search-engine dorking for exposed docs
  ├─ Wayback Machine / archive mining for old endpoints
  └─ Certificate transparency logs for API subdomains

Phase 2 — Documentation Analysis (if any docs were found in Phase 1)
  ├─ Parse OpenAPI/Swagger spec: paths, methods, parameters, schemas
  ├─ Parse Postman collections: saved requests, environment variables, auth flows
  └─ Introspect GraphQL schemas: types, queries, mutations, deprecated fields

Phase 3 — Active Discovery (targeted, informed by Phases 1–2)
  ├─ Endpoint/directory brute-forcing (wordlist- and spec-seeded)
  ├─ HTTP method enumeration per discovered endpoint
  ├─ Parameter discovery per endpoint
  ├─ Content-type fuzzing
  └─ Response-based inference (diffing responses to guess hidden structure)

Phase 4 — Shadow and Zombie API Identification
  ├─ Version enumeration (/v1/, /v2/, /internal/, /beta/)
  ├─ Cross-reference discovered endpoints against official documentation
  └─ Flag anything live-but-undocumented for priority testing
```

The output of this whole process is not a vulnerability list — it is an **asset
inventory**: every host, every API version, every endpoint, every parameter, every
method that responds. That inventory becomes the actual test plan.

## 3. What "Done" Looks Like

A recon phase is complete enough to move into vulnerability testing when you can answer
all of the following with confidence:

- What API versions exist, and which of them are actually reachable right now (not just
  the one referenced in the current front-end)?
- For each reachable version, what is the full list of endpoints, including anything
  found only via JS mining, brute-forcing, or archived snapshots — not just what's in
  the official docs?
- For each endpoint, which HTTP methods does it actually accept, versus which methods
  the documentation claims it accepts?
- What parameters does each endpoint accept, including undocumented ones found through
  parameter discovery?
- Is there a GraphQL endpoint, and if so, is introspection enabled?
- Are there any endpoints whose naming, response shape, or comments suggest they are
  debug, test, internal, or admin-only — even if they're technically reachable from the
  public internet?

If any of these are still unknown, recon isn't finished — resist the urge to jump into
exploitation testing with an incomplete map. This is the single most common shortcut
that produces a shallow, embarrassing report later.

## 4. Real-World Notes

- On real engagements, mobile applications are consistently the richest passive-recon
  source for API endpoints. Decompiling an Android APK or inspecting an iOS app bundle
  frequently reveals a full base URL, API keys, and endpoint paths hardcoded in strings
  — often for API versions the web client doesn't even reference anymore. This series
  focuses on web-facing recon techniques, but on a mobile-inclusive scope, treat the app
  binary as a first-class recon target alongside the JS bundles covered in file 2.
- Bug bounty programs increasingly scope explicitly by API version or subdomain (e.g.
  "api.example.com is in scope, api-legacy.example.com is not"). Certificate
  transparency and subdomain enumeration (`tools/amass-subfinder.md`) are how you find
  out whether that legacy host still resolves and still responds — it is common for
  out-of-scope hosts to still be live and misconfigured, which matters for
  responsible disclosure even when you can't formally report against it.
- Shadow API discovery (file 4) is consistently cited in industry reports — Salt
  Security's and Gartner's API security research being the most frequently referenced —
  as the leading cause of major API breaches, ahead of any single vulnerability class.
  The recon phase is where that risk gets caught or missed.

## 5. Next File

Continue to `02-passive-reconnaissance.md` for the first phase in detail.
