# REST API Testing Methodology — Part 7: Consolidated Methodology Checklist

## Series Position

This is the final file in the REST API-Specific Testing Methodology series. It does not introduce new technique — it consolidates Parts 1–6 into a single, engagement-ready checklist and sequencing guide, structured the way you would actually walk through a real API pentest or bug bounty target from first contact to report writing.

Use this file as the working document during an actual engagement. Use Parts 1–6 as the reference material you return to when a checklist item needs the full "why" and "how" behind it.

---

## Phase 0 — Scope and Access Confirmation

- [ ] Written scope explicitly lists the API host(s) in question
- [ ] Test credentials obtained for every distinct role the API defines (unauthenticated, each user tier, admin, and each tenant if multi-tenant)
- [ ] Rate limit / WAF behavior expectations clarified with the client where possible, to avoid unplanned lockouts mid-engagement
- [ ] Confirmed whether shadow/undocumented hosts discovered during recon (Part 1) fall inside or outside written scope before testing them

---

## Phase 1 — Reconnaissance and Baseline (Part 1)

- [ ] API specification (OpenAPI/Swagger, GraphQL introspection if relevant, public dev docs, Postman public collections) located and fully read
- [ ] Every path + method + parameter extracted into a working endpoint matrix
- [ ] Traffic-based mapping completed: full application usage proxied across every available role
- [ ] JS bundles / decompiled mobile app resources searched for undocumented routes and hardcoded internal hosts
- [ ] Baseline response recorded for every endpoint × documented method × role (status, headers, full body shape, rough response time)
- [ ] Burp configured: spec imported, Match and Replace rules built for per-role token swapping, Content-Length auto-update confirmed
- [ ] Postman configured: spec imported as collection, per-role environments built

**Exit condition for Phase 1:** every endpoint in the matrix has a recorded baseline for at least one role before any attack technique from Phases 2–5 begins.

---

## Phase 2 — HTTP Method Testing (Part 2)

- [ ] All 7 core methods (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD) tested against every endpoint in the matrix
- [ ] `OPTIONS` `Allow` header recorded per endpoint, treated as a hint rather than ground truth
- [ ] Every non-404/405 result diffed against the Phase 1 baseline (full response, not status code alone)
- [ ] Method override headers/parameters tested on top of `POST` (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, `_method`)
- [ ] Case variation spot-checked on at least one representative endpoint
- [ ] Every confirmed live undocumented method flagged for role-differential testing in Phase 5

---

## Phase 3 — API Versioning Attacks (Part 3)

- [ ] All versioning schemes in use identified (path, header/media-type, query parameter, subdomain)
- [ ] Version enumeration swept across every endpoint in the matrix (not sampled)
- [ ] Every discovered old/alternate version confirmed genuinely live (not a stub/redirect/410)
- [ ] Authorization re-tested on every old version, every role
- [ ] Rate limiting / brute-force protection re-tested on every old version
- [ ] Previously-rejected input validation payloads replayed against every old version
- [ ] Response schemas diffed field-by-field between versions for sensitive over-exposure
- [ ] Content-negotiation-based (`Accept`/media-type) versioning explicitly checked, not assumed absent

---

## Phase 4 — Content-Type Manipulation (Part 4)

- [ ] Accepted content types established per endpoint: JSON (baseline), XML, `text/plain`, `x-www-form-urlencoded`, `multipart/form-data`
- [ ] Any endpoint confirmed to accept XML flagged and escalated to full XXE testing methodology
- [ ] Any endpoint confirmed to accept `text/plain` or `x-www-form-urlencoded` flagged for CSRF-preflight-exemption implications
- [ ] Previously-rejected JSON payloads replayed across every accepted content type to check validation consistency (mass-assignment-via-content-type check)
- [ ] Malformed-body error verbosity compared across every accepted content type
- [ ] `Accept` header varied independently to check response-serializer field over-exposure
- [ ] Malformed/unusual `Content-Type` header values tested for fail-open parsing

---

## Phase 5 — Response Differential Analysis (Part 5)

- [ ] Vertical role differential run on every endpoint that appears restricted by naming, documentation, or path structure
- [ ] Horizontal (BOLA) differential run on **every** object-ID-parameterized endpoint — this is the single highest-priority item in the entire series; do not sample, cover exhaustively
- [ ] Tenant-boundary differential run separately, if the target is multi-tenant
- [ ] Every finding from Phases 2–4 (live undocumented methods, live old versions, accepted alternate content types) re-run through full role-differential testing here
- [ ] Parameter value differential run for empty/wildcard/null-byte/type-mismatch/duplicate-parameter cases
- [ ] Error-response distinguishability checked for existence-oracle leakage
- [ ] Timing differential attempted (multi-sample) where body/status differentials are inconclusive
- [ ] Every positive finding recorded as a full request/response pair

---

## Phase 6 — Parameter Fuzzing (Part 6)

- [ ] Type confusion matrix run against every documented field
- [ ] Object-for-string substitution tested on string fields for downstream query-operator injection (NoSQL injection escalation path)
- [ ] Undocumented field injection tested at every nesting level (mass assignment escalation path)
- [ ] Excessive nesting depth tested for parser DoS behavior
- [ ] Null/missing intermediate nested objects tested
- [ ] Single-value-to-array and array-to-single-value substitution tested
- [ ] Bulk/batch endpoints tested for per-element validation consistency and duplicate-entry logic bypass
- [ ] Structural mutation fuzzing automated rather than fully manual

---

## Phase 7 — Cross-Phase Escalation Tracking

Findings from this series frequently chain into vulnerability classes covered in other series. Track escalations explicitly rather than treating each phase's findings in isolation:

| Trigger (this series) | Escalate to |
|---|---|
| XML content-type accepted (Phase 4) | XXE series — full exploitation methodology |
| Object-for-string field accepts operators (Phase 6) | NoSQL Injection series |
| Undocumented field survives validation (Phase 4 / Phase 6) | Mass Assignment series |
| BOLA/BFLA confirmed (Phase 5) | OWASP API Security Top 10 series — API1/API5 |
| JWT-based auth in use anywhere in the target | JWT Attacks series — apply in parallel, not sequentially, since token-level attacks are independent of this series' endpoint-level methodology |
| OAuth-based auth in use anywhere in the target | OAuth 2.0 Attacks series — apply in parallel, same reasoning |
| Multipart acceptance found on non-upload-looking endpoint (Phase 4) | File Upload vulnerability series |
| CSRF-exempt content type accepted (Phase 4) | CSRF series |

---

## Phase 8 — Report Writing Discipline

- [ ] Every finding includes the full request/response pair that demonstrates it, not a paraphrase
- [ ] Every differential finding (Phase 5 especially) shows the **control** request/response alongside the **variable-changed** request/response, not just the successful exploit request alone
- [ ] Severity framed by real-world impact (tenant-boundary BOLA > same-tier horizontal BOLA > information-only leak, as a general — not absolute — ordering)
- [ ] Remediation guidance references the specific layer where the gap exists (e.g., "authorization middleware is applied to `/v2/` routes but not backported to `/v1/`" rather than a generic "add access control" statement) — this level of specificity is what separates a report a development team can act on quickly from one that requires them to re-discover your own reconnaissance work
- [ ] Old-version and undocumented-method/endpoint findings explicitly flagged for inventory-management remediation (OWASP API9:2023) in addition to whatever specific vulnerability was found there, since the root cause (an unmaintained, forgotten surface) will keep producing new findings until the inventory gap itself is addressed

---

## Series Summary

This series is intentionally procedural rather than payload-focused. Its core discipline, repeated across every phase, is:

1. **Map exhaustively before attacking** (Part 1).
2. **Vary one thing at a time against a recorded baseline** — method (Part 2), version (Part 3), content-type (Part 4), role/parameter/object (Part 5), type/structure (Part 6).
3. **Treat every unexpected match between "should be different" conditions as the finding itself**, not the payload that triggered it.

This mindset — comparison-driven, baseline-anchored testing — is what distinguishes systematic API assessment from ad hoc endpoint poking, and is the reason the highest-value, most-reported real-world API findings (BOLA, BFLA, version regression, mass assignment via content-type) are consistently found by testers who follow a structured differential process rather than by testers relying on payload lists alone.

**End of series.** Refer back to Parts 1–6 for full technical depth on any checklist item above.
