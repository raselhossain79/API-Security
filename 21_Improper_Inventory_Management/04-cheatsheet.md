# API9:2023 — File 4: Improper Inventory Management Cheatsheet

Condensed reference for active engagements. Full methodology and mechanism
explanations live in Files 00–03 — this file assumes that context.

## Quick Mental Model

> Deprecated/shadow/zombie endpoints aren't vulnerable because they're old —
> they're vulnerable because security controls get applied where developers are
> currently working, and nobody is currently working on the endpoint you just
> found.

## Discovery Checklist (Run in This Order)

**Passive first (low detection risk):**
- [ ] Pull and diff current API docs/OpenAPI spec against every JS bundle and sourcemap
- [ ] `grep`/LinkFinder every JS file for path-like strings, especially near `fetch`/`axios` calls
- [ ] Read every response field for IDs/references implying undocumented resources
- [ ] Check `Link`/`_links`/HATEOAS fields in responses
- [ ] Diff responses across user roles/privilege levels for extra fields
- [ ] Trigger verbose errors (malformed body, wrong content-type) and read stack traces
- [ ] `OPTIONS` request on every known endpoint, read the `Allow:` header

**Active second (higher detection risk — pace accordingly):**
- [ ] Fuzz version segments: `/v1/ /v2/ /v3/ /beta/ /internal/` against every known path
- [ ] Fuzz common zombie paths: `/test /debug /_debug /admin /console /actuator /health /qa`
- [ ] Fuzz using terms harvested from JS mining + response inference (higher signal than generic wordlists)
- [ ] Cross-product version fuzzing with path fuzzing

## Version Exploitation Quick Steps

1. Baseline the current documented version's request/response/auth.
2. Try the same path/resource under `v1`–`v(n-1)`, unversioned, and header-based version downgrades.
3. Any non-clean-404 response = route is alive. `401` still counts — means gated only by auth.
4. Diff old vs. new: response fields, required auth, rate limiting, error verbosity, allowed methods.
5. Test authorization on the old version **independently** — never assume parity with current version, in either direction.
6. If old version returns object data without auth or ownership check → sequential ID test → likely full BOLA chain.

## Shadow/Zombie Signal Reference

| Signal | Source | Meaning |
|---|---|---|
| Non-404 on unlisted path | Brute-force | Route is handled server-side |
| Path string in JS not in docs | JS mining | Shadow endpoint candidate |
| Unfamiliar ID/field in response body | Response inference | Related undocumented resource exists |
| `Allow:` header lists undocumented methods | `OPTIONS` request | Broader surface than docs imply |
| Stack trace / internal file path in error | Malformed input | Reveals internal routing/file structure |
| Endpoint named `test/debug/internal/qa` reachable externally | Brute-force + naming prior | Likely zombie endpoint, network isolation assumption broken |

## Documentation-Gap Quick Steps

1. Extract full documented contract: params, types, required/optional, response schema, methods, auth, rate limits.
2. Add undocumented parameters to requests → observe if silently accepted/reflected (mass assignment signal).
3. Diff actual response fields against documented schema, across multiple resource states/roles.
4. Test undocumented HTTP methods via `OPTIONS` + direct calls.
5. Burst-test documented rate limits for actual enforcement.
6. Test documented auth/scope with missing/wrong scope tokens.
7. Test documented input constraints with boundary/invalid values (negative, zero, oversized, null).

## WAF / API Gateway Notes (Summary)

- **File 01 (version exploitation):** minimal WAF relevance — root cause is a routing/policy gap, not a payload a WAF would catch.
- **File 02 (shadow/zombie discovery):** highest WAF relevance — brute-forcing triggers rate-based and pattern-based detection. Prefer passive techniques first; treat brute-force as last resort. Realistic expectation: hardened targets *will* detect aggressive enumeration — plan pacing and client comms accordingly.
- **File 03 (documentation gap):** minimal WAF relevance except rate-limit accuracy testing (Step 5), which behaves like File 02's burst traffic.
- Once inside a vulnerable legacy/shadow endpoint, WAF bypass for the *payload itself* (SQLi, XSS, etc.) is covered in the relevant sibling series (`sql-injection`, `xss`, etc.), not here.

## Command Reference

```bash
# JS mining
python3 linkfinder.py -i https://target.com -d -o results.html
grep -oE '"(/[a-zA-Z0-9_\-/{}\.]+)"' bundle.js | sort -u
grep -iE '(internal|admin|debug|test|staging|beta|_v[0-9]|legacy)' bundle.js

# Version + path fuzzing
ffuf -u https://target.com/api/VER/FUZZ -w endpoints.txt -w versions.txt:VER -mc all -t 40

# Directory/endpoint brute-force with soft-404 filtering
ffuf -u https://target.com/api/FUZZ -w custom-wordlist.txt -mc all -fs 1234 -t 40

# Method enumeration
curl -X OPTIONS -i https://target.com/api/v4/users/42

# Verbose error triggering
curl -X PATCH https://target.com/api/v4/users/1 -d 'not-json'

# Undocumented parameter probing
curl -X POST https://target.com/api/v4/users/42/profile \
  -H "Content-Type: application/json" \
  -d '{"displayName":"test","role":"admin","internalFlag":true}'
```

## PortSwigger Lab Sequence (Consolidated, Difficulty Order)

1. **Apprentice** — Exploiting an API endpoint using documentation
2. **Apprentice** — Finding and exploiting an unused API endpoint
3. **Practitioner** — Exploiting a mass assignment vulnerability
4. **Practitioner** — Information disclosure in error messages
5. **Practitioner** — Information disclosure on debug page
6. **Practitioner** — Broken access control labs (IDOR/BOLA-focused set)
7. **Practitioner** — Discovering GraphQL endpoints / Bypassing GraphQL introspection defenses (if target uses GraphQL)
8. **Expert** — Information disclosure in version control history

**Known gaps (see individual files for full disclosure):** no lab models version
churn (`v1` vs `v4` same-resource control differential) directly; no lab models
JS-bundle mining at scale; no lab models documented-vs-actual rate limit testing.
crAPI fills these gaps — see each file's crAPI section.

## crAPI Consolidated Reference

| Module | What It Covers |
|---|---|
| Community/forum endpoints | Shadow endpoint discovery via response inference |
| Mechanic-role API surface | Zombie/internal endpoint exposure across roles |
| Shop/coupon validation | Legacy logic paths alongside current, undocumented parameter acceptance |
| Vehicle location API | Documented-vs-actual scope/auth enforcement across roles |
| Mobile app client | JS/mobile-binary endpoint mining (endpoints not called by web UI) |

## Reporting Checklist

- [ ] State the version differential explicitly (e.g. "v4 patched, v1 not") — proves inventory failure, not isolated bug
- [ ] Note whether the finding chains into API1/API2/API5 — report the chain, not just the entry point
- [ ] Flag zombie endpoints by likely origin (test/debug artifact vs. network-isolation-assumption failure) — affects remediation advice
- [ ] For documentation-gap findings, quote the documented behavior verbatim next to observed behavior for a clean diff in the report
- [ ] Recommend decommissioning process gaps as a systemic finding, not just the individual endpoint (client will likely have more of these)
