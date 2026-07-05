# BFLA — Final Cheatsheet
### API5:2023 — Broken Function Level Authorization

---

## Quick definition

BFLA = authenticated but under-authorized access to a **function/endpoint** that should require a different (usually higher) role. Contrast with BOLA (API1) = under-authorized access to a **data object**, same function, wrong ID.

**One-line distinguishing test:** does the bug break by changing an *ID* (BOLA) or by calling a *different route/action entirely* (BFLA)?

---

## Testing checklist (in order)

- [ ] Enumerate every endpoint the app's normal UI calls (proxy history baseline)
- [ ] **Discovery** — path guessing, JS/APK source mining, OpenAPI/GraphQL introspection diffing, response field inference, `OPTIONS` probing for `Allow:` header
- [ ] For every candidate privileged endpoint: replay with a **lower-privilege token**, verify server-side state, not just response code
- [ ] Try **HTTP method switching** on every candidate: GET/POST/PUT/PATCH/DELETE + malformed methods (`POSTX`)
- [ ] Try **path manipulation**: version downgrade (`/v1/` vs `/v2/`), case changes, double slashes, trailing slash, path traversal segments, `X-Original-URL`/`X-Rewrite-URL` headers
- [ ] Try **parameter-based role injection** in write bodies (`roleId`, `isAdmin`, `permissions`, `accountType`) on profile/account update and registration endpoints
- [ ] Test **vertical escalation** (regular user → admin function) and **lateral escalation** (User A → function scoped to User B's privileged context)
- [ ] Run a full **Autorize** sweep across the entire proxied session for coverage, manually validate every "Bypassed!" flag
- [ ] Confirm every finding with actual state verification (re-fetch/re-login, don't trust response body alone)
- [ ] Classify precisely in the report: BFLA vs BOPLA/mass-assignment vs BOLA where behavior overlaps — note the overlap explicitly rather than picking one label and hiding the ambiguity

---

## Pattern reference table

| Pattern | Core trick | Root cause | PortSwigger lab match |
|---|---|---|---|
| Method switching | `PUT`→`GET`/`PATCH` on same route | Authz middleware bound to specific verb, not route | Method-based access control can be circumvented |
| Path manipulation | version/case/slash/traversal variants | Enforcement layer normalization ≠ router normalization | URL-based access control can be circumvented |
| Parameter role injection | add `roleId`/`isAdmin` to write body | Mass-binding without field allow-list | User role controlled by request parameter; User role can be modified in user profile |
| Naive baseline swap | swap token, same request | No role check at all on handler | Unprotected admin functionality (x2) |
| Multi-step gap | skip to a later step in a flow | Access control only checked on step 1 | Multi-step process with no access control on one step |
| Trust-based header | `Referer`-derived authz decision | Client-controlled header used for security decision | Referer-based access control |

---

## PortSwigger Web Security Academy — Access Control lab map (Apprentice → Practitioner)

**Honest gap disclosure:** the "Access control vulnerabilities" topic on PortSwigger Web Security Academy currently only has **Apprentice** and **Practitioner** tiers — there is no published **Expert**-tier lab in this specific topic as of this writing. Where the requirement calls for full Apprentice→Practitioner→Expert progression, this topic simply doesn't have an Expert rung yet; don't let that gap get silently smoothed over. If PortSwigger adds one later, it would slot in after the Practitioner labs below.

Also note: not every lab in this topic is BFLA. Several are pure **BOLA** (object-ID manipulation with no function-tier change) and are marked as such below so the distinction from file 01 stays concrete rather than theoretical.

### Apprentice

| # | Lab | BFLA or BOLA? | What it teaches |
|---|---|---|---|
| 1 | Unprotected admin functionality | **BFLA** | Admin panel with zero access control, found via `/robots.txt` disclosure |
| 2 | Unprotected admin functionality with unpredictable URL | **BFLA** | Same as above, URL disclosed via page source/JS instead of robots.txt |
| 3 | User role controlled by request parameter | **BFLA** | Client-controlled `roleid` parameter on profile update — direct match to pattern 3 in this series |
| 4 | User role can be modified in user profile | **BFLA** | Same family, role field settable via account/profile edit form |
| 5 | User ID controlled by request parameter | BOLA | Horizontal escalation via `id` swap — included for contrast, not BFLA |
| 6 | User ID controlled by request parameter, with unpredictable user IDs | BOLA | Same, with GUIDs instead of sequential IDs — BOLA, not BFLA |
| 7 | User ID controlled by request parameter with data leakage in redirect | BOLA | BOLA via redirect response leakage |
| 8 | User ID controlled by request parameter with password disclosure | BOLA | BOLA leading to credential exposure |
| 9 | Insecure direct object references | BOLA | Classic IDOR, BOLA family |

### Practitioner

| # | Lab | BFLA or BOLA? | What it teaches |
|---|---|---|---|
| 10 | URL-based access control can be circumvented | **BFLA** | Front-end proxy path-block bypass via alternate path structure / rewrite headers — direct match to pattern 2 |
| 11 | Method-based access control can be circumvented | **BFLA** | HTTP method switching to reach a privileged action — direct match to pattern 1 |
| 12 | Multi-step process with no access control on one step | **BFLA** | Access control enforced on step 1 of a flow but not later steps — jump straight to the unprotected step |
| 13 | Referer-based access control | **BFLA** | Authorization decision trusts a client-controlled `Referer` header instead of session/role state |

**Recommended solve order for BFLA-focused practice:** labs 1, 2, 3, 4 (Apprentice) → 11, 10, 13, 12 (Practitioner, roughly in that order since method-switching and URL-based bypass build most directly on the pattern work in file 03). Labs 5–9 are worth solving for BOLA practice (see the BOLA-specific note series) but aren't BFLA reference material.

---

## crAPI (OWASP) — supplementary BFLA practice

crAPI is API-native (not PortSwigger's browser-app style), so it's valuable specifically for practicing BFLA discovery techniques against a real REST/microservice structure rather than a single monolith app.

| Challenge | What it covers | Relevance |
|---|---|---|
| Challenge 7 — Delete another user's video via admin endpoint | Find an internal/admin-only video-delete endpoint via response field inference (an internal property exposed in an ordinary API response reveals the admin path), then call it directly | **Core BFLA challenge** — direct match to discovery technique 4 (response field inference) + baseline exploitation from file 03 |
| Challenge 2 — Access mechanic reports of other users | `report_id` parameter enumeration | This is **BOLA**, not BFLA (same function, different object ID) — useful for contrast, covered fully in the BOLA note series |
| Challenges 8–10 — Mass assignment (free item, balance increase, internal video property update) | Over-permissive field binding on write endpoints | **BOPLA/API3 territory**, but mechanically identical to pattern 3 in this series (parameter-based role/field injection) — good practice for the "is this BFLA or BOPLA" classification judgment call discussed in file 03 |
| `OPTIONS` method probing across crAPI's Postman collection endpoints | Method enumeration via `Allow:` header | Reinforces discovery technique 4 (OPTIONS probing) at API scale |

**Setup:** crAPI runs via Docker Compose (`docker-compose -f docker-compose.yml --compatibility up -d`, image pulled from the official OWASP crAPI repository). The official Postman collection is the fastest way to seed Burp's proxy history with the full endpoint set before running an Autorize sweep, since crAPI's frontend doesn't surface every API-level route through its UI.

---

## Autorize quick reference

1. Install via BApp Store (needs Jython standalone jar configured).
2. Capture low-priv session's exact auth header.
3. Paste into Autorize config, enable unauthenticated testing too.
4. Filter out static assets, scope to API host.
5. Enable Autorize, browse as high-priv account.
6. Manually validate every "Bypassed!" row — check actual response content and server-side state, not just the heuristic flag.

---

## Reporting classification reminder

When writing up a finding, state explicitly:
- **Vulnerability class**: BFLA (API5:2023), and whether vertical or lateral
- **Overlap disclosure**: if the mechanism is mass-assignment-driven, note the BOPLA (API3) overlap rather than picking one label silently
- **Gateway/WAF relevance**: state plainly that generic WAF/gateway controls are not a meaningful barrier for this class (per file 01/03), unless the specific target's gateway does implement route-level RBAC — in which case name that as the actual control that failed
- **Proof**: original vs replayed request/response pairs, plus independent state verification (not just response body)

---
*End of BFLA series. Companion files: 01-overview-and-concept.md, 02-discovery-methodology.md, 03-bfla-patterns-and-bypass-techniques.md, 04-autorize-extension-testing.md.*
