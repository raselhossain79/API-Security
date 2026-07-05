# API Broken Authentication — Final Cheatsheet

Condensed operational reference. For full explanations, see files 01–04.

---

## 1. Quick Testing Checklist

**Missing authentication enforcement**
- [ ] Every discovered endpoint tested with `Authorization` header fully removed (not just blanked)
- [ ] Automated sweep across full endpoint list, filtered for unexpected `200`/`301`/`302`
- [ ] All HTTP methods tried per path (`GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD`), with and without auth
- [ ] Method-override headers tested (`X-HTTP-Method-Override`, `X-Method-Override`, `_method`)

**Token entropy**
- [ ] 20+ sample tokens collected and diffed character-by-character
- [ ] JWT/base64 structure decoded, checked for embedded predictable data
- [ ] Timing correlation checked against issuance intervals
- [ ] Backend framework's default RNG checked for CSPRNG usage

**Token transmission**
- [ ] Full proxy history searched for token value appearing in any URL (not just headers)
- [ ] JWT pattern (`eyJ` prefix) searched across all captured traffic
- [ ] Referer-leak potential checked on any token-bearing URL that loads external resources

**Token expiration / revocation**
- [ ] `exp` claim checked (JWT) or empirical wait-and-retest performed (opaque tokens)
- [ ] Logout followed by immediate reuse of the same token
- [ ] Password change followed by reuse of all prior tokens
- [ ] "Log out all devices" (if present) followed by reuse of all prior tokens

**Credential attacks**
- [ ] Rate limit threshold measured (Section 1 methodology, file 03) before choosing a tool
- [ ] IP-based vs account-lockout-based limiting distinguished
- [ ] Response body / status code / timing / length compared across valid vs invalid usernames
- [ ] Tool selected per the decision table (file 03, Section 3.1)

**Token/format manipulation**
- [ ] `alg: none` tested
- [ ] RS256→HS256 confusion tested if public key obtainable
- [ ] Array/null/empty type-confusion tested on key/token fields
- [ ] Bearer scheme case/spacing variants tested

**Gateway/backend mismatch**
- [ ] Backend hostname hunted via error leakage / DNS / headers
- [ ] Direct backend reachability tested, bypassing Gateway entirely (in-scope only)

**Sensitive-action re-authentication**
- [ ] Email/password/MFA change attempted with token only, no current-password field
- [ ] If `current_password` field exists, tested with a deliberately wrong value to confirm it's actually checked
- [ ] MFA removal tested without a fresh MFA challenge

---

## 2. Tool Selection Quick-Reference

| Scenario | Tool |
|---|---|
| Small list, no/loose rate limit | Burp Intruder — Cluster bomb |
| Paired breach-dump credentials (credential stuffing) | Burp Intruder — Pitchfork, or Turbo Intruder at scale |
| IP-based rate limit, header trust suspected | Turbo Intruder with per-request `X-Forwarded-For` rotation |
| Very large list (100k+), speed critical | Turbo Intruder, `pipeline=True` once target behavior confirmed |
| Account-lockout-based limiting | Burp Intruder, paced via Resource Pool throttle, not IP rotation |

---

## 3. PortSwigger Web Security Academy — Authentication Lab Map

The Academy's **Authentication** topic is organized into three sub-sections. Labs are listed below in the Academy's own difficulty progression (Apprentice → Practitioner → Expert). These map directly to the concepts in this series even though the labs are framed as general web authentication rather than API-specific — the underlying flaw classes (missing rate limiting, response-based enumeration, broken token/session logic, MFA logic flaws) are identical to what you'll test against an API surface.

> Lab availability and exact titles occasionally change on PortSwigger's live site — cross-check against your Academy dashboard, but this reflects the structure as documented.

### 3.1 Password-Based Login

| Difficulty | Lab | Maps to this series |
|---|---|---|
| Apprentice | Username enumeration via different responses | File 03, §2 — response-based detection |
| Apprentice | 2FA simple bypass | File 04, §1 — missing enforcement on a step in a multi-step flow |
| Apprentice | Password reset broken logic | File 04, §5 — sensitive-action verification gaps |
| Practitioner | Username enumeration via subtly different responses | File 03, §2.2 — length/byte-level differences |
| Practitioner | Username enumeration via response timing | File 03, §2.3 — timing-based detection |
| Practitioner | Broken brute-force protection, IP block | File 03, §1 — rate-limit detection and IP-based bypass |
| Practitioner | 2FA broken logic | File 04, §1 — logic-flow enforcement gaps |
| Practitioner | Password reset poisoning via middleware | File 04, §4 — trusted-header / proxy-layer manipulation, adjacent concept |
| Expert | Username enumeration via account lock | File 03, §2 — subtler response-based signal |
| Expert | Broken brute-force protection, multiple credentials per request | File 03, §3 — batching credentials to evade per-request rate counting |
| Expert | Authentication bypass via encryption oracle | File 04, §3 — token/format-level manipulation, advanced variant |

### 3.2 Multi-Factor Authentication

| Difficulty | Lab | Maps to this series |
|---|---|---|
| Apprentice | 2FA simple bypass | File 04, §1 |
| Practitioner | 2FA broken logic | File 04, §1 |
| Practitioner | 2FA bypass using a brute-force attack | File 03, §1 and §3 — rate-limit-aware brute forcing applied to short numeric MFA codes |

### 3.3 Other Authentication Mechanisms

| Difficulty | Lab | Maps to this series |
|---|---|---|
| Apprentice | Broken authentication logic | File 01, §2.1 — missing/incorrect enforcement |
| Practitioner | Insufficient workflow validation | File 04, §5 — sensitive-action / multi-step flow gaps |
| Practitioner | Password reset poisoning via dangling markup | File 04, §4 — adjacent header/transport manipulation concept |

**Suggested working order:** complete the Password-Based Login sub-section fully (Apprentice → Expert) before moving to Multi-Factor, then Other Mechanisms — this mirrors the Academy's own recommended path and builds response-analysis skill (used constantly in later labs) early.

---

## 4. crAPI (Completely Ridiculous API) — Supplementary Authentication Practice

crAPI is a deliberately vulnerable API-specific training target (unlike PortSwigger, which is web-app-focused but conceptually transferable). Use it after the PortSwigger authentication labs to practice the same concepts against an actual API surface with mobile-app-style tokens and endpoints.

| crAPI Challenge Area | What it covers | Maps to this series |
|---|---|---|
| **JWT authentication / weak token workflow** | crAPI issues JWTs during signup/login and via a shop/community login flow with token-handling weaknesses to discover (broken signature validation and reused/predictable tokens depending on challenge configuration) | File 02, §1 (entropy/predictability) and File 04, §3 (JWT format manipulation) |
| **Reset password / OTP workflow abuse** | crAPI's password reset flow uses an email-delivered OTP that can be intercepted or brute-forced due to weak rate limiting on the OTP-verification endpoint | File 03, §1 (rate-limit detection) and File 04, §5 (sensitive-action verification gaps) |
| **Excessive data / broken object-level auth via token reuse** | While primarily a BOLA-category challenge, several crAPI flows rely on presenting a token that isn't properly scoped to the requesting user, useful for practicing token-transmission and reuse-detection technique from File 02 even though the deeper authorization implication belongs to a different OWASP category | File 02, §1–§2 |
| **Mobile app traffic interception (MITM proxy setup)** | crAPI ships an actual mobile app APK, giving direct practice routing real mobile API traffic through Burp — the exact setup described in File 02, §2.2 for token-transmission testing | File 02, §2 |

**Setup note:** crAPI is typically deployed via Docker Compose locally, which also makes it useful for testing the Gateway/backend-mismatch concept in File 04, §4 in a safe, fully-controlled environment where you can inspect the actual docker-compose service topology to confirm exactly which service is meant to be internal-only versus externally reachable.

---

## 5. Reporting Severity Quick-Reference

| Finding | Typical severity rationale |
|---|---|
| Missing auth on an endpoint returning sensitive data | High–Critical — direct data exposure, no further exploitation needed |
| Token in URL (confirmed logged/leaked path) | Medium–High — depends on demonstrated exposure path (Referer leak, log access) |
| No token expiration | Medium — extends exploitation window for any other token-theft vector |
| No revocation on logout/password change | Medium–High — directly undermines the value of the very controls meant to contain a compromise |
| Missing/weak rate limiting on login | Medium–High — enables credential stuffing/brute force at scale |
| Username enumeration via response difference | Low–Medium on its own; escalates when chained with brute force |
| `alg: none` / algorithm confusion accepted | Critical — typically full authentication bypass |
| Change email/password without current-password check | High–Critical — near-direct path to full account takeover |
| Gateway/backend mismatch (backend directly reachable, unauthenticated) | Critical — architecture-level bypass of the sole enforcement point |

---

## 6. File Index

1. `01_Overview_Classification.md`
2. `02_Token_Security_Testing.md`
3. `03_Credential_Based_Attacks.md`
4. `04_Authentication_Bypass_Techniques.md`
5. `05_Final_Cheatsheet.md` (this file)

See `README.md` for the full repository index.
