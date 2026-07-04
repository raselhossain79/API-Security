# BOLA — Final Cheatsheet

Quick-reference summary of the full series. Use files 1–4 for full explanations; this file is for fast recall during live testing.

---

## 1. BOLA vs IDOR — One-Line Recall

Same root cause (missing per-object ownership check on a client-supplied reference). IDOR = the general/legacy web-app term, tested via UI-crawling and URL/form tampering. BOLA = the same flaw in API context, tested via spec review, method-by-method coverage, and multi-tenant boundary checks. Full detail: file 1.

---

## 2. Core Test Pattern (applies everywhere)

1. Capture your own valid request (your token + your object ID).
2. Get a target object ID that belongs to someone else (or another tenant).
3. Replace **only the object ID**, keep **your own token unchanged**.
4. Compare full response bodies, not just status codes.
5. Repeat across every HTTP method the endpoint supports, not just GET.

---

## 3. Scenario Quick-Reference

| Scenario | What to swap | What stays fixed | Full detail |
|---|---|---|---|
| Horizontal escalation | Object ID (path) | Your own token | File 2 §3 |
| Cross-tenant (path-based) | `org_id`/`tenant_id` in path | Your own token | File 2 §4.2 |
| Cross-tenant (header-based) | `X-Tenant-ID` header | Your own token, URL | File 2 §4.3 |
| Cross-tenant (JWT claim) | Decoded tenant claim, re-signed/sent | Rest of token structure | File 2 §4.4 |
| Body-hidden reference | ID field inside JSON body | URL/path (may be correctly scoped) | File 2 §5.1 |
| Disclosed-then-reused ID | Reused ID from unrelated response | Your token | File 2 §5.2 |
| Method coverage gap | HTTP method (GET→PUT/PATCH/DELETE) | Object ID, token | File 2 §5.3 |
| Method-override bypass | `X-HTTP-Method-Override` header | Literal HTTP method | File 2 §5.3.3 |
| Nested parent/child mismatch | Child ID under wrong parent ID | Parent belongs to you | File 2 §5.4 |

---

## 4. ID Type Quick-Reference

| ID type | Recognize by | Approach | Tooling |
|---|---|---|---|
| Sequential integer | Small increment between own created objects | Brute-force enumeration | Burp Intruder (Sniper, Numbers payload) |
| UUIDv1 | 36 chars, version nibble = `1` | Timestamp narrows search space | Manual/Turbo Intruder |
| UUIDv4 | 36 chars, version nibble = `4` | Disclosure-based discovery only — search all responses for leaked UUIDs | Burp proxy history search |
| Hashed ID | Fixed-length hex, no hyphens (32/40/64 chars) | Identify algorithm → recreate hash of guessable input space → match | `hashid`, `md5sum`/`sha1sum`/`sha256sum` loops, rainbow tables |
| GUID | Same as UUID format | Treat identically to UUID | Same as UUID |
| Base64-encoded | Base64 charset, often `==` padding | Decode → identify underlying pattern (usually sequential) → modify → re-encode | `base64 -d` / `base64` |

Full walkthroughs with exact commands: file 3.

---

## 5. Autorize Quick-Setup

1. Install Jython jar → `Extender > Options`.
2. Install Autorize from BApp Store.
3. Capture a low-privilege token/cookie from a second account.
4. `Autorize > Config` → paste header + low-priv value under header replacement.
5. Set enforcement detection rule (status code / length / custom string match).
6. Toggle Autorize ON, browse app fully as high-priv user.
7. Review results: **red = bypassed (investigate)**, **yellow = ambiguous (mandatory manual check)**, **green = enforced**.
8. Manually confirm every red/yellow row before reporting — check actual response body content, not just the color.

Full guide with false-positive handling: file 4.

---

## 6. WAF / Gateway — One-Line Recall

Signature-based WAFs cannot detect BOLA — the request is syntactically identical to a legitimate one; only the ID value and true ownership differ, which WAFs have no visibility into. Only behavioral/anomaly-based API security tooling and properly-scoped gateway authorization policy are relevant, and "bypass" in this context means evading rate/pattern-based detection (pacing, non-sequential ordering), not defeating a rule signature. Full reasoning: file 1 §4.

---

## 7. PortSwigger Web Security Academy Lab Mapping

The Access Control topic contains PortSwigger's primary IDOR/BOLA-relevant lab set. Recommended progression order (Apprentice → Practitioner):

**Apprentice:**
1. Unprotected admin functionality
2. Unprotected admin functionality with unpredictable URL
3. User role controlled by request parameter
4. User role can be modified in user profile
5. User ID controlled by request parameter — *direct IDOR, maps to file 2 §3 core pattern*
6. User ID controlled by request parameter, with unpredictable user IDs — *maps to file 3 §2 (UUID/GUID discovery)*
7. User ID controlled by request parameter with data leakage in redirect — *maps to file 2 §3.4 (redirect-body leakage false-negative trap)*
8. User ID controlled by request parameter with password disclosure in redirect
9. Insecure direct object references — *the canonical IDOR lab, maps to file 2 §3 baseline pattern*
10. URL-based access control can be circumvented
11. Method-based access control can be circumvented — *maps directly to file 2 §5.3 (HTTP method coverage gap)*

**Practitioner:**
12. Multi-step process with no access control on one step — *conceptually adjacent: validates the "check exists on some steps/methods but not others" pattern central to file 2 §5.3*
13. Referer-based access control

**Honest gap disclosure:** PortSwigger's Access Control topic does not currently include a dedicated cross-tenant/multi-tenant SaaS lab, nor a dedicated GraphQL/nested-object-relationship IDOR lab, nor a lab specifically modeling a hashed or base64-encoded object ID. These gaps are exactly why crAPI (below) and real-world/CTF-style multi-tenant labs remain necessary supplementary practice for the cross-tenant (file 2 §4) and hashed/base64 (file 3 §3–5) material in this series. Always cross-check the live "All Labs" page (`portswigger.net/web-security/all-labs`) before a study session, since PortSwigger periodically adds labs to this topic.

---

## 8. crAPI Supplementary Practice (Challenges 1–3, BOLA-focused)

crAPI ("Completely Ridiculous API") is OWASP's dedicated vulnerable API training project — a better fit than PortSwigger for genuinely API-shaped BOLA practice (JSON bodies, GUID-based object references, mobile-style API flows) since PortSwigger's labs are fundamentally web-app-shaped.

**Challenge 1 — Access details of another user's vehicle.**
Vehicle records are referenced by GUID rather than sequential ID. The vehicle's GUID is disclosed via a "Community" feed endpoint that over-shares other users' object references in its response. The bypass is a direct real-world instance of file 3 §2 (UUID/GUID disclosure-based discovery) — the GUID is never given to you directly by the app for your own testing purposes; it is harvested from an unrelated endpoint's response and reused against the vehicle-location endpoint using your own valid token.

**Challenge 2 — Access mechanic reports of other users.**
Mechanic service reports are referenced by a `report_id` that turns out to be sequential once you submit two reports back-to-back and compare the IDs. This is a direct real-world instance of file 3 §1 (sequential ID enumeration) combined with file 2 §3 (horizontal escalation using your own valid token against another user's `report_id`).

**Challenge 3 — Reset the password of a different user.**
Chains the email address disclosed via Challenge 2's report data with an OTP-based password reset flow. While the final step overlaps with broken-authentication territory rather than pure BOLA, the initial information-gathering step is itself a BOLA-driven data leak (an unrelated endpoint disclosing PII belonging to another user without an ownership check), reinforcing the file 2 §5.2 pattern of one broken endpoint's disclosure enabling a subsequent, higher-impact attack.

**Setup:** crAPI is deployed via Docker Compose from the official OWASP crAPI GitHub repository. It includes a MailHog interface (typically port 8025) for capturing verification emails/OTPs generated during account setup and the Challenge 3 flow.

---

## 9. Reporting Reminders

- Always capture full request/response pairs for both the authorized baseline and the successful bypass — a finding without this pairing is not reproducible by a reviewer.
- State explicitly which of horizontal, cross-tenant, or method-coverage category the finding falls under (file 2's categories) — severity ratings differ significantly between these.
- For any finding involving PII or another real user's data during an authorized engagement, follow the client's/program's data-handling rules — do not exfiltrate or retain more of another user's data than the single sample needed to prove the finding.
