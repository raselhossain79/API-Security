# BOLA — Burp Suite Autorize Extension: Complete Usage Guide

Manual testing (file 2) proves individual findings precisely, but it does not scale to an API with hundreds of endpoints. Autorize automates the repetitive part: replaying every request your browsing session generates under a *lower-privileged* identity, and flagging whether the response still succeeds. This file covers setup, configuration, and — critically — how to actually read its results without generating false positives.

---

## 1. What Autorize Does, Conceptually

While you (or a higher-privileged/normal test account) browse the target application normally through Burp's proxy, Autorize intercepts every outgoing request in the background and **automatically fires a second copy of that exact request, substituting in a different set of credentials you configured in advance** (typically a lower-privileged user's token/cookie, or no authentication at all). It then compares the two responses and color-codes the result so you can scan hundreds of endpoints for authorization gaps without manually re-sending each one.

This directly automates the core technique from file 2, section 3 (swap the identity, keep the object reference, compare the response) — but across your *entire* browsing session instead of one endpoint at a time.

---

## 2. Installation

**Step 2.1 — Confirm the Jython standalone jar is configured.** Autorize is a Python-based BApp Store extension and requires Jython. In Burp: `Extender` → `Options` → `Python Environment` → set the path to a downloaded Jython standalone `.jar` (download from jython.org if not already present).

**Step 2.2 — Install Autorize from the BApp Store.** `Extender` → `BApp Store` → search "Autorize" → `Install`.

**What this does:** loads the extension and adds a new "Autorize" tab to Burp's main tab bar.

---

## 3. Capturing the Low-Privilege Credential

This is the single most important preparation step — Autorize's entire mechanism depends on having a valid, working credential for the *lower-privileged* account you want to test against.

**Step 3.1 — Log in as the low-privilege test account** (e.g., Account B from file 2, or an unauthenticated/anonymous state if testing "does this require auth at all") in a separate browser session or Burp-proxied request.

**Step 3.2 — Capture the exact authentication mechanism the app uses.** This could be:
- A `Cookie` header value (session-based apps)
- An `Authorization: Bearer <token>` header (most modern APIs)
- A custom header (e.g., `X-API-Key: ...`)

Copy this value in full, exactly as it appears in a real captured request — do not truncate or manually retype it, since a single missing character invalidates every single Autorize test for the rest of the session.

---

## 4. Configuring Autorize

**Step 4.1 — Open the Autorize tab → Config sub-tab.**

**Step 4.2 — Paste the low-privilege header into "Headers to replace by their value below."**
Enter the exact header name and the low-privilege value, e.g.:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...LOW_PRIV_TOKEN
```
**What this configures and why:** for every request Autorize intercepts (which will contain your *high-privilege* Account A's header, since that's the session you're browsing with), it will strip out that header and replace it with the low-privilege value you just entered, before replaying the request. This is the automated equivalent of file 2, step 3.3 — same object reference, swapped identity.

**Step 4.3 — (Optional but recommended) Add a second replacement set for the "unauthenticated" case.** Configure a second profile with the Authorization header removed entirely (or set to an obviously invalid value), to simultaneously test "does this endpoint require authentication at all" alongside "does it require the *correct* authorization for this specific object" — these are two different failure modes and Autorize can test both if you set up multiple enforcement detectors.

**Step 4.4 — Configure "Unauthorized Match Rules"/"Detect enforcement based on."**
This is what tells Autorize how to judge whether the low-privilege replay actually succeeded or failed. Common configurations:
- **HTTP status code:** flag as "bypassed" if the replayed (low-priv) response returns `200`/`201`/`204` where you'd expect a `401`/`403`.
- **Response length similarity:** flag if the replayed response's byte length is close to (or identical to) the original high-privilege response's length — a strong indicator that real data was returned rather than an empty/error placeholder.
- **Custom string/regex match:** if the application returns a generic `200` even on failure but includes a distinguishing string like `"error":"forbidden"` in the body, configure Autorize to treat responses containing that string as "enforced" regardless of status code — this avoids the exact false-positive trap described in file 2, section 3.4, now automated.

**Step 4.5 — Enable interception.** Toggle the extension to `Autorize is on` at the top of the Config tab. From this point, every request passing through Burp's proxy while browsing as the high-privilege account will be automatically replayed.

---

## 5. Running the Test — Workflow

**Step 5.1 — Browse the application as thoroughly as possible while logged in as the high-privilege/normal account,** with Autorize enabled. Click through every page, every settings screen, every CRUD action (create, view, edit, delete) you can reach, ideally including actions on objects that belong to that account specifically (so there's a legitimate object ID in every request for Autorize to attempt replaying against the low-priv identity).

**Step 5.2 — If the API has documented endpoints not reachable through the UI** (from your spec review in file 2, section 2.2), manually send those requests once through Repeater with your proxy routed through Burp so Autorize still intercepts and replays them — Autorize only sees traffic that actually passes through the proxy, so endpoints never triggered by your browsing session or manual requests are simply never tested.

---

## 6. Reading the Results Table

The Autorize results tab (sub-tab: "Authorization Enforcement") shows one row per intercepted request-and-replay pair, with these key columns:

| Column | Meaning |
|---|---|
| **URL / Method** | The original endpoint and HTTP method that was intercepted |
| **Enforced?** | Autorize's automatic verdict based on your Step 4.4 rules |
| **Status (original)** | Status code of the original, high-privilege request |
| **Status (modified)** | Status code of the replayed, low-privilege request |
| **Length (original)** / **Length (modified)** | Byte lengths of both responses, for manual comparison |

**Color coding (default):**
- **Red row — "Bypassed!"**: the low-privilege replay returned a response that met your "still succeeded" criteria — this is a candidate BOLA/broken-authorization finding and needs manual confirmation.
- **Green row — "Enforced"**: the low-privilege replay was correctly denied according to your configured detection rule.
- **Yellow/orange row — "Is enforced?"** (unconfirmed): Autorize could not confidently classify the result against your rules and is flagging it for manual review — treat every yellow row as mandatory to check by hand, since this is where genuine findings hide behind ambiguous response shapes.

---

## 7. Interpreting Results Without False Positives

Autorize is a triage tool, not a final verdict — every red or yellow row must be manually confirmed before being reported. Common false-positive causes:

**7.1 — Generic "not found" pages returning 200.** If the app returns a soft-404 (status `200`, body says "Item not found") for *any* invalid ID — including IDs that genuinely don't exist — Autorize may flag this as "bypassed" purely because the status code matched your rule, even though no actual unauthorized data was disclosed. **Fix:** always click into the actual response body for red/yellow rows and confirm it contains real target-user data, not a placeholder.

**7.2 — Public/intentionally-shared endpoints.** Some endpoints are genuinely meant to be accessible without the resource owner's specific privilege (e.g., a public product listing, a publicly shareable document link). These will always show as "bypassed" and are not findings — filter these out based on your ownership model cataloged in file 2, section 2.3.

**7.3 — Stale or expired low-privilege token.** If the token configured in Step 3.2 has expired mid-session, every single row will show as "enforced" (because every replayed request now correctly gets rejected for auth reasons, not authorization reasons) — creating a false sense of security. **Fix:** periodically re-verify the low-priv token is still valid by manually sending one request with it directly, especially on any test session lasting more than the token's typical lifetime.

**7.4 — Endpoints requiring dynamic/one-time tokens (CSRF tokens, nonces).** If a request body contains a one-time-use token tied to the *original* session, the replay may fail for that reason alone, unrelated to authorization — showing as "enforced" when the actual authorization logic was never truly exercised. **Fix:** identify these cases manually and test them outside Autorize using the direct token-substitution method from file 2.

**7.5 — Rate limiting interfering with bulk replay.** If Autorize is left running against a live browsing session for a long period, rate limiting may start rejecting requests with `429` responses independent of authorization logic, which can appear in the results table and should not be misread as "enforced" — check for `429` explicitly and re-test those endpoints individually, more slowly, outside of Autorize.

---

## 8. Real-World Notes

- Autorize is most effective as a **first-pass triage tool across a large API surface** — running it while performing a full manual walkthrough of an application typically surfaces the majority of horizontal BOLA issues automatically, which is exactly why it's a standard tool in professional API pentest workflows rather than a novelty extension.
- It does **not** automatically test cross-tenant scenarios unless you configure a second low-privilege identity from a genuinely separate tenant/org and re-run the entire walkthrough with that profile — running it once with a same-tenant low-priv user only covers horizontal escalation (file 2, section 3), not cross-tenant boundaries (file 2, section 4).
- It does not automatically catch the "hidden in the response body, reused later" pattern (file 2, section 5.2) — that chain requires the tester to manually identify the leaked field and construct the second request, since Autorize only replays requests that were actually sent during your session, not derived attack chains.
- Because Autorize only sees requests that pass through Burp's proxy, remember to route mobile app traffic and any Postman/script-driven calls through Burp as an upstream proxy if you want those covered as well — a common gap in real engagements is forgetting to proxy a mobile client and only getting web-browser coverage.

---

**Next file:** `05_Cheatsheet.md` — condensed final reference covering the full series plus the PortSwigger and crAPI lab mapping.
