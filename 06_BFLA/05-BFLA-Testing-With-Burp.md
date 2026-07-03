# BFLA — Manual Testing Workflow With Burp Suite

This file covers the practical, repeatable Burp workflow for BFLA testing — from capturing multi-role traffic through to systematically sweeping discovered endpoints.

---

## 1. Prerequisites: Multiple Authenticated Sessions

BFLA testing fundamentally requires **at least two sets of valid credentials at different privilege levels** (ideally three: regular user, elevated role, admin) that you're authorized to use in the engagement scope. Without a genuine privilege differential to test against, you can only find unauthenticated-access bugs, not authorization-boundary bugs.

**Setup:**
1. Log in as each role in **separate browser profiles or separate Burp sessions** (Burp's built-in browser supports multiple profiles; alternatively use one Firefox container per role).
2. In Burp, tag/label each session's traffic clearly — use **Project Options → Sessions** or simply keep separate Proxy history filters per role using a distinct `Comment` or color-coded highlight on each request.
3. Extract and save each role's raw `Authorization` header / session cookie value somewhere accessible (a Burp-saved item, or a notes tab) — you'll be swapping these constantly.

---

## 2. Step-by-Step Manual Workflow

### Step 1 — Build the candidate endpoint list
Using file 02's discovery methodology, compile every candidate privileged endpoint into a single list — ideally imported into Burp as a **sitemap** entry or a **Burp Suite Enterprise/Pro "Target" scope** so every subsequent request against these paths is automatically logged for later review.

### Step 2 — Capture the "should work" baseline
As the **higher-privileged** role, walk through every admin/privileged function in the actual application UI at least once, letting Burp's Proxy capture the real request. This gives you:
- The correct URL, method, headers, and body shape (critical — guessing body shape from Swagger alone sometimes misses required fields).
- Confirmation the function actually does something observable, so a later "success" response from the low-privileged token isn't a false positive against dead/broken functionality.

### Step 3 — Send to Repeater, strip the privilege, replay
For each captured request:
1. Right-click → **Send to Repeater**.
2. Duplicate the tab (so you keep the original, working, high-privilege version intact for comparison).
3. In the duplicate, **replace only the `Authorization` header (or session cookie)** with the low-privileged token. Change nothing else — same path, same method, same body.
4. Send. Compare status code **and full response body** against the baseline from Step 2.

**Why not change anything else:** isolating the authorization header as the *only* variable is what proves the finding is specifically an authorization failure and not, say, a difference caused by a missing required field or a different content type. Precision here directly strengthens the finding when writing it up.

### Step 4 — Diff the responses
Use Burp's **Comparer** tool (right-click both responses → "Send to Comparer") to get a word-level or byte-level diff between the high-privilege and low-privilege responses. This is especially useful for the "field inference" cases from file 02 — subtle differences (e.g., `internalNotes` present in one, absent in the other, but both `200 OK`) are easy to miss by eye and easy to catch in Comparer.

### Step 5 — Sweep systematically with Repeater tab groups or Intruder
For a large candidate list (dozens to hundreds of endpoints from a mined Swagger spec):
1. Group Repeater tabs by controller/resource for organization.
2. For simple "does this path respond differently to this token" sweeps across many URLs with the same method, **Intruder's Sniper mode** works well: set the path as the payload position, load your candidate endpoint list as the payload set, keep the low-privilege token fixed in the header, and grep-match the response for indicators like `"error"`, `"forbidden"`, or expected success field names to auto-flag interesting results in the results grid.
3. For sweeping **every HTTP verb** against a fixed set of paths (file 03, pattern 1), set the method itself as the Intruder payload position and supply `GET/POST/PUT/PATCH/DELETE` as the payload list.

### Step 6 — Extension-assisted testing (optional but efficient)
- **Autorize** (Burp extension): once configured with your low-privilege session token/cookie, it automatically replays *every* request your higher-privileged browsing session generates using the low-privilege credential in a background parallel request, and color-codes the results (bypassed / enforced / potentially vulnerable). This effectively automates Steps 3–4 for your entire browsing session instead of one request at a time — extremely efficient when you're clicking through an entire admin panel's worth of functionality as the high-privilege user.
- **AuthMatrix**: lets you define multiple roles/users and multiple requests up front, then runs a full matrix (every role × every request) in one pass, producing a clear pass/fail grid. Better suited than Autorize when you already have a fixed, known list of privileged endpoints (e.g., from a Swagger export) rather than discovering them live by clicking through the UI.

### Step 7 — Confirm real effect, not just response code
As emphasized in file 02, section 6: a `200`/`204` is not proof of impact for state-changing requests. Where scope and test data allow:
- Re-query the resource as the high-privilege role afterward to confirm a `DELETE`/`PUT`/`POST` actually persisted.
- For destructive actions, always coordinate with the client on using disposable test accounts/records — never execute unconfirmed destructive BFLA payloads against data you can't identify as safe to modify.

---

## 3. PortSwigger Web Security Academy — Lab Mapping

**Honest gap disclosure first:** PortSwigger's Web Security Academy does not have a dedicated "API Security" or "BFLA-labeled" category the way it has dedicated categories for XSS, SQLi, or SSRF. The relevant labs live under the general **Access Control** topic, and that topic mixes what the API Top 10 would separately classify as BOLA (object/record-level, IDOR-style) and BFLA (function/endpoint-level). The labs below are selected and ordered specifically for their **function-level** relevance; a few are borderline and noted as such. This is a genuine coverage gap in PortSwigger's lab catalog relative to API-specific categories — crAPI (section 4) fills it far more directly.

**Recommended progression order (easiest to hardest), function-level-focused:**

1. **Unprotected admin functionality** — the purest possible BFLA lab: an admin panel with literally no access control check at all, reachable simply by knowing/guessing the URL. Maps directly to file 02 (path guessing discovery) and file 03's "no check exists at all" baseline case.
2. **Unprotected admin functionality with unpredictable URL** — same core bug, but the URL isn't guessable and must be found via a disclosed reference (e.g., in a robots.txt or JS source) — directly exercises file 02's JS-mining and source-inspection techniques.
3. **User role controlled by request parameter** — directly maps to file 03, pattern 3 (parameter-based role manipulation): a request includes a role indicator the server trusts without verifying against the actual session.
4. **User role can be modified in user profile** — a variant of the same pattern applied to a profile-update flow; strongly parallels the mass-assignment-style worked example in file 03.
5. **Multi-step process with no access control on one step** — relevant to BFLA because it demonstrates a *function-level* gap in a workflow: one step in a privileged multi-step process is missing its check even though the surrounding steps have it, which mirrors the "some verbs/routes protected, others forgotten" root cause from file 01, section 3.
6. **Referer-based access control** — technically a broken *mechanism* for enforcement rather than a missing check, but it's still a function-level authorization bypass (the "check" exists but is trivially spoofable via the `Referer` header), worth including for completeness on how NOT to implement function-level checks.

**Explicitly not included here (more accurately BOLA, not BFLA):** "User ID controlled by request parameter" and its unpredictable-ID/data-leakage/password-disclosure variants, and "Insecure direct object references" — these are object/record-level (ownership) failures, covered instead in this repository's BOLA note series.

---

## 4. crAPI — Practical BFLA Exercises

crAPI (Completely Ridiculous API) is purpose-built with a realistic multi-role model (regular user, mechanic/workshop role, and administrative functions) and is the more accurate hands-on environment for BFLA specifically, since it's an actual API-first application rather than a generic web app repurposed for the exercise.

Relevant crAPI flows for BFLA practice:
- **Workshop/mechanic-role endpoints** reachable by a regular user token — directly exercises vertical escalation (file 04, section 1).
- **Vehicle/service management functions** intended to be scoped per-user or per-mechanic, useful for combining BFLA discovery with the lateral/scope-check concepts from file 04, section 2.
- Community-documented crAPI walkthroughs (OWASP's own crAPI repository and associated writeups) explicitly call out several of these as BFLA-category findings, making it a good source for confirming your own methodology against known-good answers.

---

## 5. What's Next

**File 06** is the condensed cheatsheet — quick-reference checklists, curl one-liners, and a compact discovery-to-exploitation flow for use during live engagements.
