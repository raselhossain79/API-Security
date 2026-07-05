# BFLA — Automated Detection with Autorize

Manual testing (baseline swap-the-token method from file 03) works, but doesn't scale across a large API surface with dozens or hundreds of endpoints. Autorize automates the exact same core test — replay every request with a lower-privileged session's credentials and flag responses that shouldn't have succeeded — across an entire Burp proxy history in real time.

---

## 1. What Autorize actually automates

Autorize's core logic, mechanically:

1. You browse/use the application normally as your **higher-privileged** session (the one whose traffic populates Burp's proxy history as you click around).
2. For every request that passes through the proxy, Autorize **automatically replays it twice more**: once with the low-privilege session's auth material substituted in, and once with **no** auth material at all (to also catch unauthenticated access).
3. It compares the three responses (original, low-priv replay, unauthenticated replay) and applies a heuristic to flag whether the low-priv/unauth replay "looks like" it got the same access as the original.
4. Results populate in an Autorize tab as color-coded rows: bypassed (red — likely vulnerable), enforced (green — properly blocked), and "is enforced?" unknown/needs manual review (for cases the heuristic can't confidently classify, e.g., partial content differences).

This is precisely the manual technique from file 03, section 0 — done automatically for every single request instead of one at a time in Repeater.

---

## 2. Installation

1. Burp Suite → **Extensions** tab → **BApp Store**.
2. Search "Autorize" (author: Barak Tawily).
3. Click **Install**. Requires Jython standalone jar configured under **Extensions → Extension settings → Python environment** if not already set up (Autorize is a Python/Jython extension) — Burp will prompt if it's missing; download the standalone Jython `.jar` and point Burp at it.
4. After install, a new **Autorize** tab appears in the main Burp tab bar.

---

## 3. Capturing the low-privilege session token

Before configuring Autorize you need the **exact auth header/cookie** of the low-privilege account you'll test against.

1. Log into the application as the **low-privilege** test account in a separate browser (or separate Burp-proxied session/incognito window).
2. Perform any single authenticated action so a request with that session's credentials appears in Burp's proxy history.
3. Right-click that request → **Copy headers** or manually copy the exact value of the relevant header:
   - Cookie-based auth: copy the full `Cookie:` header value.
   - Token-based auth: copy the full `Authorization: Bearer <token>` header value.
   - API key header: copy the full custom header (e.g., `X-API-Key: ...`).

Keep this value ready to paste into Autorize's configuration in the next step.

---

## 4. Configuring Autorize

In the **Autorize** tab:

1. **Paste the low-privilege header** into the "Configuration" panel's header field — this is the credential Autorize will substitute into every replayed request. Multiple headers can be added if the app uses more than one auth mechanism (e.g., both a cookie and a CSRF token header).
2. **Unauthenticated replay toggle** — enable "Also test unauthenticated" if you want Autorize to additionally strip auth entirely and test true unauthenticated access on every request (recommended — catches endpoints with *no* protection at all, one tier worse than BFLA).
3. **Filters (important — reduces noise):**
   - Exclude static asset extensions (`.js`, `.css`, `.png`, `.woff`, etc.) — these will always "match" and flood results with irrelevant rows.
   - Scope the target to the API's host/path prefix under **Filters → In-scope items only**, matched to your configured Burp Target scope.
4. **Enable Autorize** via the checkbox/toggle at the top of the tab (it does nothing until explicitly turned on — this is easy to forget and results in an empty table while you browse).
5. Leave Burp Proxy intercept **off** (Autorize works passively off proxy history, not through active intercept) and browse the app normally as the **high-privilege** account through the browser with Burp as its proxy.

---

## 5. Reading and interpreting results

As you browse as the admin/high-priv account, the Autorize tab populates one row per request:

| Column | Meaning |
|---|---|
| Request | The method + path that was captured and replayed |
| Enforced? | Autorize's heuristic verdict: **Bypassed!** (red, likely vulnerable), **Enforced** (green, correctly blocked), or a status needing manual check |
| Original response length/code | The high-priv response, for comparison |
| Modified response length/code | The low-priv (or unauth) replay's response |

### Piece-by-piece: how to validate a "Bypassed!" flag, don't trust it blindly

Autorize's heuristic (mainly comparing response length/status code similarity) produces **false positives**, especially on endpoints that return a generic "200 OK, here's an empty array" for both an authorized empty-result and an unauthorized-blocked-but-still-200 response. For every red flag:

1. Right-click the row → **Send original/modified request to Repeater**.
2. Manually inspect the **modified** (low-priv) response body, not just its length/status code.
3. Confirm it contains **actual privileged data or a real state change**, not just a superficially similar-length empty/error response.
4. If it's a write operation (POST/PUT/PATCH/DELETE), go verify server-side state actually changed (same state-verification step emphasized in file 03) — Autorize only tells you the response *looked* like success, it does not independently confirm a database write actually happened.

### Example — one flagged row walked through

```
Autorize flags:
POST /api/v1/admin/users/41/promote
Original (admin session): 200 OK, 87 bytes, {"success":true,"role":"admin"}
Modified (regular-user session): 200 OK, 87 bytes, {"success":true,"role":"admin"}
Verdict: Bypassed!
```

- **What Autorize actually did:** took the exact request Burp captured while you clicked "promote" as an admin, silently swapped the `Authorization` header to the regular user's token, replayed it, and got back a response of near-identical shape.
- **Why this is a strong true positive:** the response isn't just "200 with an empty list" (a common false-positive shape) — it explicitly echoes `"role":"admin"` back, meaning the low-privilege token's request appears to have caused (or claims to have caused) an actual privilege change.
- **Manual confirmation step, non-optional:** log in as user 41 (or re-fetch their profile with the admin session) and confirm `role` is now genuinely `admin` server-side. Only after this confirmation is the finding solid enough to report.

---

## 6. Practical workflow for a full BFLA sweep on a target

1. Set up two accounts (admin/privileged + regular), log both in separately.
2. Configure Autorize with the regular account's auth header, enable unauthenticated testing too.
3. Set filters to scope only the API host and exclude static assets.
4. Systematically click through **every** feature of the app as the admin account — every admin panel screen, every settings page, every list/detail/edit/delete action — ensuring each generates proxy traffic Autorize can replay.
5. Supplement organic browsing with the discovery-phase candidate list from file 02: manually send each guessed/mined endpoint through Repeater once as admin (to seed it into proxy history) so Autorize also picks up and replays those, not just the ones reachable purely by clicking the UI.
6. Sort/filter the Autorize results table to "Bypassed!" rows first, work through each with the manual validation steps in section 5 above.
7. Export or screenshot confirmed findings with full request/response pairs (original + modified) for the report — Autorize's side-by-side comparison view is well-suited for this evidence format directly.

---

## 7. Limitations to keep in mind

- Autorize only replays requests that **actually pass through Burp's proxy** — anything the admin account's UI never triggers (dead code, feature-flagged functionality, undocumented endpoints not surfaced anywhere in the UI you clicked) won't appear unless you manually seed it via Repeater as in step 5 above.
- It cannot reason about **business logic context** — e.g., a lateral escalation case where the correct verdict depends on cross-referencing "is this admin token scoped to *this specific* team" (file 03, section 4) is often beyond what a length/status-code heuristic can catch; these require manual testing regardless of automation.
- GraphQL traffic (single endpoint, varying only in POST body) needs extra care in Autorize's matching config, since naive length-comparison on a single `/graphql` endpoint conflates dozens of unrelated queries/mutations into one "request" bucket unless body-aware matching is configured — for heavy GraphQL targets, manual mutation-by-mutation testing (per file 03 methodology) is often more reliable than relying on Autorize's default matching.

---
*Autorize accelerates coverage across a large endpoint set; it does not replace the manual state-verification discipline established in file 03 for confirming any individual finding is a real, exploitable BFLA rather than a heuristic false positive.*
