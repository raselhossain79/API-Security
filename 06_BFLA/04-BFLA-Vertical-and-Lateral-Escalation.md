# BFLA — Vertical and Lateral Privilege Escalation

BFLA findings are usually reported under one of two escalation shapes. Knowing which shape you're looking at changes how you describe impact and how you search for the next step in a chain.

---

## 1. Vertical Escalation — Definition and Mechanism

**Vertical escalation** is the classic BFLA case: a lower-privileged role reaches a function reserved for a strictly higher-privileged role in the same authorization hierarchy.

```
Regular User  --->  Support Agent  --->  Org Admin  --->  Super Admin
   (you are here)                                          (you reach this)
```

The check that's missing is a **rank comparison** — "does `current_user.privilege_level >= required_privilege_level for this function`."

### Worked Example — Full Chain

**Step 1 — confirm current role via a legitimate, low-privilege call:**
```
GET /api/me HTTP/1.1
Authorization: Bearer <token>
```
```
HTTP/1.1 200 OK

{"id":1042,"role":"user","orgId":88}
```
- **What's being tested:** establishing ground truth for the token's actual assigned role before attempting escalation, so the report can clearly state "this token was `role: user`" when describing impact.

**Step 2 — attempt a function documented (via Swagger/JS mining) as admin-only:**
```
POST /api/admin/users/2201/suspend HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json

{"reason":"policy violation"}
```
```
HTTP/1.1 200 OK

{"userId":2201,"status":"suspended"}
```
- **What's being tested:** whether the suspend-user function checks the caller's role at all, or only checks that the caller is authenticated and the target user ID exists.
- **Why the check fails:** the handler almost certainly does `if not current_user: return 401` and stops there — there's no second condition checking `current_user.role == 'admin'`. This is the single most common vertical BFLA root cause: authentication was implemented, authorization was not.
- **Impact:** a regular user can now suspend *any other user's account at will*, including competitors' accounts on a marketplace platform, or — worse — the accounts of the platform's own admins if their user IDs are guessable or enumerable.

**Step 3 — push further up the hierarchy (super-admin-only function):**
```
POST /api/admin/system/feature-flags HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json

{"flag":"maintenance_mode","enabled":true}
```
- **What's being tested:** whether the vulnerability is isolated to one poorly-secured controller (user management) or systemic across the entire admin API surface (platform-level configuration).
- **Why this step matters for reporting:** a client will sometimes push back on a single BFLA finding as "just one endpoint, low real-world likelihood." Demonstrating that the *same missing-role-check pattern* recurs across unrelated admin functions (user management, billing, system configuration) reframes the finding correctly: it's not one bug, it's a missing architectural layer.

---

## 2. Lateral Escalation — Definition and Mechanism

**Lateral escalation**, in the BFLA context, is not "role A to role B where B is higher" — it's **role/scope A to role/scope B where B is a different, equally-or-differently restricted boundary** the caller was never meant to cross. The two most common real-world shapes:

### 2a. Cross-Tenant Admin Function Access (Multi-Tenant SaaS)

In a multi-tenant product, "admin" is almost never global — it's admin **of your own organization/tenant only**. Lateral BFLA here means an org-admin for Tenant A can call admin functions scoped to Tenant B.

```
Org A Admin  --->  [should be blocked]  --->  Org B Admin Functions
```

**Worked example:**
```
GET /api/admin/orgs/88/users HTTP/1.1
Authorization: Bearer <org-88-admin-token>
```
```
HTTP/1.1 200 OK

[{"id":1042,"email":"jdoe@orgA.com"}, ...]
```
- **Baseline:** legitimate — this admin correctly manages their own org (`orgId: 88`).

```
GET /api/admin/orgs/91/users HTTP/1.1
Authorization: Bearer <org-88-admin-token>
```
```
HTTP/1.1 200 OK

[{"id":3310,"email":"ceo@competitor.com"}, ...]
```
- **What's being tested:** whether the admin-function's role check stops at "is this caller an org admin" (a role check, which passes) without a second check for "is this caller an admin **of the specific org ID being requested**" (a scope check, which should fail).
- **Why the check fails:** this is functionally identical to BOLA's ownership-check gap, but applied one level up — the missing check isn't "does this user own this record," it's "does this admin's tenant scope include this target tenant." Some teams classify this as "BFLA with a tenant-scoping failure"; others file it as a distinct multi-tenant isolation bug. Either label is defensible — what matters in the report is describing the actual mechanism precisely, since "admin function reachable across tenant boundaries" is a different fix (add tenant-scope middleware) than "admin function reachable by non-admins" (add role middleware).
- **Impact:** full cross-tenant data exposure and administrative control — in a B2B SaaS product this can mean one paying customer administering, viewing, or disabling another paying customer's entire account.

### 2b. Cross-Role, Same-Level Function Access

Distinct roles at a similar privilege *level* (support agent vs. content moderator vs. billing agent) often each have their own restricted function set. Lateral escalation here means a support agent reaching billing-agent-only functions, despite neither role being "above" the other.

**Worked example:**
```
POST /api/billing/refunds HTTP/1.1
Authorization: Bearer <support-agent-token>
Content-Type: application/json

{"orderId":55210,"amount":249.00}
```
```
HTTP/1.1 200 OK

{"refundId":9931,"status":"processed"}
```
- **What's being tested:** whether the refund function checks for the specific `billing_agent` permission, or just checks "is this caller *some kind* of internal staff role" (a coarse `is_staff` boolean rather than a granular permission).
- **Why the check fails:** many role systems evolve from a simple `is_staff: true/false` flag into a more granular permission model, but older endpoints written before the granular model existed never get retrofitted — they still check the original coarse flag, which every internal role satisfies.
- **Impact:** a support agent (who should only read tickets and issue apology credits up to a small limit, if any) can issue unlimited financial refunds — a direct financial-loss vulnerability.

---

## 3. Chaining BFLA With BOLA — Full Account Takeover Path

Real-world critical findings frequently chain BFLA (reach a privileged function) with BOLA (that function then lacks an object-ownership check of its own). Worked chain:

**Step 1 — BFLA: reach an admin-only "impersonate user" function as a regular user (per section 1's method):**
```
POST /api/admin/impersonate HTTP/1.1
Authorization: Bearer <low-priv-token>
Content-Type: application/json

{"targetUserId":2201}
```
```
HTTP/1.1 200 OK

{"impersonationToken":"eyJhbGciOi..."}
```
- **Why step 1 is BFLA:** a regular user should never be able to call the impersonation endpoint at all — this is a pure function-level check failure, identical in mechanism to section 1's example.

**Step 2 — BOLA layered inside the same function: no check on whether `targetUserId` is a legitimate support target:**
- **What's being tested:** even if the impersonation function *were* correctly restricted to support staff, does it further check that the target user is one the agent is authorized to impersonate (e.g., only users who opened a support ticket), or does it accept **any** user ID including other admins?
- **Result:** if `targetUserId: 1` (often the first-created account, frequently a super-admin or the platform owner) returns a valid impersonation token, the chain goes from "regular user" to "fully authenticated as the platform's original super-admin" in two requests.
- **Why this matters for severity:** report this as a single chained Critical finding, not two separate Medium findings — the combination is what produces full account/platform takeover, and the fix requires addressing both layers (role check on the endpoint, and ownership/scope check within it).

---

## 4. Reporting Guidance

For every BFLA finding, state explicitly:
1. **Escalation type** — vertical, lateral (cross-tenant), or lateral (cross-role).
2. **Starting privilege** and **reached privilege**, in the client's own role terminology, not generic "low/high."
3. **Whether the finding is isolated or systemic** (i.e., did the same root-cause pattern reproduce across multiple unrelated endpoints).
4. **Whether it chains** into further impact (BOLA, mass assignment, data exfiltration at scale) — chained findings should be reported together with a combined severity, not fragmented.

---

## 5. What's Next

**File 05** walks through the manual Burp Suite workflow used to efficiently test for all of the above — session/token swapping, request diffing, and using Burp's extensions to semi-automate the "replay every endpoint with every role" sweep.
