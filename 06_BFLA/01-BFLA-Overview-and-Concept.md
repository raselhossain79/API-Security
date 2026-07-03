# Broken Function Level Authorization (BFLA) — Overview & Concept

**OWASP API Security Top 10 2023 — API5:2023**

---

## 1. What BFLA Actually Is

BFLA happens when an API checks **who you are** (authentication) but fails to correctly check **what you are allowed to do** (function-level authorization) before executing a privileged action.

The core failure is architectural: many APIs implement authorization as a single global check ("is this user logged in?") instead of a per-function check ("is this specific user, with this specific role, allowed to call this specific function?"). Once you're authenticated, the API assumes you're also authorized for every function you can reach — which is false in any system with roles (user, moderator, admin, support-agent, etc.).

BFLA is not about *data*. It's about *capability*. The question BFLA testing asks is:

> "Can a low-privileged, authenticated user successfully invoke a function that should only be reachable by a higher-privileged role?"

---

## 2. BOLA vs BFLA — The Distinction That Matters Most

This is the single most confused pair in the API Top 10, so it's worth being precise before anything else.

| | **BOLA (API1:2023)** | **BFLA (API5:2023)** |
|---|---|---|
| Full name | Broken Object Level Authorization | Broken Function Level Authorization |
| What's broken | Checking whether *this user* owns *this object* | Checking whether *this user's role* may call *this function* |
| Typical question | "Can I view/edit `order_id=1002` when I only own `order_id=1001`?" | "Can I call `DELETE /admin/users/5` as a regular user at all?" |
| Axis of authorization | Ownership (horizontal) | Role/privilege (vertical, sometimes horizontal-across-roles) |
| Classic example | Changing `?user_id=1001` to `?user_id=1002` and reading someone else's profile with your own normal-user token | Calling `/api/admin/reports/export` with a normal-user token that was never meant to reach that endpoint |
| Root cause | Missing "does `request.user.id == object.owner_id`" check | Missing "does `request.user.role` include permission for this route/handler" check |
| Where the check should live | Data-access layer (per-record) | Route/controller/middleware layer (per-endpoint) |

**The practical mental model:**

- BOLA = "I have a key to my own house. Does this lock also open my neighbor's house?"
- BFLA = "I have a key that opens *some* doors in the building. Does it also open the door marked 'Staff Only' or 'Server Room'?"

A single vulnerable application very often has **both**. For example: a support-agent role can view tickets (function-level access to `/tickets`, correctly gated) but the API doesn't check ticket ownership within that function, so agent A can read agent B's private ticket notes (BOLA layered inside a function that BFLA correctly gated). Conversely, a normal user might never be meant to reach `/tickets` at all — if they can, that's BFLA regardless of whose ticket they read.

**Why this distinction matters for reporting:** mislabeling a BFLA finding as BOLA (or vice versa) in a pentest report signals to the client that you don't understand their authorization model, and it changes the recommended fix. BOLA fixes are usually "add an ownership check in the query." BFLA fixes are usually "add a role check in the route/middleware, independent of any specific record."

---

## 3. Why BFLA Happens (Mechanism, Not Just Symptom)

BFLA is rarely a single missing `if` statement in a vacuum — it's usually a predictable engineering pattern:

1. **Authorization is implemented ad hoc per endpoint** instead of centrally (in middleware or a policy engine). Developers remember to add the admin check on the endpoints they think of as "obviously sensitive" (user deletion, billing) and forget the ones that don't feel sensitive at first glance (export, audit log read, internal config toggle, bulk actions).
2. **Frontend-driven security.** The web/mobile client only *renders* admin buttons for admin roles, and the team assumes that if the UI hides it, the backend doesn't need to enforce it. The API itself has no independent check — this is "security through UI obscurity," and it fails the instant someone crafts the request directly (Burp Repeater, curl, Postman).
3. **New endpoints inherit authentication middleware but not authorization middleware.** A framework's `@login_required`-style decorator gets applied everywhere, but the more granular `@role_required('admin')` decorator is only added where someone remembered to add it.
4. **HTTP verb-based route definitions get partial protection.** A developer secures `POST /api/users/{id}` (create) but forgets that `PUT` and `DELETE` on the same route path also need the same check — each verb is technically a separate function even though it shares a URL.
5. **Versioned or legacy API paths bypass newer authorization layers.** A `/v1/` endpoint gets deprecated and the team adds proper role checks only to `/v2/`, leaving the old, still-functional `/v1/` route with weaker or no checks.
6. **Microservice boundaries.** An internal service assumes the API gateway already enforced role checks, and the gateway assumes the downstream service will enforce it — both trust the other, and neither does it.

Every discovery and testing technique in this series exists because of one of these six root causes. Understanding *why* the gap exists tells you *where* to go looking for it.

---

## 4. Impact — Why This Sits at #5, Not Lower

BFLA findings escalate fast because the "function" being reached is often not just data exposure — it's an *action*:

- **Vertical privilege escalation to full admin** — user management, billing changes, feature flags, content moderation override, refund issuance.
- **Mass data exposure through admin-only bulk/export functions** (e.g., an unauthenticated-feeling `/admin/users/export` that dumps the entire user table, which is a BFLA finding with a BOLA-scale blast radius).
- **Business logic abuse** — triggering internal-only workflows (approve loan, mark order as shipped without payment, issue coupon codes) that were never meant to be user-reachable.
- **Chaining into full account or platform takeover** — see file 04 for chained escalation paths combining BFLA with BOLA and IDOR-style user enumeration.

In real-world engagements, BFLA findings frequently carry **Critical** severity precisely because the discovered function does something (write/delete/execute), not just reveal something. A read-only BOLA leaking one extra record is often Medium; a BFLA reaching `DELETE /admin/users/{id}` or `/admin/impersonate/{id}` is routinely Critical.

---

## 5. Vertical vs. Lateral BFLA — Quick Preview

Covered in full depth with worked examples in **file 04**, but the definitions belong here since they frame everything that follows:

- **Vertical escalation:** a lower-privileged role (regular user) successfully calls a function reserved for a higher-privileged role (admin, moderator, support). This is the "classic" BFLA case and maps directly to the OWASP definition.
- **Lateral escalation (role-to-role, not rank-to-rank):** an authenticated user in one restricted role reaches a function scoped to a *different* restricted role or a different tenant/organization's administrative surface — for example, a support agent for Company A reaching the admin panel functions scoped to Company B in a multi-tenant SaaS product. This isn't strictly "up" the privilege ladder in the traditional sense, but it's still a function-level authorization failure: the check "does this role/tenant combination match the resource being administered" is missing.

---

## 6. Real-World Framing

This class of bug is one of the most consistently reported findings in API-focused bug bounty programs and pentest engagements, for a structural reason: modern SPAs and mobile apps ship with a huge, mostly-hidden backend API surface, and only a fraction of it is exercised through the visible UI. Every hidden admin dashboard, internal tooling endpoint, or "will build the UI later" backend route is a candidate. Fintech, SaaS B2B (multi-tenant), and healthcare platforms are disproportionately represented in BFLA disclosures because they all share the same shape: many roles (user, org-admin, super-admin, support, billing), many tenants, and API-first architectures where the mobile/web client is just one of several consumers.

The practical takeaway for testing: **assume every "admin" or "internal" capability visible anywhere in the client-side code, documentation, or response payloads is reachable by a non-admin token until proven otherwise.** That assumption is the foundation for file 02 (discovery methodology).

---

## 7. What's Next

- **File 02** — Discovery methodology: finding privileged endpoints before you can test them.
- **File 03** — Common BFLA patterns with full request/response breakdowns.
- **File 04** — Vertical and lateral escalation, including chained attack paths.
- **File 05** — Manual testing workflow in Burp Suite.
- **File 06** — Cheatsheet.
