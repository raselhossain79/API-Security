# BFLA — Overview & Core Concept
### OWASP API Security Top 10 2023 — API5:2023 Broken Function Level Authorization

---

## 1. What BFLA actually is

Broken Function Level Authorization (BFLA) happens when an API checks **who you are** (authentication) but fails to properly check **what you're allowed to do** (authorization) at the level of a specific function or endpoint.

The core failure: the API exposes an administrative, privileged, or role-restricted operation, and the authorization logic either doesn't run for that operation, runs against the wrong role, or can be bypassed with a small manipulation of the request.

The result is that a low-privilege user (or an unauthenticated attacker, in the worst cases) can invoke a function that should have been entirely off-limits to them — not just view data they shouldn't see, but **execute an action** they shouldn't be able to perform.

---

## 2. BOLA vs BFLA — the distinction that matters most

This is the single most important conceptual line to draw clearly, because the two vulnerabilities look similar in tooling and mindset but are fundamentally different in what's broken.

| | **BOLA (API1:2023)** | **BFLA (API5:2023)** |
|---|---|---|
| Full name | Broken Object Level Authorization | Broken Function Level Authorization |
| What fails | Checking whether **this specific object** belongs to the requesting user | Checking whether the requesting user's **role/privilege level** permits this **function** |
| Question being asked | "Is `object_id=1042` mine to access?" | "Am I allowed to call this endpoint/action at all?" |
| Typical exploit shape | Change an ID in the URL/body: `GET /orders/1042` → `GET /orders/1043` | Call an endpoint that should require a different role: `GET /user/profile` → `GET /admin/users` |
| Who the victim is | Another user at the **same** privilege level | Either the system itself (vertical) or another user's admin-adjacent capability (lateral) |
| Root cause pattern | Missing ownership check on a data object | Missing role/permission check on a function |
| Example | Regular user views another regular user's invoice by changing `invoiceId` | Regular user calls `DELETE /admin/users/{id}`, an endpoint meant only for admins |

**The mental model Rasel should hold onto:** BOLA is about *whose data*, BFLA is about *whose privilege*. In BOLA, the endpoint is one you're allowed to call — you're just supplying someone else's identifier. In BFLA, the endpoint itself is one your role should never be able to reach, regardless of whose ID you put in it.

### Why they get confused in practice

Many real vulnerabilities are actually **both at once**, or sit right on the boundary:

- `PUT /api/users/{id}/role` called by a non-admin user, changing **their own** `id` — this is BFLA (a privileged *function*, role modification, being called by an unauthorized role), even though the object (their own user record) technically belongs to them.
- `DELETE /api/mechanic/reports/{id}` called against another user's `id` by a mechanic-role account — if the flaw is "any mechanic can delete any report" this is BOLA (object ownership). If the flaw is "a *customer* account can call the mechanic-only delete endpoint at all," that's BFLA.

The distinguishing question to ask for every finding: **is the flaw about "which object" or about "which function"?** If swapping the ID on an otherwise-identical, equally-permitted request causes the break, it's BOLA. If the request hits a **different capability tier** that the role should never reach — regardless of ID — it's BFLA.

---

## 3. Why BFLA is ranked #5 and why it's dangerous

BFLA consistently produces **higher-severity outcomes per finding** than most other API Top 10 categories, because the functions being reached are disproportionately the ones with real power:

- User management (promote/demote, delete accounts, reset passwords)
- Financial operations (refunds, balance adjustments, coupon generation)
- Content moderation and system configuration
- Data export/bulk operations
- Internal/administrative dashboards

A single BFLA finding on `POST /api/admin/users/{id}/promote` can mean full account takeover of every user on the platform, whereas a single BOLA finding typically exposes one victim's data per exploited ID. This is why BFLA findings tend to get rated Critical rather than High even when the request itself looks unremarkable.

### Real-world framing

BFLA-class bugs have been the mechanism behind several disclosed API incidents: privilege-escalation bugs in SaaS admin consoles where a "manage team" endpoint didn't check the caller's role, and API-driven mobile apps where the Android/iOS client simply hid admin buttons in the UI while the backend endpoint accepted calls from any authenticated session (a client-side-only control — the classic BFLA root cause). This pattern is common enough that "does the mobile app just hide the button, or does the server reject the request?" is a standard first question when scoping an API pentest.

---

## 4. Two flavors of privilege escalation under BFLA

- **Vertical privilege escalation** — a lower-privileged role (regular user) reaches a higher-privileged function (admin action). This is the "classic" BFLA case and the one most people mean by default.
- **Lateral escalation into privileged scope** — User A, who has no special privilege, reaches a function that operates on User B's *privileged* context (e.g., User B's admin panel, or an admin-only action scoped to User B's account). This is subtler: the attacker doesn't become an admin globally, but manipulates or exposes an administrative capability tied to someone else.

Both are covered in depth in `03-bfla-patterns-and-bypass-techniques.md`, with request-level breakdowns for each.

---

## 5. WAF / API Gateway relevance for BFLA — explicit statement

Per the requirement to never silently omit this consideration: **WAF and API Gateway bypass is only marginally relevant to BFLA, and here's why.**

WAFs and generic API gateways are pattern-matching and rate/schema enforcement layers. They are effective against vulnerability classes that have a recognizable *malicious payload signature* — SQL injection strings, XSS markup, path traversal sequences, oversized payloads, known exploit strings. BFLA has no such signature. A BFLA exploit request is, byte-for-byte, often **identical** to a completely legitimate admin request — the only thing that's "wrong" is *who* is sending it and whether the backend's authorization logic checked that. A WAF sitting in front of the API has no way to know that the bearer token attached to a syntactically-perfect `DELETE /api/admin/users/42` request belongs to a non-admin account, because that's an **application-layer authorization decision**, not a content-inspection decision.

Where gateway/WAF layers *do* intersect with BFLA (and this is covered as its own short section in the patterns file, not ignored):

- Some API gateways (Kong, Apigee, AWS API Gateway with custom authorizers, Azure APIM) **can** be configured to enforce role-based route access themselves, as a layer in front of the backend. When they are, gateway misconfiguration itself becomes the vulnerability — e.g., a route-level policy that checks JWT scope for `POST` but forgets `PATCH`, reproducing the HTTP-method-switching pattern at the gateway layer instead of the backend.
- Some gateways strip or normalize HTTP methods/headers in ways that can accidentally either fix or reintroduce BFLA-adjacent bugs (e.g., collapsing `POSTX` typo-methods, which removes one specific bypass trick but says nothing about the underlying missing check).
- WAFs occasionally flag BFLA *testing traffic* incidentally — rapid sequential requests to `/admin/*` paths from a single low-privilege session can trip rate-based or anomaly-based rules — but this is a side effect of testing behavior (volume/pattern), not detection of the vulnerability itself.

**Practical conclusion:** don't spend testing time trying to "bypass a WAF" for BFLA. Spend it on the authorization logic itself. If a WAF blocks your discovery scanning traffic, that's a rate-limiting/anomaly-detection problem to solve (slow down, rotate source IPs/tools per engagement rules, use realistic headers) — it is not the same problem as bypassing a security control that was actually designed to stop BFLA, because none of them are.

---

## 6. What the rest of this series covers

- **02 — Discovery methodology**: how to actually find the privileged endpoints in the first place (this is most of the real work in a BFLA test)
- **03 — Patterns & bypass techniques**: the concrete request-level tricks once you have candidate endpoints
- **04 — Autorize**: automating the "does every endpoint enforce role correctly" sweep across an entire app
- **05 — Cheatsheet**: condensed reference + full PortSwigger and crAPI lab map

---
*Series maintained as part of a personal OWASP API Security Top 10 2023 reference build. Content reflects manual testing methodology using Burp Suite Professional/Community against PortSwigger Web Security Academy labs and OWASP crAPI.*
