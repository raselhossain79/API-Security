# BOLA: Overview and Core Concepts

## 1. Definition

Broken Object Level Authorization (BOLA) occurs when an API endpoint accepts an object
identifier from the client and uses it to fetch or modify a resource **without verifying that
the authenticated caller is actually authorized to access that specific object**. The
authentication check passes (the caller has a valid session or token), but the authorization
check — "does *this* user own or have rights to *this* object" — is missing, incomplete, or
performed on the wrong scope.

The defining trait of BOLA is that the vulnerability lives at the level of the **individual
object**, not the endpoint or the function. An endpoint can require a valid token, enforce
correct roles, and still be completely broken if it never checks object ownership before
returning or modifying data tied to that object ID.

## 2. BOLA vs IDOR — same root cause, different context

This is the distinction that trips up a lot of testers moving from web app work into API work,
so it is worth being precise about it.

**Root cause: identical.** Both BOLA and IDOR describe the same underlying failure — a
user-supplied reference to an object is trusted without an ownership/authorization check
against the requesting identity. There is no technical difference in the vulnerability
mechanism itself.

**Origin and context: different.**

- **IDOR (Insecure Direct Object Reference)** is the older term, popularized by the OWASP Top
  Ten 2007. It was coined in the context of traditional server-rendered web applications,
  where the object reference typically shows up as a URL query parameter, a form field, or a
  path segment tied to a page (`?customer_number=132355`, `?id=wiener`, a static filename like
  `2.txt`). IDOR as a term makes no assumption about REST semantics, JSON bodies, or API
  versioning — it predates the API-first architecture shift.

- **BOLA (Broken Object Level Authorization)** is the term introduced by the OWASP API
  Security Top 10 (first in 2019, retained as API1:2023 in the 2023 revision) specifically for
  API contexts. It describes the identical failure but framed around how APIs expose object
  references: in URL path segments (`/api/users/{id}`), in JSON request bodies
  (`{"account_id": 4471}`), in query strings, and increasingly in GraphQL node IDs. The API
  Security Top 10 chose a new term deliberately, because IDOR-era testing methodology (mostly
  built around manipulating a visible URL parameter on a rendered page) does not map cleanly
  onto REST/JSON/GraphQL testing, where the same class of bug shows up across multiple HTTP
  methods, in nested JSON structures, and in machine-to-machine calls that have no browser UI
  at all.

**Testing methodology: different in practice.**

| Aspect | Classic IDOR (web app) | BOLA (API) |
|---|---|---|
| Where the ID usually lives | URL query string, hidden form field | URL path, JSON body (often nested), query string, GraphQL variables |
| How you discover it | Browse the app, change a visible parameter, reload the page | Enumerate API endpoints/spec first (Swagger/OpenAPI, JS bundle, mobile app traffic), then test each object-accepting endpoint independently |
| HTTP methods in scope | Usually just GET (page loads) | GET, POST, PUT, PATCH, DELETE — each tested separately, since an endpoint can enforce authorization on GET but not on PUT/DELETE |
| Volume of test surface | Handful of pages per app | Can be dozens to hundreds of endpoints per API, many undocumented |
| Response format | HTML — visual confirmation of leaked data | JSON — requires diffing structured responses, not visual inspection |
| Automation approach | Burp Intruder against one parameter | Requires spec-driven enumeration (per file 02) across many endpoints and multiple ID-bearing fields per endpoint |

**Practical takeaway used throughout this series:** BOLA is IDOR's methodology rebuilt for a
world where the client is a JSON API instead of a rendered page. Every technique in this
series is IDOR logic applied with API-aware tooling and API-aware scope.

## 3. Why APIs make this worse, not just different

A traditional web app usually has a small number of pages, and each page's data-access logic
tends to get security review because it is user-visible. An API backing a mobile app or SPA
frequently has an order of magnitude more endpoints, many of which are never rendered directly
and are only discovered by reverse-engineering client traffic. Backend teams under delivery
pressure commonly implement the *authentication* middleware once, globally, and assume it
covers authorization too — it does not. Each individual endpoint still needs its own
object-level ownership check, and it is extremely common for one endpoint in a resource
family to have that check while a sibling endpoint (a bulk export, an admin-adjacent read
path, a newly added PATCH route) does not.

Industry API security data consistently places BOLA as the single most reported finding in
both commercial API penetration tests and bug bounty programs that scope in APIs — more
common than injection flaws, broken authentication, or excessive data exposure. This is
consistent with the mechanism described above: the more endpoints an application exposes, the
more chances there are for exactly one of them to be missing the ownership check.

## 4. Horizontal privilege escalation vs cross-tenant BOLA — why they are treated separately in this series

Both are BOLA. Both share the identical technical root cause. They are split into separate
testing workflows in this series (see file `02-Testing-Methodology.md`) because they differ in
**scope of impact**, **severity**, and **how you obtain the comparison objects needed to prove
the bug**.

### Horizontal privilege escalation

User A, authenticated normally, accesses or modifies an object belonging to User B, where both
users are peers within the **same tenant/organization/account boundary**. This is the classic
IDOR scenario: two individual accounts on the same consumer app, one reading the other's order
history, profile, or private message.

- Attack requires: two low-privilege test accounts within the same application instance.
- Typical impact: exposure or tampering of one other user's personal data or records.
- Severity driver: sensitivity of the individual record (PII, financial data, health data).

### Cross-tenant BOLA

In multi-tenant SaaS APIs (the dominant architecture for B2B software — CRM platforms, HR
systems, project management tools, fintech back-office tools), each customer organization is a
separate "tenant" that should be completely isolated from every other tenant's data. Cross-tenant
BOLA occurs when a user authenticated inside Tenant A can access objects belonging to Tenant B
— a different customer's entire dataset, not just a different user in the same customer's
account.

- Attack requires: two accounts in **two different tenant organizations**, ideally on
  completely unrelated top-level accounts, not just different users invited to the same
  workspace.
- Typical impact: a single vulnerable endpoint can expose or corrupt data belonging to every
  other customer on the platform — the blast radius is the entire customer base, not one user.
- Severity driver: this is routinely rated Critical rather than High/Medium, because it breaks
  the fundamental multi-tenancy guarantee the SaaS vendor is contractually and often
  regulatorily obligated to provide (data residency, SOC 2 boundary commitments, HIPAA/GDPR
  tenant isolation). A single cross-tenant BOLA finding in a B2B SaaS product is often treated
  as an incident-response-triggering event by the vendor, not just a bug ticket.

**Why this distinction changes methodology, not just severity rating:** finding cross-tenant
BOLA requires deliberately provisioning test data across genuinely separate tenant boundaries
and specifically hunting for tenant-scoping logic (a `tenant_id`, `org_id`, or subdomain-based
scope) that might be checked inconsistently across endpoints — some endpoints might correctly
filter by tenant while a newer or less-reviewed endpoint filters only by object ID. This is a
distinct hunting pattern from horizontal escalation, which is discussed fully as its own
workflow in file 02.

## 5. Real-world industry framing

BOLA is not a theoretical category. It maps directly onto a long list of disclosed,
real-world API incidents at companies across fintech, social platforms, ride-sharing, and
e-commerce, where an attacker was able to pull another customer's account data, financial
records, or trip history simply by changing an object ID in an otherwise normal, authenticated
API call — no exploit chain, no memory corruption, just an authorization check that was never
written. This is precisely why OWASP ranked it API1 in both the 2019 and 2023 editions of the
API Security Top 10, and why it remains the highest-yield category to test first in any API
engagement.

## 6. What's next

`02-Testing-Methodology.md` walks through the manual, step-by-step process for both horizontal
and cross-tenant BOLA testing, including how to set up the test accounts and objects you need
before you start sending requests.
