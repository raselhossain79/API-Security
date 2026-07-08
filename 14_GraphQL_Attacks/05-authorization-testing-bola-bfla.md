# Authorization Testing in GraphQL (BOLA/BFLA on Resolvers)

File 5 of 9. Assumes file 1 (resolvers as the true access-control boundary)
and file 2 (using introspection to find mutations/fields to test). This
file covers testing BOLA (Broken Object Level Authorization) and BFLA
(Broken Function Level Authorization) specifically in a GraphQL context,
where the target of authorization testing is the **resolver**, not the
endpoint.

---

## 1. Why "test the endpoint" doesn't apply here

In REST API testing, BOLA/BFLA methodology centers on the endpoint:
`GET /api/users/3/invoices` either checks that the caller owns user 3's
invoices or it doesn't; `POST /api/admin/users` either checks the caller is
an admin or it doesn't. One endpoint, one authorization decision to test.

GraphQL has one endpoint total. **Every field is its own potential
authorization decision point**, because every field has its own resolver
(file 1, section 10), and there is no framework-level guarantee that every
resolver independently re-checks authorization — some frameworks make it
easy to add auth middleware once per resolver; others make it easy to
forget, especially for fields added later or fields that seem "obviously
safe" to the developer who wrote them. This means GraphQL authorization
testing isn't "test the endpoint," it's **"test every field and every
mutation argument that touches an object you shouldn't be able to
access."** The methodology below is how you do that systematically instead
of ad hoc.

---

## 2. BOLA in GraphQL: object-level authorization on fields and arguments

BOLA is: *can I access or modify an object that isn't mine, by supplying a
different ID than the one I'm supposed to use?* In GraphQL this shows up in
two places:

### 2a. ID arguments on queries

```graphql
query {
  user(id: 4) {
    email
    billingAddress
  }
}
```

Breakdown: `id: 4` is a plain, client-supplied argument. If your own
account is user 3, and the server returns user 4's `email` and
`billingAddress` without erroring, that's a direct BOLA — the resolver for
`user(id:)` fetched by ID without checking that the requester is entitled
to view that particular ID's data.

**Testing method:** for every query field that takes an ID-like argument
(from the introspected schema, file 2 — look at argument names/types, not
just field names, since an innocuous-sounding query can still take an `id`
argument), systematically substitute IDs belonging to a second test
account, sequential/adjacent IDs, and IDs obtained from other parts of the
API's own responses (e.g. an `authorId` returned inside a `Review` object
becomes your next `user(id:)` test value). This is exactly the same IDOR
methodology used in REST testing — the difference is *where* you have to
apply it (every field, not every endpoint) and that you need the schema
(file 2) to know the full set of fields that take ID arguments in the first
place, since many won't be visible from normal UI traffic.

### 2b. Nested object access through unrelated top-level fields

This is the pattern that's genuinely GraphQL-specific and easy to miss.
Because a query can traverse relationships, you don't need a direct
`user(id:)`-style entry point at all — you can sometimes reach the same
protected data through a completely different, seemingly unrelated field
that the developer didn't think to protect because they were focused on
securing the "obvious" direct-access field.

```graphql
query {
  product(id: 1) {
    reviews {
      author {
        email
        billingAddress
      }
    }
  }
}
```

If the developer correctly locked down `Query.user(id:)` to prevent
arbitrary user lookups, but the `Review.author` resolver just returns the
linked `User` object without re-checking whether the current caller should
be able to see that user's private fields, you've reached the same
sensitive data through a side door. **This is why testing must be
field-by-field across the whole schema graph, not just "test every
top-level query with an ID argument."** Walk every path in the introspected
schema that terminates at a sensitive type (like `User`), regardless of how
many relationship hops it takes to get there.

### 2c. BOLA via mutations

Same principle, write side:

```graphql
mutation {
  updateInvoice(id: 55, status: "PAID") {
    id
    status
  }
}
```

Test with invoice IDs belonging to other accounts. A missing ownership
check here is a BOLA that also has write impact — worth flagging as higher
severity than a read-only equivalent.

---

## 3. BFLA in GraphQL: function-level authorization on mutations

BFLA is: *can I call an operation that should be restricted to a different
privilege level (e.g. admin-only), regardless of which object it targets?*
This is where file 2's introspection payoff directly matters: **the schema
frequently contains mutations that no UI element ever calls**, because the
frontend for a given role simply never renders the button — but the backend
mutation resolver still exists and still executes if called directly,
unless it independently checks the caller's role.

```graphql
mutation {
  setUserRole(userId: 3, role: "ADMIN") {
    id
    role
  }
}
```

**Testing method:**
1. From the full introspected mutation list (file 2), identify every
   mutation you have never observed called by the UI for your current
   privilege level — these are your BFLA candidates, ranked by how
   privileged-sounding the name is (`setUserRole`, `deleteOrganization`,
   `issueRefund`, `exportAuditLog`).
2. Call each candidate directly as your low-privilege test account,
   supplying valid-shaped arguments (from the introspected argument types,
   so the call doesn't fail on a type/validation error that masks the
   actual authorization outcome).
3. Distinguish carefully between three possible outcomes, because they mean
   different things:
   - **A GraphQL validation/type error** (e.g. "argument X is required")
     — inconclusive; you haven't reached the resolver's authorization logic
     yet, only the schema-validation layer. Fix the argument shape and
     retry.
   - **An explicit authorization error** (e.g. "Forbidden", "Insufficient
     permissions", HTTP 200 with a GraphQL error in the `errors` array
     naming an auth failure) — correctly defended; not a finding.
   - **A successful result matching the mutation's actual intended
     effect** — confirmed BFLA. Verify impact carefully (e.g. actually
     check that the role change or deletion took effect) before reporting,
     since some resolvers return a misleadingly successful-looking payload
     without actually performing the write (rare, but worth ruling out to
     avoid a false positive in your report).

---

## 4. Field-level authorization gaps (a narrower but common variant)

Sometimes the operation itself is correctly gated, but a *specific field*
within its result is not. This overlaps with the "accidental field
exposure" scenario introduced in file 2:

```graphql
query {
  getUser(id: 0) {
    username
    password
  }
}
```

Here `getUser` might be intentionally accessible to any logged-in user
(e.g. for a public profile-lookup feature returning `username`), but the
`User` type's `password` field — present in the schema, perhaps left over
from an internal admin tool that shares the same underlying type — has no
independent field-level check and gets returned to anyone who happens to
request it in their selection set. **This is a distinct bug from both BOLA
and BFLA**: the operation is authorized, the object being accessed might
even be your own, but one specific field on the returned type leaks data it
shouldn't. Test by requesting every field on every returned type (again,
from the introspected schema) rather than only the fields the UI normally
selects — the UI's selection set tells you nothing about what the resolver
would return if asked for more.

---

## 5. A systematic authorization-testing workflow

Putting sections 2–4 together into one repeatable process:

1. **Get the full schema** via introspection (file 2).
2. **Enumerate every field that returns a sensitive type** (`User`,
   `Invoice`, `Organization`, etc.) — build a list of every path that leads
   to that type, direct or nested, regardless of how many relationship hops
   away it is.
3. **Enumerate every mutation** and bucket each one by apparent privilege
   level based on name and the type it operates on.
4. **Test with a matrix of accounts**, minimum: low-privilege account A,
   low-privilege account B (to test cross-account BOLA between two peers,
   not just low-vs-admin), and an admin/privileged account if available (to
   confirm the mutation *does* work correctly for the intended role, which
   matters for distinguishing "broken" from "intentionally disabled
   entirely").
5. **For each path/mutation, record**: which account tested it, the exact
   query/mutation sent, and the outcome bucketed per section 3's three
   categories.
6. **Escalate interesting findings** — e.g. if `setUserRole` correctly
   rejects account A trying to promote itself, still test whether account A
   can call it targeting a *different* low-privilege account's ID (a BOLA +
   BFLA combination — role-check passed via some other flawed logic path,
   or the ownership check on `userId` is what's actually missing, not the
   role check itself).

---

## 6. WAF / API gateway relevance for this specific vulnerability

**BOLA and BFLA are business-logic/authorization vulnerabilities, and this
category is fundamentally not addressable at the WAF or gateway layer.** A
WAF operates on request shape, syntax, rate, and known attack signatures —
it has no way to know that user ID `4` belongs to someone other than the
authenticated caller, or that a given mutation is supposed to be
admin-restricted, because that requires business context the gateway simply
doesn't have. This is worth stating explicitly per this series' convention:
**where a WAF/gateway defense isn't meaningfully relevant to a topic, that
gets said outright rather than a token bypass section being invented for
completeness.**

The one partial exception worth noting: some API gateways with GraphQL
schema-awareness support declarative, per-field or per-mutation
authorization policies configured at the gateway layer (e.g. "field `role`
on type `User` requires scope `admin:read`") — effectively pushing part of
the authorization decision out of application code and into the gateway.
Where this is in place, it is a legitimate additional defense layer worth
testing directly (does the gateway policy actually match the intended
authorization model, or does it have its own gaps/misconfigurations), but
it is a genuine access-control mechanism at that point, not a WAF-style
signature/pattern defense — testing it uses the exact same methodology as
sections 2–5, just against a policy enforced one layer earlier in the
request path.

---

## 7. Summary checklist for this file

- [ ] Build a full list of schema paths (direct and nested) that reach
      sensitive types.
- [ ] Test ID-argument substitution on every such path with a second test
      account's IDs, not just your own account's adjacent IDs.
- [ ] Specifically test nested/indirect access paths, not just direct
      top-level ID lookups.
- [ ] Enumerate every mutation from introspection and bucket by apparent
      privilege level; call each candidate directly as a low-privilege
      account.
- [ ] Distinguish validation errors, authorization errors, and true
      successes carefully before recording a finding.
- [ ] Test field-level exposure by requesting the full field set on
      returned types, not just UI-selected fields.
- [ ] Use a minimum two-low-privilege-account matrix to catch peer-to-peer
      BOLA, not just low-vs-admin BFLA.
- [ ] Do not invent a WAF-bypass angle for this category — state plainly
      that authorization logic is out of scope for perimeter defenses,
      except where a gateway implements genuine declarative
      field/mutation-level policy.

**Next: file 6 — Injection Testing in GraphQL**, covering how classic
injection classes (SQL, NoSQL, OS command) resurface through GraphQL
variables and inline arguments once they reach a resolver.
