# Authorization Testing on gRPC: BOLA and BFLA Patterns

## 1. How this maps to your existing API series

If you've worked through the BOLA and BFLA-adjacent material in your API Security Top 10 series (API1 BOLA, API5 BFLA equivalents), the underlying logic here is identical — the only thing that changes is the transport and message format. BOLA is still "can I access an object that isn't mine by changing an identifier," and BFLA is still "can I call a function/method my role shouldn't be able to reach." What changes on gRPC is *where* the identifier lives (a protobuf field instead of a URL path segment or JSON body key) and *how* you detect failure (a `grpc-status` trailer instead of an HTTP status code). This file assumes you're comfortable with the BOLA/BFLA concept itself and focuses on the gRPC-specific mechanics.

---

## 2. Why gRPC is structurally prone to both issues

Two facts from files 1 and 2 combine to make gRPC a strong candidate for authorization testing:

1. **Every RPC method is a direct function call with no implied access boundary.** In REST, nested resource URLs sometimes give an accidental hint about intended access scope (`/users/123/orders` at least visually implies orders belong to a user). gRPC methods are flat — `GetOrder(order_id)` — with no structural signal about ownership at all. Ownership checks live entirely in server-side logic, and it's easy for a developer to authenticate the caller (check "is this a valid, logged in user") without authorizing the object (check "does this order belong to this specific user").
2. **Reflection (file 2) hands you the complete method list, admin methods included, with no visual distinction from customer methods.** As noted in file 2 section 5, `AdminRefundOrder` sits in the same list as `GetOrder` with nothing marking it as privileged. If a developer relies on "the client app doesn't expose a UI button for this" as their only protection, BFLA testing finds it immediately.

---

## 3. BOLA testing on gRPC methods

### 3.1 The core test

For any method that takes an object identifier as input and returns or modifies data tied to that object:

1. Authenticate as **User A**. Call the method with **User A's own** object ID and confirm it succeeds normally — this is your baseline.
2. Using the **same User A session/token**, call the method again but substitute an object ID belonging to **User B** (obtained legitimately — your own second test account, or an ID observed in shared/public data).
3. Compare the result against your baseline. If the server returns User B's data (or successfully modifies it) using User A's credentials, that's BOLA.

### 3.2 Doing this with the Burp workflow from file 3

Using `OrderService.GetOrder` as the running example from files 1–3:

1. Capture a legitimate `GetOrder` call made as User A, with User A's `order_id` in the decoded body.
2. Send to Repeater (file 3, section 5).
3. In the decoded protobuf tab, edit `order_id` from User A's value to a User B order ID, leaving every other part of the request — critically, the auth token/session header — untouched.
4. Send, then check the decoded response body and the `grpc-status` trailer.

```
Baseline:  order_id = "ord_88213" (User A's own order) → grpc-status: 0, order data returned
Test:      order_id = "ord_88214" (User B's order)     → grpc-status: 0, User B's order data returned  ← BOLA
Expected:  order_id = "ord_88214" (User B's order)     → grpc-status: 7 (PERMISSION_DENIED) or 5 (NOT_FOUND)
```

A `grpc-status: 0` with User B's actual data in the response is a confirmed BOLA finding. A well-implemented server should return `PERMISSION_DENIED` (status 7) or, to avoid confirming the object even exists, `NOT_FOUND` (status 5) — note which one you get, since that's a useful detail for the report (returning `PERMISSION_DENIED` on someone else's valid ID is itself a minor information leak: it confirms the ID exists).

### 3.3 Don't stop at the "primary" identifier field

Reflection's `describe` output (file 2, section 6) shows you every field in the request message, not just the obvious one. Repeat the BOLA test against **every field that looks like it could reference another entity**, not just the field the client happens to populate for the "normal" flow. A `ListOrders` request might accept an optional `customer_id` filter field the UI never exposes but the schema defines — test that field explicitly, the same way you'd test an undocumented query parameter on REST.

### 3.4 Streaming methods need the same scrutiny, applied per message

Recall from file 1 section 4 that server-streaming methods (`rpc ListOrders (...) returns (stream Order)`) send multiple response messages over one call. Authorization checks are sometimes implemented only once, at the start of the stream (e.g., "is this caller allowed to call ListOrders at all") rather than per emitted item (e.g., "does each Order in this stream actually belong to the caller"). Test whether a streaming method that's supposed to be scoped to the caller's own data leaks other users' records mixed into the stream — this is a BOLA variant specific to streaming RPCs that has no clean REST equivalent, since REST has no native streaming response pattern to compare it to.

---

## 4. BFLA testing on gRPC methods

### 4.1 The core test

For every method reflection revealed (file 2, section 5 and 7), regardless of whether it looks customer-facing or admin-facing:

1. Call it as an **unauthenticated** caller (no token/session at all).
2. Call it as an **authenticated, low-privilege** caller (a normal customer account).
3. Compare both against what you'd expect that method to require.

```bash
# No credentials at all
grpcurl -plaintext target.internal:50051 ecommerce.v1.OrderService/AdminRefundOrder \
  -d '{"order_id": "ord_88213", "refund_amount": 999.00, "admin_reason": "test", "bypass_approval": true}'

# Low-privilege authenticated session
grpcurl -plaintext -H "authorization: Bearer <low_priv_token>" target.internal:50051 \
  ecommerce.v1.OrderService/AdminRefundOrder \
  -d '{"order_id": "ord_88213", "refund_amount": 999.00, "admin_reason": "test", "bypass_approval": true}'
```

(Full flag breakdown for every part of this command is in file 6 — this file focuses on the testing logic, not the flag syntax.)

If either call returns `grpc-status: 0` and an actual refund result rather than `PERMISSION_DENIED`/`UNAUTHENTICATED`, you've confirmed BFLA on an administrative method reachable by a normal or anonymous caller.

### 4.2 Systematic coverage using your reflection output

This is where file 2's full attack-surface dump (`grpc_attack_surface.txt`) becomes a literal test checklist. For every method in that file:

1. Note whether the method's name or apparent purpose (from its request/response message fields) suggests a privilege tier — admin, internal, debug, or plain customer-facing.
2. Call it with no auth, then with your lowest available privilege level.
3. Record the `grpc-status` for each. Build a simple table as you go — method name, expected privilege tier, actual result unauthenticated, actual result low-priv. This table is your deliverable for this phase and translates directly into report findings.

Do this exhaustively rather than selectively — the entire value of BFLA testing on gRPC comes from the fact that reflection removes any excuse for missing a method. A method that "looks" customer-facing by name can still turn out to have no authorization check at all, and the reverse — a scary-sounding method name that's actually properly locked down — is just as important to confirm and rule out.

### 4.3 Watch for role checks that use client-supplied data

A specific gRPC-flavored variant of BFLA worth testing explicitly: some implementations determine the caller's role or permissions from a field **inside the request message itself** (e.g., a `role` or `is_admin` field the client is expected to set correctly) rather than deriving it server-side from the authenticated session. This is easy to spot once you're in the decoded protobuf tab (file 3) — if you see a field like `requester_role` or `is_admin` sitting in a request message alongside legitimate business fields, test setting it directly, the same way you'd test a client-controlled role parameter in a REST JSON body. This is a design flaw independent of gRPC specifically, but gRPC's flat, all-fields-visible schema (via reflection) makes it unusually easy to spot compared to REST APIs where such a field might be buried in a large JSON body you'd need to notice on your own.

---

## 5. Interpreting `grpc-status` correctly during authorization testing

| Status code | Name | What it tells you |
|---|---|---|
| `0` | OK | Call succeeded — if you weren't supposed to have access, this is your finding |
| `5` | NOT_FOUND | Could mean genuinely doesn't exist, **or** could mean the server is deliberately hiding existence from an unauthorized caller — check whether this differs from the response to a truly nonexistent ID as a control |
| `7` | PERMISSION_DENIED | Server checked authorization and rejected you — expected/correct behavior for out-of-scope access |
| `16` | UNAUTHENTICATED | No valid credentials at all — expected for the unauthenticated leg of BFLA testing |
| `3` | INVALID_ARGUMENT | Not an authorization result — your request was malformed; fix the payload and retest before drawing conclusions |

The `5` vs `7` distinction is worth deliberately testing as its own step: call the method with an ID you know doesn't exist at all, and separately with an ID you know exists but belongs to another user. If both return identical `NOT_FOUND` responses, the server is correctly avoiding existence disclosure. If the real-but-not-yours ID returns something distinguishable (a different status, a different message, a slightly different response shape or timing), that's a minor information disclosure worth noting even in cases where the primary BOLA test is otherwise properly blocked.

---

## 6. Real-world notes

- The single most common authorization gap found on gRPC services in practice is authentication-without-authorization on object-scoped methods — the server correctly rejects calls with no token at all, which makes a superficial test look "secure," but never actually checks that the authenticated caller owns the specific object referenced by ID. Always run the full BOLA sequence (section 3) even on methods that clearly do enforce *some* authentication — that's necessary but not sufficient.
- Internal/service-to-service methods discovered via reflection (file 2) are disproportionately likely to have weak or no authorization, because they were built under the assumption that "only other backend services can reach this," an assumption reflection and network access directly undermine during testing — this is one of the highest-yield areas to focus BFLA testing time on.
- Watch for authorization checks implemented only on the unary "get single item" method but missing on the corresponding streaming "list all items" method (or vice versa) — teams sometimes secure the method they think of as "the sensitive one" and miss that a list/stream method leaks the same data at scale.
- When you find a BFLA issue on an admin method, always also test it as an authenticated low-privilege user in addition to fully unauthenticated — the write-up and severity differ meaningfully between "any authenticated customer can issue refunds" and "the internet at large, with zero credentials, can issue refunds," and clients need that distinction to prioritize the fix correctly.

---

## 7. Where this series goes next

- **File 5** — injection testing through the same decoded fields, once authorization boundaries are mapped.
- **File 6** — full `grpcurl` flag reference for scripting the systematic BFLA sweep described in section 4.2.
- **File 7** — consolidated cheatsheet covering both this file and file 5.
