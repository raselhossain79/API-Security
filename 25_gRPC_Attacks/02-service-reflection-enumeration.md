# gRPC Service Enumeration via Reflection

## 1. What reflection is and why it exists

gRPC Server Reflection is an optional gRPC service that a server can register alongside its real services. When enabled, it exposes a special service — `grpc.reflection.v1.ServerReflection` (or the older `grpc.reflection.v1alpha.ServerReflection`) — that answers questions like "what services do you host?" and "what does message type `X` look like?" over the network, using gRPC itself.

It exists for legitimate developer convenience: tools like `grpcurl`, Postman, and internal debugging dashboards use it so engineers don't have to manually distribute `.proto` files to every client. From a testing perspective, reflection is the single highest-value reconnaissance step in gRPC testing, because when it's enabled it hands you the **entire attack surface map** for free — no `.proto` file needed, no source code access needed.

**This is directly equivalent to an exposed Swagger/OpenAPI spec on a REST API** — same risk profile, same reason it happens (developer convenience left on in production), same remediation (disable in production, or gate it behind internal-only network access).

---

## 2. What reflection exposes

When reflection is enabled and you query it, you get:

- **Every service** registered on that server (not just the "intended" public ones — if a service is registered on the same gRPC server instance, reflection will list it, including internal/admin services the developers may not have meant to expose alongside the public API).
- **Every RPC method** on each service.
- **The full message schema** for every request and response type — every field name, field number, and field type, including nested messages and enums.
- Whether a method is unary, client-streaming, server-streaming, or bidirectional-streaming.

What reflection does **not** expose:

- Authentication or authorization requirements for a method. Reflection tells you a method exists and what its input looks like; it tells you nothing about whether calling it requires a valid token, and nothing about whether the caller's role is checked. That gap is exactly what file 4 (authorization testing) exploits — reflection gives you the map, authorization testing tells you which doors are actually locked.
- Business logic or validation rules beyond wire-level types (e.g., it won't tell you that `quantity` must be positive, only that it's an `int32`).

## 3. Why this matters as an enumeration technique

Compare the effort of testing a REST API with no Swagger doc (guessing endpoints, brute-forcing paths, reading JS bundles for hints) against a gRPC API with reflection enabled: one `grpcurl ... list` command gives you a complete, authoritative list of every callable method. This is why reflection enumeration should be your **first move** on any gRPC target before you touch Burp or write a single payload — it tells you exactly how large the attack surface is and exactly what shape every request needs to be, which then feeds directly into authorization testing (file 4) and injection testing (file 5).

---

## 4. Checking whether reflection is enabled

The most direct way is with `grpcurl` (full flag breakdown in file 6; the commands here are explained inline so this file is self-contained):

```bash
grpcurl -plaintext target.internal:50051 list
```

- `grpcurl` — the tool itself.
- `-plaintext` — tells grpcurl to connect without TLS. Use this for internal/unencrypted targets. If the target expects TLS, drop this flag (grpcurl uses TLS by default) or use `-insecure` if you need TLS without certificate validation (self-signed certs, common on internal or staging systems).
- `target.internal:50051` — host and port. gRPC has no fixed default port the way HTTP does; common ones seen in the wild are `50051` (the gRPC "hello world" convention lots of teams copy), `443`, `8080`, and `9090`, but treat this as target-specific — check load balancer configs, docs, or just try common ports during recon.
- `list` — the grpcurl verb meaning "list everything reflection will tell me about." With no further argument, this lists every service.

If reflection is enabled, you'll get output like:

```
ecommerce.v1.OrderService
ecommerce.v1.UserService
grpc.health.v1.Health
grpc.reflection.v1alpha.ServerReflection
```

If reflection is disabled, you'll get a connection-level error along the lines of `rpc error: code = Unimplemented desc = unknown service grpc.reflection.v1alpha.ServerReflection` — this specific error is diagnostic: it tells you the server is reachable and speaking gRPC, but the reflection service specifically hasn't been registered. At that point your enumeration path shifts to acquiring `.proto` files some other way — checking for leaked files in mobile app bundles, JS source maps, GitHub, or public API documentation, or falling back to traffic analysis of legitimate client requests you can observe.

---

## 5. Enumerating methods on a service

Once you know a service exists, list its methods:

```bash
grpcurl -plaintext target.internal:50051 list ecommerce.v1.OrderService
```

Same command as before, but with the fully-qualified service name appended. Output:

```
ecommerce.v1.OrderService.GetOrder
ecommerce.v1.OrderService.ListOrders
ecommerce.v1.OrderService.CreateOrder
ecommerce.v1.OrderService.CancelOrder
ecommerce.v1.OrderService.AdminRefundOrder
```

This is the moment reflection earns its keep as a security tool: notice `AdminRefundOrder` sitting in the same list as ordinary customer-facing methods with no visual or structural distinction. There is nothing in the gRPC method-listing mechanism that separates "customer" methods from "admin" methods — that separation, if it exists at all, is enforced (or not) entirely in server-side authorization logic per method. **Every method you see here is a candidate for BFLA testing in file 4** — call it as a low-privilege or unauthenticated user and see whether the server actually checks.

---

## 6. Describing a service or method in detail

```bash
grpcurl -plaintext target.internal:50051 describe ecommerce.v1.OrderService
```

- `describe` — the grpcurl verb that returns the full schema for a symbol, rather than just its name.
- The symbol `ecommerce.v1.OrderService` — describing a service shows every method signature in `.proto`-like syntax.

Output looks like:

```
ecommerce.v1.OrderService is a service:
service OrderService {
  rpc GetOrder ( .ecommerce.v1.GetOrderRequest ) returns ( .ecommerce.v1.Order );
  rpc ListOrders ( .ecommerce.v1.ListOrdersRequest ) returns ( stream .ecommerce.v1.Order );
  rpc CreateOrder ( .ecommerce.v1.CreateOrderRequest ) returns ( .ecommerce.v1.Order );
  rpc CancelOrder ( .ecommerce.v1.CancelOrderRequest ) returns ( .ecommerce.v1.Order );
  rpc AdminRefundOrder ( .ecommerce.v1.AdminRefundRequest ) returns ( .ecommerce.v1.RefundResult );
}
```

This is functionally a reconstructed `.proto` file — you now know every method's exact input and output message type without ever having source access. Read this the same way you read section 4 of file 1 (fundamentals) — every `rpc` line is one item on your test plan.

To go one level deeper and see the fields of a specific message:

```bash
grpcurl -plaintext target.internal:50051 describe ecommerce.v1.AdminRefundRequest
```

Output:

```
ecommerce.v1.AdminRefundRequest is a message:
message AdminRefundRequest {
  string order_id = 1;
  double refund_amount = 2;
  string admin_reason = 3;
  bool bypass_approval = 4;
}
```

This tells you exactly what fields to populate to call `AdminRefundOrder` yourself — including `bypass_approval`, a field name that should immediately raise your interest for both BFLA testing (does the server actually require the admin role to call this method at all?) and business-logic testing (does setting `bypass_approval = true` actually skip a control it shouldn't?).

You can describe a single method directly too:

```bash
grpcurl -plaintext target.internal:50051 describe ecommerce.v1.OrderService.AdminRefundOrder
```

This is useful when you only want one method's signature without scrolling through the whole service.

---

## 7. Building a full attack-surface map efficiently

For anything beyond a handful of services, script the walk instead of doing it method by method:

```bash
for svc in $(grpcurl -plaintext target.internal:50051 list | grep -v reflection); do
  echo "=== $svc ==="
  grpcurl -plaintext target.internal:50051 describe "$svc"
done > grpc_attack_surface.txt
```

- `grpcurl ... list | grep -v reflection` — lists all services, then filters out `grpc.reflection.v1alpha.ServerReflection` itself (and, if present, `grpc.health.v1.Health`, which you may also want to exclude — it's rarely a meaningful target) so you're not wasting cycles describing reflection's own bookkeeping service.
- The `for` loop calls `describe` on every remaining service and writes the full schema for the entire server to `grpc_attack_surface.txt`.

The output of this single command is your reconnaissance deliverable — it's the gRPC equivalent of a scraped Swagger spec, and it's what you hand off to build your test plan for files 4 and 5.

### Exporting as reusable descriptor files

If you want to keep this schema for later use with tools that need proper `.proto` or descriptor files (rather than free text), export it directly:

```bash
grpcurl -plaintext target.internal:50051 describe ecommerce.v1.OrderService --msg-template
```

- `--msg-template` — instead of just showing the schema, this flag also prints a filled-out JSON template with placeholder values for every field, showing you exactly what a valid request body should look like. This saves you from manually inferring valid JSON structure from the schema alone, especially for nested or repeated fields — genuinely useful once you move into file 6's `describe`/`-d` workflow for crafting real calls.

---

## 8. Testing reflection access control itself

Before you assume reflection is safe to rely on, test one more thing: **is reflection itself gated behind authentication?** Some teams correctly restrict reflection to internal networks or authenticated callers, while leaving the actual RPC methods less protected — or the inverse, where reflection is wide open but individual methods enforce auth. Test both independently:

```bash
grpcurl -plaintext -H "authorization: Bearer <token>" target.internal:50051 list
grpcurl -plaintext target.internal:50051 list
```

Run the enumeration once with a valid session token attached (`-H` adds a header — full flag reference in file 6) and once with no credentials at all. If the unauthenticated call succeeds, reflection itself is an information-disclosure finding independent of anything else you find on individual methods — report it as such, since the fully-qualified names of internal-only services (`AdminRefundOrder` sitting next to customer methods) is meaningful disclosure on its own, even before you test whether those methods enforce authorization when called.

---

## 9. When reflection is disabled — fallback enumeration paths

Reflection being off doesn't end your recon, it just changes the source of your schema:

- **Decompile or inspect mobile app bundles.** Android APKs and iOS IPAs that speak gRPC frequently embed compiled `.proto` descriptors or the generated client stub code, which reveals method and message names even without a live reflection endpoint.
- **Check JS bundles for gRPC-Web clients.** A web frontend using gRPC-Web ships generated JS/TS client stubs to the browser — these are readable source, not compiled binaries, and typically contain full method names, field names, and message structures in plaintext or lightly minified form.
- **Search public repos and API documentation.** `.proto` files are source code; they leak the same way any other source artifact leaks — public GitHub repos, Postman collections, internal wikis indexed by search engines.
- **Passive traffic analysis.** Capture legitimate traffic from a real client (browser dev tools for gRPC-Web, or a proxied mobile app for native gRPC) and reconstruct field structure from observed request/response pairs, cross-referenced with a heuristic Burp decoder (file 3) that doesn't require a schema.

---

## 10. Real-world notes

- In practice, reflection is left enabled in production far more often than teams expect — it's usually on by default in the standard gRPC server libraries (Go, Java, Python, Node) unless a developer explicitly disables it, and it's genuinely useful for internal debugging, so it tends to survive the transition from staging to production unless someone specifically thinks to gate it.
- When reflection reveals a service name with an obviously internal-sounding package or prefix (`internal.v1`, `admin.*`, `debug.*`), that's worth flagging even before deeper testing — it's a strong signal the service was never intended to be reachable from where you're standing, which is itself worth raising as a network segmentation or exposure finding.
- Reflection responses can be large on servers with many services — redirect output to a file (as in section 7) rather than trying to read it inline; you'll want to grep back through it repeatedly as you build out test cases for files 4 and 5.
- Some organizations run reflection on an internal-only listener port distinct from the public-facing gRPC port. If reflection fails on the port your client traffic uses, it's worth a quick port sweep (`443`, `50051`, `8080`, `9090`, and anything found in configs or app binaries) before concluding it's disabled entirely.

---

## 11. Where this series goes next

- **File 3** — decoding and modifying the protobuf messages you now know the shape of, inside Burp Suite.
- **File 4** — using this enumerated method list to systematically test BOLA and BFLA on every RPC method.
- **File 6** — the complete `grpcurl` flag reference, including authenticated calls, TLS handling, and invoking methods with real data.
