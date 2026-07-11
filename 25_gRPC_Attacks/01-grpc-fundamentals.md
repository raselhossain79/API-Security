# gRPC Fundamentals for Pentesters

## 1. Why this file exists

You cannot test what you cannot read. gRPC traffic looks like binary noise in a normal proxy until you understand three mechanisms: Protocol Buffers (the serialization format), `.proto` service definitions (the schema), and HTTP/2 framing (the transport). This file covers each mechanism-first — enough to test effectively, not a full protocol implementation guide.

Everything downstream in this series (reflection enumeration, protobuf manipulation, authorization testing, injection) assumes you understand what's in this file.

---

## 2. What gRPC actually is

gRPC is a Remote Procedure Call (RPC) framework built by Google. Instead of a client hitting REST-style resource URLs (`GET /users/123`), a gRPC client calls a **method** on a **service** as if it were a local function: `UserService.GetUser(request)`. Under the hood, that call is:

1. Serialized into binary using Protocol Buffers.
2. Wrapped in a small gRPC framing header.
3. Sent as an HTTP/2 request to a path like `/package.ServiceName/MethodName`.
4. The server deserializes it, executes the method, serializes the response, and sends it back the same way.

This matters for testing because the "URL" in gRPC is really a method name, the "body" is always binary, and the transport is always HTTP/2 (not HTTP/1.1 in native gRPC). Every one of those three facts breaks assumptions that REST-focused tooling makes by default.

---

## 3. Protocol Buffers (protobuf) — the serialization format

### 3.1 What protobuf is, mechanically

Protobuf is a binary serialization format. Instead of sending readable JSON like:

```json
{"user_id": 42, "username": "carlos"}
```

protobuf sends a sequence of `(field_number, wire_type, value)` triples with no field names at all. The field names only exist in the `.proto` schema — the wire format has no idea what a "field" is called, only what number it is.

A protobuf message on the wire is a sequence of **tag-length-value** entries:

```
tag = (field_number << 3) | wire_type
```

- **field_number**: an integer you assign in the `.proto` file (e.g., `user_id = 1`).
- **wire_type**: a 3-bit code telling the parser how to read the value. The wire types that matter for testing:
  - `0` = Varint — used for `int32`, `int64`, `bool`, `enum`. Variable-length integer encoding.
  - `1` = 64-bit — used for `fixed64`, `double`.
  - `2` = Length-delimited — used for `string`, `bytes`, embedded messages, and repeated fields. This is the one you'll manipulate most, because it contains your injection payloads.
  - `5` = 32-bit — used for `fixed32`, `float`.

**Why this matters for testing**: protobuf is untyped on the wire in a specific sense — the parser trusts the wire type, not the schema, unless the schema is enforced strictly. This is why blackbox decoders (used when you don't have the `.proto` file) can only guess field types from the wire type and often misinterpret a field (e.g., a length-delimited field could be a string, bytes, or a nested message — the decoder has to guess). Understanding this is what lets you read a heuristic decode intelligently instead of trusting it blindly.

### 3.2 A minimal worked example

Given this `.proto` snippet:

```protobuf
message LoginRequest {
  string username = 1;
  string password = 2;
}
```

A request for `username="carlos"`, `password="pass123"` encodes roughly as:

```
0A 06 63 61 72 6C 6F 73          # field 1, wire type 2, length 6, "carlos"
12 07 70 61 73 73 31 32 33       # field 2, wire type 2, length 7, "pass123"
```

Breaking down `0A`: in binary this is `00001 010`. The last 3 bits (`010` = 2) are the wire type (length-delimited). The remaining bits (`00001` = 1) are the field number. So `0A` = field 1, length-delimited. The next byte (`06`) is the length of the value in bytes, then the raw UTF-8 bytes follow.

This is exactly what you'll see reconstructed in Burp's decoded protobuf tab — field numbers instead of names if no `.proto` is loaded, real field names if one is.

### 3.3 What this means practically

- Field **names** are testing metadata, not wire data. If you don't have the `.proto` file, you'll see `field_1`, `field_2`, etc. Reflection (covered in file 2) is how you recover real names and types without a `.proto` file on disk.
- Because field meaning is positional (by number, not name), an attacker can send a field number that exists in the schema but that the client UI never populates — this is the protobuf equivalent of a hidden form field, and it is a common source of mass-assignment-style bugs.
- Because protobuf has no inherent length limit or type enforcement at the wire level, injecting a string wildly larger or differently typed than expected is often accepted by permissive server-side deserializers, which is your entry point for injection testing (file 5).

---

## 4. Reading `.proto` files

When you do have a `.proto` file — because it leaked, was published, or reflection gave you the descriptor — you need to be able to read it quickly.

```protobuf
syntax = "proto3";

package ecommerce.v1;

service OrderService {
  rpc GetOrder (GetOrderRequest) returns (Order);
  rpc ListOrders (ListOrdersRequest) returns (stream Order);
  rpc CreateOrder (CreateOrderRequest) returns (Order);
}

message GetOrderRequest {
  string order_id = 1;
}

message Order {
  string order_id = 1;
  string customer_id = 2;
  double total_amount = 3;
  OrderStatus status = 4;
  repeated LineItem items = 5;
}

enum OrderStatus {
  PENDING = 0;
  PAID = 1;
  SHIPPED = 2;
}
```

What to extract from this as a tester, line by line:

- `package ecommerce.v1;` — this prefix is required when you address the service over the wire. The full method path becomes `/ecommerce.v1.OrderService/GetOrder`.
- `service OrderService { ... }` — this is your attack surface map. Every `rpc` line inside it is one callable method — treat each one the way you'd treat one REST endpoint.
- `rpc GetOrder (GetOrderRequest) returns (Order);` — unary call: one request message in, one response message out. Test this like a normal REST GET/POST.
- `rpc ListOrders (...) returns (stream Order);` — the `stream` keyword means server-streaming: one request, multiple response messages sent over time on the same HTTP/2 stream. This is relevant because streaming methods often have weaker per-message authorization checks — a common target for BOLA (see file 4).
- `message GetOrderRequest { string order_id = 1; }` — this is your request body schema. `order_id` is field number 1 — this is exactly what you'll manipulate for BOLA testing (swap in another customer's order ID).
- `enum OrderStatus { ... }` — enums are just integers on the wire. `PENDING = 0`, `PAID = 1`, `SHIPPED = 2`. If you can write to a `status` field, sending an out-of-range integer (e.g., `99`) tests whether the server validates enum bounds server-side — clients typically only offer valid values in dropdowns, but the wire format doesn't stop you from sending anything.
- No field here is marked `required` — proto3 dropped the `required`/`optional` distinction for singular fields for years (it's back as `optional` in some proto3 revisions for explicit presence tracking), so **you cannot assume a missing field will be rejected** — always test omitting fields you'd expect to be mandatory.

---

## 5. gRPC vs REST — the differences that change how you test

| Aspect | REST | gRPC |
|---|---|---|
| Addressing | URL path + verb (`GET /users/123`) | Method path only, always `POST` (`/pkg.Service/Method`) |
| Body format | JSON/XML, human-readable | Protobuf, binary |
| Transport | HTTP/1.1 or HTTP/2 | HTTP/2 only (native gRPC) |
| Schema discovery | OpenAPI/Swagger docs (often absent) | Reflection API or `.proto` files (also often absent, but discoverable) |
| Streaming | Not native (polling, SSE, WebSockets bolted on) | Native (client, server, and bidirectional streaming) |
| Status codes | HTTP status codes (404, 403, 500) | gRPC status codes sent as **trailers** (`grpc-status`, `grpc-message`), HTTP status is almost always `200 OK` |
| Proxy/tooling support | Universal — every tool speaks REST | Patchy — most tools need a plugin or a translation layer |

The two facts that most change your workflow:

**1. HTTP status is always 200.** A gRPC call that fails authorization, fails validation, or errors internally still returns HTTP `200 OK` at the transport level. The real result is in the `grpc-status` trailer (a header sent *after* the response body, once the server is done). If you're skimming Burp's proxy history by HTTP status code the way you would for a REST API, you will miss every failed gRPC call, including the ones that reveal an authorization bypass. You have to open the response and check the `grpc-status` trailer, not the HTTP status line.

**2. Everything is `POST` to the same few paths.** There's no verb tampering, no method-based access control quirks to exploit the way you might on REST (`PUT` vs `PATCH` mismatches, etc.). Every gRPC call looks identical at the HTTP layer — `POST /package.Service/Method`. Your differentiator between endpoints is the method path and the decoded body, not the HTTP verb.

---

## 6. gRPC vs gRPC-Web — a distinction that decides your tooling

This trips up almost everyone starting gRPC testing, so it gets its own section.

- **Native gRPC** runs directly over HTTP/2, using HTTP/2 trailers for status codes, and requires HTTP/2 trailer support end-to-end. Native gRPC is what you'll see between backend microservices, and increasingly what mobile apps speak directly to a backend (mobile HTTP stacks support raw HTTP/2 fine).
- **gRPC-Web** is a variant designed for **browsers**, because browsers historically could not read HTTP/2 trailers from JavaScript. A browser client speaks gRPC-Web to an intermediary proxy (commonly Envoy, or a language-specific gRPC-Web gateway), which translates it to native gRPC on the backend. gRPC-Web either base64-encodes the framed protobuf and sends it as text (`application/grpc-web-text`) or sends the binary form directly (`application/grpc-web+proto`), and it moves the trailers into the body instead of real HTTP/2 trailers, which is what lets a browser read them.

**Why this matters for you**: most of the mature Burp extensions for gRPC (covered fully in file 6) target **gRPC-Web** specifically, because that's the traffic that actually flows through a browser-facing proxy — which is what Burp intercepts naturally. Native gRPC between two backend services rarely flows through your browser proxy at all; you'll typically only see it if you're testing a mobile app configured to proxy through Burp, or a service-to-service call you've redirected deliberately. If you're testing a web frontend calling a gRPC backend, you are almost certainly looking at gRPC-Web. If you're testing a mobile app or a backend service directly, you're likely looking at native gRPC, and your Burp tooling needs will differ (see file 6, section on tool selection).

---

## 7. HTTP/2 transport — just enough to test effectively

You don't need to reimplement HTTP/2. You need these mechanics:

- **Multiplexed streams**: HTTP/2 sends multiple request/response exchanges over a single TCP connection, each tagged with a stream ID. This is why a single gRPC connection can support many concurrent method calls without opening new connections — relevant when you're reasoning about how a race-condition or rate-limit test behaves (concurrent gRPC calls are cheaper for an attacker to fire than concurrent REST calls, since there's no new-TLS-handshake cost per call).
- **Binary framing**: HTTP/2 doesn't send plaintext headers like HTTP/1.1. Headers are HPACK-compressed binary frames. This is part of why raw `curl` (unless a very recent version with full HTTP/2 support) and naive traffic tools can't read gRPC without help — you need a client or proxy that speaks HTTP/2 framing and knows how to unpack it, which is exactly what `grpcurl` and a gRPC-aware Burp extension do for you.
- **Trailers**: HTTP/2 allows a second set of headers ("trailers") sent *after* the message body, once the server has finished producing the response. gRPC uses trailers to carry `grpc-status` (numeric status, `0` = OK) and `grpc-message` (human-readable error text). This is the mechanism behind the "always HTTP 200" behavior in section 5 — the real result lives in a trailer, not the response line.
- **The 5-byte gRPC message header**: independent of HTTP/2 framing, every individual gRPC message (the protobuf payload) is prefixed with 5 bytes before the actual protobuf bytes:

  ```
  [1 byte: compressed flag][4 bytes: message length, big-endian uint32]
  ```

  The compressed flag is `0x00` (uncompressed) or `0x01` (compressed, typically gzip). This 5-byte header is what a gRPC-aware decoder strips off before handing you the raw protobuf bytes to decode per section 3. If you ever manually reconstruct a gRPC message body (e.g., hand-editing raw bytes in Repeater), forgetting this 5-byte prefix — or getting the length wrong after you edit the payload — is the single most common reason a modified request gets rejected by the server with a framing error rather than actually being evaluated.

---

## 8. How gRPC traffic appears in Burp Suite — what to expect

Out of the box, Burp Suite Professional/Community will show a gRPC or gRPC-Web request in Proxy history as:

- Method: `POST`
- Path: something like `/ecommerce.v1.OrderService/GetOrder`
- Content-Type: `application/grpc` (native), `application/grpc-web+proto` or `application/grpc-web-text` (gRPC-Web)
- Body: unreadable binary, or a base64-looking blob (gRPC-Web text mode)

Without a plugin, this is where most people get stuck — the request/response editor shows raw bytes and Burp has no idea how to render or let you edit the structured content underneath. Burp added native HTTP/2 support some time ago, so the transport layer itself is intercepted and proxyable — the gap that plugins fill is specifically **protobuf decoding and re-encoding**, not HTTP/2 handling itself.

This is the handoff point to file 3 (protobuf manipulation in Burp) and file 6 (tooling), where the actual plugin workflow is broken down step by step. The short version to remember from this file: you are looking for a plugin that (a) recognizes the gRPC/gRPC-web content type, (b) decodes the framed protobuf into an editable structured view, and (c) re-encodes it correctly — including recalculating that 5-byte length prefix from section 7 — when you send a modified request.

---

## 9. WAF and API Gateway relevance across this series

Since this consideration applies differently to each topic in this series, here's where it does and doesn't matter, so it isn't silently skipped anywhere:

- **This file (fundamentals) and file 2 (reflection enumeration)**: WAF/gateway bypass is not meaningfully relevant here. These are reconnaissance activities, not delivery of a malicious payload — there's nothing to "bypass" beyond whatever access control gates the reflection endpoint itself, which is an authorization concern (see file 2, section 8), not a signature-evasion one.
- **File 3 (protobuf manipulation)**: marginally relevant at most — the concern is whether a gateway's own gRPC/HTTP2 handling normalizes or rejects malformed frames before your edited request reaches the backend, which mostly shows up as the framing errors already covered in file 3, section 8, not as WAF signature evasion.
- **File 4 (authorization testing)**: relevant in a narrow, specific way — some API gateways enforce coarse-grained, route-level authorization (e.g., "only allow calls to `/ecommerce.v1.OrderService/*` from authenticated sessions") in front of the backend. This can mask a BFLA finding at the gateway layer while the backend service itself remains unprotected, or conversely produce a false sense of security if you only test through the gateway and never reach the backend directly. Worth a quick note in your test scope, but it isn't a detection/bypass topic in the WAF-signature sense.
- **File 5 (injection testing)**: this is where WAF/gateway relevance is substantial and gets a full dedicated section, because gRPC's binary transport meaningfully changes how signature-based detection works compared to REST/JSON injection testing. See file 5, section 6.

---

## 10. Real-world notes

- In real engagements, `.proto` files are frequently **not** provided, even in a "graybox" test — teams often don't think to hand them over, or the schema lives in a private internal repo. Don't wait for them; go straight to reflection (file 2) as your default starting point, and treat provided `.proto` files as a bonus that saves you enumeration time, not a prerequisite.
- Mobile apps are one of the most common places you'll encounter native gRPC in the wild — many mobile backends use gRPC for efficiency over cellular networks. If a mobile app won't proxy cleanly through Burp, check for certificate pinning first; that's a separate (and very common) blocker unrelated to gRPC itself.
- Internal/service-to-service gRPC (the kind you'd encounter in an internal network pentest or an SSRF pivot) is a genuinely different risk profile from external gRPC-Web APIs — internal services frequently skip authentication entirely under the assumption that "only other trusted services can reach this," which is exactly the assumption BOLA/BFLA testing (file 4) exists to break.
- Don't assume every field you see in a decoded message is user-controllable from the client — some fields are populated server-side only (e.g., `created_at`, `internal_score`) and the client never sends them, even though they exist in the schema. Reflection and `.proto` files show you the full schema, not just what a given client actually populates — cross-check against real captured traffic before assuming a field is reachable.

---

## 11. Where this series goes next

- **File 2** — using gRPC server reflection to enumerate services and methods when you have no `.proto` file.
- **File 3** — the actual Burp workflow for intercepting, decoding, and modifying protobuf messages.
- **File 4** — applying BOLA/BFLA authorization testing patterns to individual RPC methods.
- **File 5** — delivering SQLi, command injection, and SSTI through decoded protobuf string fields.
- **File 6** — full flag-by-flag `grpcurl` reference and Burp gRPC plugin setup.
- **File 7** — consolidated cheatsheet.
